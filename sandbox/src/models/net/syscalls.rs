//! [`Net`] as a [`Model`]: emulation of the socket, epoll, eventfd and poll syscalls against
//! the network state, and the modelled clients' actions. A syscall on a virtual descriptor
//! never reaches the kernel: its result is computed here, written into the target's registers
//! and memory, and the thread continues. Calls that would block park the thread in
//! `ThreadState::Wait`; every change to the network world retries them from their entry
//! registers.

use super::{
    CLIENT_PORT_BASE, ClientEvent, EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLRDHUP, Net, Obj, SockState,
    VFD_BASE,
};
use crate::{
    model::{Cx, Emu, Ext, Filter, Model, ModelId, Prior, WORLD_THREAD},
    ptrace::Regs,
    sched::ThreadState,
    world::{CHUNK_CHOICES, Kind, Outcome, Pending, Point},
};
use std::io;

/// Result of emulating one syscall, before the thread's fate is decided.
enum Io {
    Ret(i64),
    /// Would block (the descriptor is blocking); retry when the world changes.
    Block,
    /// Not modelled.
    Pass,
    /// Touches only kernel descriptors and cannot block.
    Kernel,
}

const SOCK_NONBLOCK_FLAG: u64 = 0o4000;
const MSG_PEEK: u64 = 2;
const F_DUPFD_CLOEXEC: u64 = 1030;
const FIONBIO: u64 = 0x5421;
const FIONREAD: u64 = 0x541b;
const EPOLL_EVENT_BYTES: u64 = 12;
const POLLFD_BYTES: usize = 8;
const POLLNVAL: u16 = 0x20;

const OP_CONNECT: u8 = 0;
const OP_SEND: u8 = 1;
const OP_CLOSE: u8 = 2;

impl ClientEvent {
    fn ext(self) -> Ext {
        let (op, actor, prior) = match self {
            ClientEvent::Connect => (OP_CONNECT, 0, Prior::Spawn),
            ClientEvent::Send(c) => (OP_SEND, c as u32, Prior::Actor(c)),
            ClientEvent::Close(c) => (OP_CLOSE, c as u32, Prior::Last),
        };
        Ext {
            model: ModelId::Net,
            op,
            actor,
            prior,
        }
    }

    fn from_ext(ev: Ext) -> io::Result<Self> {
        Ok(match ev.op {
            OP_CONNECT => ClientEvent::Connect,
            OP_SEND => ClientEvent::Send(ev.actor as usize),
            OP_CLOSE => ClientEvent::Close(ev.actor as usize),
            _ => return Err(io::Error::other(format!("{ev:?}: not a net event"))),
        })
    }
}

fn is_epoll_wait(nr: i64) -> bool {
    nr == libc::SYS_epoll_wait || nr == libc::SYS_epoll_pwait || nr == libc::SYS_epoll_pwait2
}

impl Model for Net {
    const ID: ModelId = ModelId::Net;
    const FILTER: Filter = Filter {
        always: &[
            libc::SYS_epoll_wait,
            libc::SYS_epoll_pwait,
            libc::SYS_epoll_pwait2,
            libc::SYS_poll,
            libc::SYS_ppoll,
            libc::SYS_select,
            libc::SYS_pselect6,
            libc::SYS_socket,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_create,
            libc::SYS_eventfd2,
        ],
        vfd: &[
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_recvfrom,
            libc::SYS_sendto,
            libc::SYS_recvmsg,
            libc::SYS_sendmsg,
            libc::SYS_close,
            libc::SYS_fcntl,
            libc::SYS_ioctl,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_connect,
            libc::SYS_shutdown,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_setsockopt,
            libc::SYS_getsockopt,
            libc::SYS_epoll_ctl,
            libc::SYS_dup,
            libc::SYS_dup3,
            libc::SYS_fstat,
        ],
    };

    /// Emulate the call, then either let the thread run on (the call could not have affected
    /// another thread) or stop it as a scheduling point.
    fn syscall(&mut self, cx: &mut Cx, thread: usize, regs: &Regs) -> io::Result<Emu> {
        let nr = regs.orig_rax as i64;
        let io = self.emulate(cx, thread, regs)?;
        if cx.opts.verbose {
            let r = match &io {
                Io::Ret(v) => format!("{v}"),
                Io::Block => "block".into(),
                Io::Pass => "pass".into(),
                Io::Kernel => "kernel".into(),
            };
            eprintln!(
                "[sandbox] T{thread} net syscall {nr}({}, {:#x}, {}) -> {r}",
                regs.rdi as i32, regs.rsi, regs.rdx
            );
        }
        Ok(match io {
            Io::Ret(v) => {
                let point = match nr {
                    n if (n == libc::SYS_accept || n == libc::SYS_accept4) && v >= 0 => {
                        Some(Point::Accept)
                    }
                    n if is_epoll_wait(n) => Some(Point::EpollReady),
                    n if n == libc::SYS_write && v > 0 && self.is_eventfd(regs.rdi as i32) => {
                        Some(Point::Wake)
                    }
                    _ => None,
                };
                match point {
                    Some(p) => Emu::Stop(v, p),
                    None => Emu::Ret(v),
                }
            }
            Io::Block => {
                let (deadline, point) = if is_epoll_wait(nr) {
                    (self.epoll_deadline(cx, nr, regs)?, Point::EpollWait)
                } else {
                    (self.poll_deadline(cx, nr, regs)?, Point::IoWait)
                };
                let seq = cx.sched.next_seq();
                Emu::Wait(
                    ThreadState::Wait {
                        model: ModelId::Net,
                        deadline,
                        seq,
                    },
                    point,
                )
            }
            Io::Pass => Emu::Pass,
            Io::Kernel => Emu::Kernel,
        })
    }

    /// A client sends its whole request before it may close: a half-sent request is a fault
    /// the corpus can express directly, not a schedule.
    fn events(&self, _cx: &Cx) -> Vec<Ext> {
        self.client_events()
            .into_iter()
            .map(ClientEvent::ext)
            .collect()
    }

    fn act(&mut self, cx: &mut Cx, ev: Ext) -> io::Result<()> {
        cx.sched.idle_fires = 0;
        match ClientEvent::from_ext(ev)? {
            ClientEvent::Connect => {
                let n = self.requests.len() as u32;
                let request = if n == 1 {
                    self.requests[0].clone()
                } else {
                    Vec::new()
                };
                let Some((client, listener)) = self.connect(request) else {
                    return Err(io::Error::other("client connect without a listener"));
                };
                self.signal(listener, EPOLLIN);
                cx.record(WORLD_THREAD, Point::Connect);
                if n >= 2 {
                    *cx.pending = Some(Pending::Model {
                        model: ModelId::Net,
                        kind: Kind::Payload,
                        actor: client,
                        n,
                    });
                }
                self.changed(cx)
            }
            ClientEvent::Send(client) => {
                if self.clients[client].remaining() > 1 {
                    *cx.pending = Some(Pending::Model {
                        model: ModelId::Net,
                        kind: Kind::Chunk,
                        actor: client,
                        n: CHUNK_CHOICES,
                    });
                    Ok(())
                } else {
                    self.deliver_chunk(cx, client, 0)
                }
            }
            ClientEvent::Close(client) => {
                self.clients[client].fin = true;
                if let Some(obj) = self.socket_of_client(client) {
                    self.signal(obj, EPOLLIN | EPOLLRDHUP);
                }
                cx.record(WORLD_THREAD, Point::ClientClose);
                self.changed(cx)
            }
        }
    }

    fn choose(&mut self, cx: &mut Cx, kind: Kind, actor: usize, choice: u32) -> io::Result<()> {
        match kind {
            Kind::Payload => {
                self.clients[actor].request = self.requests[choice as usize].clone();
                Ok(())
            }
            Kind::Chunk => self.deliver_chunk(cx, actor, choice),
            other => Err(io::Error::other(format!("{other}: not a net decision"))),
        }
    }

    fn idle(&self, _cx: &Cx) -> Option<Outcome> {
        let clients = self.hung_clients();
        (!clients.is_empty()).then_some(Outcome::Hang { clients })
    }
}

impl Net {
    fn is_eventfd(&self, fd: i32) -> bool {
        matches!(self.get(fd), Some(Obj::EventFd { .. }))
    }

    fn epoll_deadline(&self, cx: &Cx, nr: i64, regs: &Regs) -> io::Result<Option<u64>> {
        if nr == libc::SYS_epoll_pwait2 {
            if regs.r10 == 0 {
                return Ok(None);
            }
            let ns = cx.read_timespec_ns(regs.r10)?;
            return Ok(Some(cx.now().saturating_add(ns)));
        }
        let ms = regs.r10 as i32;
        Ok((ms >= 0).then(|| cx.now().saturating_add(ms as u64 * 1_000_000)))
    }

    /// Deadline of a blocking `poll`/`ppoll`; every other blocking call waits indefinitely.
    fn poll_deadline(&self, cx: &Cx, nr: i64, regs: &Regs) -> io::Result<Option<u64>> {
        if nr == libc::SYS_poll {
            let ms = regs.rdx as i32;
            return Ok((ms >= 0).then(|| cx.now().saturating_add(ms as u64 * 1_000_000)));
        }
        if nr == libc::SYS_ppoll && regs.rdx != 0 {
            let ns = cx.read_timespec_ns(regs.rdx)?;
            return Ok(Some(cx.now().saturating_add(ns)));
        }
        Ok(None)
    }

    /// `poll`/`ppoll` over a set of virtual descriptors: readiness is the same as epoll's.
    /// A set of kernel descriptors that cannot block (zero timeout, e.g. std's startup check
    /// of fds 0-2) is the kernel's; a set mixing virtual and kernel descriptors cannot be
    /// split, so it passes through unmodelled.
    fn do_poll(&mut self, cx: &Cx, regs: &Regs) -> io::Result<Io> {
        let nfds = (regs.rsi as usize).min(1024);
        let mut buf = vec![0u8; nfds * POLLFD_BYTES];
        cx.read_mem(regs.rdi, &mut buf)?;
        let zero_timeout = if regs.orig_rax as i64 == libc::SYS_poll {
            regs.rdx as i32 == 0
        } else {
            regs.rdx != 0 && cx.read_timespec_ns(regs.rdx)? == 0
        };
        let (pollfds, _) = buf.as_chunks_mut::<POLLFD_BYTES>();
        let fds = pollfds
            .iter()
            .map(|pfd| i32::from_ne_bytes(pfd[..4].try_into().unwrap()));
        let (mut virtual_fds, mut kernel_fds) = (false, false);
        for fd in fds.filter(|fd| *fd >= 0) {
            if Net::is_virtual(fd) {
                virtual_fds = true;
            } else {
                kernel_fds = true;
            }
        }
        if kernel_fds {
            return Ok(if virtual_fds || !zero_timeout {
                Io::Pass
            } else {
                Io::Kernel
            });
        }
        let mut ready = 0;
        for pfd in pollfds.iter_mut() {
            let fd = i32::from_ne_bytes(pfd[..4].try_into().unwrap());
            let events = u16::from_ne_bytes(pfd[4..6].try_into().unwrap()) as u32;
            let revents = if fd < 0 {
                0
            } else if self.get(fd).is_none() {
                POLLNVAL as u32
            } else {
                self.ready(fd) & (events | EPOLLERR | EPOLLHUP)
            };
            if revents != 0 {
                ready += 1;
            }
            pfd[6..8].copy_from_slice(&(revents as u16).to_ne_bytes());
        }
        if ready == 0 && !zero_timeout {
            return Ok(Io::Block);
        }
        cx.write_mem(regs.rdi, &buf)?;
        Ok(Io::Ret(ready))
    }

    /// The network world changed: retry the waits it may satisfy.
    fn changed(&mut self, cx: &mut Cx) -> io::Result<()> {
        for i in 0..cx.sched.threads.len() {
            let ThreadState::Wait {
                model: ModelId::Net,
                ..
            } = cx.sched.threads[i].state
            else {
                continue;
            };
            let regs = cx.sched.threads[i]
                .blocked
                .expect("net wait without saved registers");
            let ret = match self.emulate(cx, i, &regs)? {
                Io::Ret(v) => v,
                Io::Block => continue,
                Io::Pass | Io::Kernel => -(libc::EBADF as i64),
            };
            let point = if is_epoll_wait(regs.orig_rax as i64) {
                Point::EpollWoken
            } else {
                Point::IoWoken
            };
            cx.wake(i, ret, point)?;
        }
        Ok(())
    }

    fn write_epoll_events(&self, cx: &Cx, addr: u64, evs: &[(u32, u64)]) -> io::Result<()> {
        let mut buf = Vec::with_capacity(evs.len() * EPOLL_EVENT_BYTES as usize);
        for (events, data) in evs {
            buf.extend_from_slice(&events.to_ne_bytes());
            buf.extend_from_slice(&data.to_ne_bytes());
        }
        cx.write_mem(addr, &buf)
    }

    fn read_sockaddr(&self, cx: &Cx, addr: u64, len: u64) -> io::Result<(u32, u16)> {
        if addr == 0 || len < 8 {
            return Ok((0, 0));
        }
        let mut buf = [0u8; 8];
        cx.read_mem(addr, &mut buf)?;
        let family = u16::from_ne_bytes([buf[0], buf[1]]);
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let ip = if family == libc::AF_INET as u16 {
            u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]])
        } else {
            0
        };
        Ok((ip, port))
    }

    fn write_sockaddr(&self, cx: &Cx, addr: u64, lenp: u64, ip: u32, port: u16) -> io::Result<()> {
        if addr == 0 || lenp == 0 {
            return Ok(());
        }
        let cap = cx.read_u32(lenp)? as usize;
        let mut buf = [0u8; 16];
        buf[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        buf[2..4].copy_from_slice(&port.to_be_bytes());
        buf[4..8].copy_from_slice(&ip.to_be_bytes());
        cx.write_mem(addr, &buf[..cap.min(16)])?;
        cx.write_u32(lenp, 16)
    }

    fn read_iovecs(&self, cx: &Cx, iov: u64, count: u64) -> io::Result<Vec<(u64, usize)>> {
        let count = count.min(1024) as usize;
        let mut buf = vec![0u8; count * 16];
        cx.read_mem(iov, &mut buf)?;
        Ok(buf
            .as_chunks::<16>()
            .0
            .iter()
            .map(|c| {
                (
                    u64::from_ne_bytes(c[..8].try_into().unwrap()),
                    u64::from_ne_bytes(c[8..].try_into().unwrap()) as usize,
                )
            })
            .collect())
    }

    /// `iov` of a `struct msghdr`.
    fn read_msghdr_iov(&self, cx: &Cx, msg: u64) -> io::Result<Vec<(u64, usize)>> {
        let iov = cx.read_u64(msg + 16)?;
        let iovlen = cx.read_u64(msg + 24)?;
        self.read_iovecs(cx, iov, iovlen)
    }

    fn gather(&self, cx: &Cx, iovs: &[(u64, usize)]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        for (base, len) in iovs {
            let mut buf = vec![0u8; *len];
            cx.read_mem(*base, &mut buf)?;
            out.extend_from_slice(&buf);
        }
        Ok(out)
    }

    fn scatter(&self, cx: &Cx, iovs: &[(u64, usize)], mut data: &[u8]) -> io::Result<()> {
        for (base, len) in iovs {
            if data.is_empty() {
                break;
            }
            let n = (*len).min(data.len());
            cx.write_mem(*base, &data[..n])?;
            data = &data[n..];
        }
        Ok(())
    }

    /// Read up to `cap` bytes from `fd` into `iovs`.
    fn do_recv(&mut self, cx: &Cx, fd: i32, iovs: &[(u64, usize)], flags: u64) -> io::Result<Io> {
        let cap: usize = iovs.iter().map(|(_, l)| *l).sum();
        let nonblock = self.nonblock(fd);
        match self.get(fd) {
            Some(Obj::EventFd { count, .. }) => {
                if cap < 8 {
                    return Ok(Io::Ret(-(libc::EINVAL as i64)));
                }
                if *count == 0 {
                    return Ok(would_block(nonblock));
                }
                let v = *count;
                if let Some(Obj::EventFd { count, .. }) = self.get_mut(fd) {
                    *count = 0;
                }
                self.scatter(cx, iovs, &v.to_ne_bytes())?;
                Ok(Io::Ret(8))
            }
            Some(Obj::Socket {
                state: SockState::Connected { client, .. },
                ..
            }) => {
                let client = *client;
                let c = &self.clients[client];
                if c.rx.is_empty() {
                    return Ok(if c.fin {
                        Io::Ret(0)
                    } else {
                        would_block(nonblock)
                    });
                }
                let n = cap.min(c.rx.len());
                let data: Vec<u8> = c.rx[..n].to_vec();
                if flags & MSG_PEEK == 0 {
                    self.clients[client].rx.drain(..n);
                }
                self.scatter(cx, iovs, &data)?;
                Ok(Io::Ret(n as i64))
            }
            Some(Obj::Socket { .. }) => Ok(Io::Ret(-(libc::ENOTCONN as i64))),
            Some(Obj::Epoll { .. }) => Ok(Io::Ret(-(libc::EINVAL as i64))),
            None => Ok(Io::Pass),
        }
    }

    fn do_send(&mut self, cx: &mut Cx, fd: i32, iovs: &[(u64, usize)]) -> io::Result<Io> {
        let data = self.gather(cx, iovs)?;
        match self.get(fd) {
            Some(Obj::EventFd { .. }) => {
                if data.len() < 8 {
                    return Ok(Io::Ret(-(libc::EINVAL as i64)));
                }
                let v = u64::from_ne_bytes(data[..8].try_into().unwrap());
                let obj = self.obj_of(fd).unwrap();
                if let Some(Obj::EventFd { count, .. }) = self.get_mut(fd) {
                    *count = count.saturating_add(v);
                }
                self.signal(obj, EPOLLIN);
                self.changed(cx)?;
                Ok(Io::Ret(8))
            }
            Some(Obj::Socket {
                state: SockState::Connected { client, shut_wr },
                ..
            }) => {
                if *shut_wr {
                    return Ok(Io::Ret(-(libc::EPIPE as i64)));
                }
                let client = *client;
                if let Some(failure) = self.protocol.verdict(&data) {
                    *cx.outcome = Some(failure);
                }
                self.clients[client].response.extend_from_slice(&data);
                Ok(Io::Ret(data.len() as i64))
            }
            Some(Obj::Socket { .. }) => Ok(Io::Ret(-(libc::ENOTCONN as i64))),
            Some(Obj::Epoll { .. }) => Ok(Io::Ret(-(libc::EINVAL as i64))),
            None => Ok(Io::Pass),
        }
    }

    fn emulate(&mut self, cx: &mut Cx, thread: usize, regs: &Regs) -> io::Result<Io> {
        let nr = regs.orig_rax as i64;
        let fd = regs.rdi as i32;
        Ok(match nr {
            n if n == libc::SYS_socket => {
                let domain = regs.rdi as i32;
                let ty = regs.rsi;
                if (domain != libc::AF_INET && domain != libc::AF_INET6)
                    || (ty & 0xf) as i32 != libc::SOCK_STREAM
                {
                    return Ok(Io::Pass);
                }
                Io::Ret(self.create(
                    Obj::Socket {
                        nonblock: ty & SOCK_NONBLOCK_FLAG != 0,
                        local: None,
                        state: SockState::Fresh,
                    },
                    VFD_BASE,
                ) as i64)
            }
            n if n == libc::SYS_epoll_create1 || n == libc::SYS_epoll_create => {
                Io::Ret(self.create(
                    Obj::Epoll {
                        interests: Default::default(),
                    },
                    VFD_BASE,
                ) as i64)
            }
            n if n == libc::SYS_eventfd2 => Io::Ret(self.create(
                Obj::EventFd {
                    count: regs.rdi as u32 as u64,
                    nonblock: regs.rsi & SOCK_NONBLOCK_FLAG != 0,
                },
                VFD_BASE,
            ) as i64),
            n if n == libc::SYS_poll || n == libc::SYS_ppoll => self.do_poll(cx, regs)?,
            _ if !Net::is_virtual(fd) || self.get(fd).is_none() => Io::Pass,
            n if n == libc::SYS_close => match self.close(fd) {
                Some(_) => Io::Ret(0),
                None => Io::Ret(-(libc::EBADF as i64)),
            },
            n if n == libc::SYS_fcntl => match regs.rsi {
                c if c == libc::F_DUPFD as u64 || c == F_DUPFD_CLOEXEC => {
                    Io::Ret(self.dup(fd, regs.rdx as i32).unwrap() as i64)
                }
                c if c == libc::F_GETFD as u64 => Io::Ret(libc::FD_CLOEXEC as i64),
                c if c == libc::F_SETFD as u64 => Io::Ret(0),
                c if c == libc::F_GETFL as u64 => Io::Ret(
                    (libc::O_RDWR
                        | if self.nonblock(fd) {
                            libc::O_NONBLOCK
                        } else {
                            0
                        }) as i64,
                ),
                c if c == libc::F_SETFL as u64 => {
                    self.set_nonblock(fd, regs.rdx & libc::O_NONBLOCK as u64 != 0);
                    Io::Ret(0)
                }
                _ => Io::Ret(-(libc::EINVAL as i64)),
            },
            n if n == libc::SYS_dup => Io::Ret(self.dup(fd, VFD_BASE).unwrap() as i64),
            n if n == libc::SYS_dup3 => Io::Ret(-(libc::EINVAL as i64)),
            n if n == libc::SYS_ioctl => match regs.rsi {
                FIONBIO => {
                    let on = cx.read_u32(regs.rdx)? != 0;
                    self.set_nonblock(fd, on);
                    Io::Ret(0)
                }
                FIONREAD => {
                    let n = match self.get(fd) {
                        Some(Obj::Socket {
                            state: SockState::Connected { client, .. },
                            ..
                        }) => self.clients[*client].rx.len(),
                        _ => 0,
                    };
                    cx.write_u32(regs.rdx, n as u32)?;
                    Io::Ret(0)
                }
                _ => Io::Ret(-(libc::ENOTTY as i64)),
            },
            n if n == libc::SYS_fstat => {
                let mut st = [0u8; 144];
                st[24..28].copy_from_slice(&(libc::S_IFSOCK | 0o777).to_ne_bytes());
                cx.write_mem(regs.rsi, &st)?;
                Io::Ret(0)
            }
            n if n == libc::SYS_setsockopt => Io::Ret(0),
            n if n == libc::SYS_getsockopt => {
                if regs.r8 != 0 && regs.r10 != 0 {
                    let cap = cx.read_u32(regs.r8)? as usize;
                    cx.write_mem(regs.r10, &vec![0u8; cap.min(4)])?;
                }
                Io::Ret(0)
            }
            n if n == libc::SYS_bind => {
                let (ip, port) = self.read_sockaddr(cx, regs.rsi, regs.rdx)?;
                Io::Ret(self.bind(fd, ip, port))
            }
            n if n == libc::SYS_listen => Io::Ret(self.listen(fd)),
            n if n == libc::SYS_connect => {
                cx.uncontrolled(format!("connect() refused on T{thread}: no peer model"));
                Io::Ret(-(libc::ECONNREFUSED as i64))
            }
            n if n == libc::SYS_getsockname || n == libc::SYS_getpeername => {
                let (ip, port): (u32, u16) = match self.get(fd) {
                    Some(Obj::Socket { local, state, .. }) => {
                        if n == libc::SYS_getsockname {
                            local.unwrap_or((0, 0))
                        } else {
                            match state {
                                SockState::Connected { client, .. } => {
                                    (0x7f00_0001, CLIENT_PORT_BASE + *client as u16)
                                }
                                _ => return Ok(Io::Ret(-(libc::ENOTCONN as i64))),
                            }
                        }
                    }
                    _ => return Ok(Io::Ret(-(libc::ENOTSOCK as i64))),
                };
                self.write_sockaddr(cx, regs.rsi, regs.rdx, ip, port)?;
                Io::Ret(0)
            }
            n if n == libc::SYS_accept || n == libc::SYS_accept4 => {
                let flags = if n == libc::SYS_accept4 { regs.r10 } else { 0 };
                let nonblock = self.nonblock(fd);
                match self.accept(fd, flags & SOCK_NONBLOCK_FLAG != 0) {
                    Some((new, client)) => {
                        self.write_sockaddr(
                            cx,
                            regs.rsi,
                            regs.rdx,
                            0x7f00_0001,
                            CLIENT_PORT_BASE + client as u16,
                        )?;
                        Io::Ret(new as i64)
                    }
                    None => match self.get(fd) {
                        Some(Obj::Socket {
                            state: SockState::Listening { .. },
                            ..
                        }) => would_block(nonblock),
                        _ => Io::Ret(-(libc::EINVAL as i64)),
                    },
                }
            }
            n if n == libc::SYS_shutdown => {
                let client = match self.get_mut(fd) {
                    Some(Obj::Socket {
                        state: SockState::Connected { client, shut_wr },
                        ..
                    }) => {
                        if regs.rsi as i32 != libc::SHUT_RD {
                            *shut_wr = true;
                            Some(*client)
                        } else {
                            None
                        }
                    }
                    Some(Obj::Socket { .. }) => return Ok(Io::Ret(-(libc::ENOTCONN as i64))),
                    _ => return Ok(Io::Ret(-(libc::ENOTSOCK as i64))),
                };
                if let Some(c) = client {
                    self.clients[c].server_closed = true;
                }
                Io::Ret(0)
            }
            n if n == libc::SYS_epoll_ctl => {
                let (events, data) = if regs.r10 != 0 {
                    let mut buf = [0u8; EPOLL_EVENT_BYTES as usize];
                    cx.read_mem(regs.r10, &mut buf)?;
                    (
                        u32::from_ne_bytes(buf[..4].try_into().unwrap()),
                        u64::from_ne_bytes(buf[4..].try_into().unwrap()),
                    )
                } else {
                    (0, 0)
                };
                Io::Ret(self.epoll_ctl(fd, regs.rsi as i32, regs.rdx as i32, events, data))
            }
            n if is_epoll_wait(n) => {
                let max = (regs.rdx as i32).max(0) as usize;
                let evs = self.epoll_poll(fd, max);
                if !evs.is_empty() {
                    self.write_epoll_events(cx, regs.rsi, &evs)?;
                    return Ok(Io::Ret(evs.len() as i64));
                }
                let zero_timeout = if n == libc::SYS_epoll_pwait2 {
                    regs.r10 != 0 && cx.read_timespec_ns(regs.r10)? == 0
                } else {
                    regs.r10 as i32 == 0
                };
                if zero_timeout { Io::Ret(0) } else { Io::Block }
            }
            n if n == libc::SYS_read || n == libc::SYS_recvfrom => {
                let flags = if n == libc::SYS_recvfrom { regs.r10 } else { 0 };
                self.do_recv(cx, fd, &[(regs.rsi, regs.rdx as usize)], flags)?
            }
            n if n == libc::SYS_readv => {
                let iovs = self.read_iovecs(cx, regs.rsi, regs.rdx)?;
                self.do_recv(cx, fd, &iovs, 0)?
            }
            n if n == libc::SYS_recvmsg => {
                let iovs = self.read_msghdr_iov(cx, regs.rsi)?;
                cx.write_u32(regs.rsi + 48, 0)?;
                self.do_recv(cx, fd, &iovs, regs.rdx)?
            }
            n if n == libc::SYS_write || n == libc::SYS_sendto => {
                self.do_send(cx, fd, &[(regs.rsi, regs.rdx as usize)])?
            }
            n if n == libc::SYS_writev => {
                let iovs = self.read_iovecs(cx, regs.rsi, regs.rdx)?;
                self.do_send(cx, fd, &iovs)?
            }
            n if n == libc::SYS_sendmsg => {
                let iovs = self.read_msghdr_iov(cx, regs.rsi)?;
                self.do_send(cx, fd, &iovs)?
            }
            _ => Io::Pass,
        })
    }

    /// Deliver the next piece of `client`'s request (see `CHUNK_CHOICES`).
    fn deliver_chunk(&mut self, cx: &mut Cx, client: usize, choice: u32) -> io::Result<()> {
        let rem = self.clients[client].remaining();
        let n = match choice {
            0 => rem,
            1 => (rem / 2).max(1),
            2 => (rem - 1).max(1),
            _ => 1,
        };
        self.deliver(client, n);
        if let Some(obj) = self.socket_of_client(client) {
            self.signal(obj, EPOLLIN);
        }
        cx.record(WORLD_THREAD, Point::ClientSend);
        self.changed(cx)
    }
}

fn would_block(nonblock: bool) -> Io {
    if nonblock {
        Io::Ret(-(libc::EAGAIN as i64))
    } else {
        Io::Block
    }
}
