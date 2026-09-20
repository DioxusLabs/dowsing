//! Emulation of the network syscalls against [`crate::net::Net`], and the modelled clients'
//! actions. A syscall on a virtual descriptor never reaches the kernel: its result is computed
//! here, written into the target's registers and memory, and the thread continues. Calls that
//! would block park the thread in `EpollWait`/`IoWait`; every change to the network world
//! retries them.

use super::*;
use crate::net::{
    CLIENT_PORT_BASE, ClientEvent, EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLRDHUP, Net, Obj, SockState,
    http_status,
};

/// Result of emulating one syscall.
enum Emu {
    /// Done; the value goes into `rax`.
    Ret(i64),
    /// Would block (the descriptor is blocking); retry when the world changes.
    Block,
    /// Not modelled: let the kernel run it and report it.
    Pass,
    /// Touches only kernel descriptors and cannot block: let the kernel run it, nothing to report.
    Kernel,
}

const SOCK_NONBLOCK_FLAG: u64 = 0o4000;
const MSG_PEEK: u64 = 2;
const F_DUPFD_CLOEXEC: u64 = 1030;
const FIONBIO: u64 = 0x5421;
const FIONREAD: u64 = 0x541b;
const EPOLL_EVENT_BYTES: u64 = 12;
/// Timeouts fired with no client action in between before an idle run is declared over.
pub(super) const MAX_IDLE_FIRES: u32 = 256;

pub(super) fn is_net_syscall(nr: i64) -> bool {
    seccomp::FD_SYSCALLS.contains(&nr)
        || [
            libc::SYS_socket,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_create,
            libc::SYS_eventfd2,
            libc::SYS_sched_getaffinity,
            libc::SYS_epoll_wait,
            libc::SYS_epoll_pwait,
            libc::SYS_epoll_pwait2,
            libc::SYS_poll,
            libc::SYS_ppoll,
        ]
        .contains(&nr)
}

const POLLFD_BYTES: usize = 8;
const POLLNVAL: u16 = 0x20;

impl Session {
    /// Seccomp stop on a network syscall: emulate it, then either let the thread run on (the
    /// call could not have affected another thread) or stop it as a scheduling point.
    pub(super) fn handle_net(&mut self, index: usize, regs: &mut Regs) -> io::Result<()> {
        let tid = self.world.threads[index].tid;
        let nr = regs.orig_rax as i64;
        let emu = self.emulate(index, regs)?;
        if self.opts.verbose {
            let r = match &emu {
                Emu::Ret(v) => format!("{v}"),
                Emu::Block => "block".into(),
                Emu::Pass => "pass".into(),
                Emu::Kernel => "kernel".into(),
            };
            eprintln!(
                "[sandbox] T{index} net syscall {nr}({}, {:#x}, {}) -> {r}",
                regs.rdi as i32, regs.rsi, regs.rdx
            );
        }
        match emu {
            Emu::Ret(v) => {
                self.skip_syscall(tid, regs, v)?;
                let point = match nr {
                    n if (n == libc::SYS_accept || n == libc::SYS_accept4) && v >= 0 => {
                        Some(Point::Accept)
                    }
                    n if n == libc::SYS_epoll_wait
                        || n == libc::SYS_epoll_pwait
                        || n == libc::SYS_epoll_pwait2 =>
                    {
                        Some(Point::EpollReady)
                    }
                    n if n == libc::SYS_write && v > 0 && self.is_eventfd(regs.rdi as i32) => {
                        Some(Point::Wake)
                    }
                    _ => None,
                };
                match point {
                    Some(p) => {
                        self.stop_here(index, p);
                        Ok(())
                    }
                    None if self.world.outcome.is_some() => {
                        self.stop_here(index, Point::Oracle);
                        Ok(())
                    }
                    None => ptrace::cont(tid, 0),
                }
            }
            Emu::Block => {
                let entry = *regs;
                self.skip_syscall(tid, regs, 0)?;
                self.world.wait_seq += 1;
                let seq = self.world.wait_seq;
                let point = match nr {
                    n if n == libc::SYS_epoll_wait
                        || n == libc::SYS_epoll_pwait
                        || n == libc::SYS_epoll_pwait2 =>
                    {
                        let deadline = self.epoll_deadline(nr, regs)?;
                        self.world.threads[index].state = ThreadState::EpollWait {
                            epfd: regs.rdi as i32,
                            events: regs.rsi,
                            maxevents: regs.rdx as usize,
                            deadline,
                            seq,
                        };
                        Point::EpollWait
                    }
                    _ => {
                        let deadline = self.poll_deadline(nr, regs)?;
                        self.world.threads[index].blocked = Some(entry);
                        self.world.threads[index].state = ThreadState::IoWait { deadline, seq };
                        Point::IoWait
                    }
                };
                self.world.current = None;
                self.record(index, point);
                Ok(())
            }
            Emu::Pass => {
                self.uncontrolled
                    .push(format!("syscall {nr} passed through on T{index}"));
                ptrace::cont(tid, 0)
            }
            Emu::Kernel => ptrace::cont(tid, 0),
        }
    }

    fn is_eventfd(&self, fd: i32) -> bool {
        matches!(self.world.net.get(fd), Some(Obj::EventFd { .. }))
    }

    fn epoll_deadline(&self, nr: i64, regs: &Regs) -> io::Result<Option<u64>> {
        if nr == libc::SYS_epoll_pwait2 {
            if regs.r10 == 0 {
                return Ok(None);
            }
            let ns = self.read_timespec_ns(regs.r10)?;
            return Ok(Some(self.world.clock_ns.saturating_add(ns)));
        }
        let ms = regs.r10 as i32;
        Ok((ms >= 0).then(|| self.world.clock_ns.saturating_add(ms as u64 * 1_000_000)))
    }

    /// Deadline of a blocking `poll`/`ppoll`; every other blocking call waits indefinitely.
    fn poll_deadline(&self, nr: i64, regs: &Regs) -> io::Result<Option<u64>> {
        if nr == libc::SYS_poll {
            let ms = regs.rdx as i32;
            return Ok((ms >= 0).then(|| self.world.clock_ns.saturating_add(ms as u64 * 1_000_000)));
        }
        if nr == libc::SYS_ppoll && regs.rdx != 0 {
            let ns = self.read_timespec_ns(regs.rdx)?;
            return Ok(Some(self.world.clock_ns.saturating_add(ns)));
        }
        Ok(None)
    }

    /// `poll`/`ppoll` over a set of virtual descriptors: readiness is the same as epoll's.
    /// A set of kernel descriptors that cannot block (zero timeout, e.g. std's startup check
    /// of fds 0-2) is the kernel's; a set mixing virtual and kernel descriptors cannot be
    /// split, so it passes through unmodelled.
    fn do_poll(&mut self, regs: &Regs) -> io::Result<Emu> {
        let nfds = (regs.rsi as usize).min(1024);
        let mut buf = vec![0u8; nfds * POLLFD_BYTES];
        ptrace::read_mem(self.leader, regs.rdi, &mut buf)?;
        let zero_timeout = if regs.orig_rax as i64 == libc::SYS_poll {
            regs.rdx as i32 == 0
        } else {
            regs.rdx != 0 && self.read_timespec_ns(regs.rdx)? == 0
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
                Emu::Pass
            } else {
                Emu::Kernel
            });
        }
        let mut ready = 0;
        for pfd in pollfds.iter_mut() {
            let fd = i32::from_ne_bytes(pfd[..4].try_into().unwrap());
            let events = u16::from_ne_bytes(pfd[4..6].try_into().unwrap()) as u32;
            let revents = if fd < 0 {
                0
            } else if self.world.net.get(fd).is_none() {
                POLLNVAL as u32
            } else {
                self.world.net.ready(fd) & (events | EPOLLERR | EPOLLHUP)
            };
            if revents != 0 {
                ready += 1;
            }
            pfd[6..8].copy_from_slice(&(revents as u16).to_ne_bytes());
        }
        if ready == 0 && !zero_timeout {
            return Ok(Emu::Block);
        }
        ptrace::write_mem(self.leader, regs.rdi, &buf)?;
        Ok(Emu::Ret(ready))
    }

    /// The network world changed: complete the waits it satisfies.
    pub(super) fn net_changed(&mut self) -> io::Result<()> {
        for i in 0..self.world.threads.len() {
            match self.world.threads[i].state {
                ThreadState::EpollWait {
                    epfd,
                    events,
                    maxevents,
                    ..
                } => {
                    let evs = self.world.net.epoll_poll(epfd, maxevents);
                    if evs.is_empty() {
                        continue;
                    }
                    self.write_epoll_events(events, &evs)?;
                    self.set_return(i, evs.len() as i64)?;
                    self.world.threads[i].state = ThreadState::Stopped;
                    self.record(i, Point::EpollWoken);
                }
                ThreadState::IoWait { .. } => {
                    let regs = self.world.threads[i]
                        .blocked
                        .expect("IoWait without saved registers");
                    let ret = match self.emulate(i, &regs)? {
                        Emu::Ret(v) => v,
                        Emu::Block => continue,
                        Emu::Pass | Emu::Kernel => -(libc::EBADF as i64),
                    };
                    self.set_return(i, ret)?;
                    self.world.threads[i].blocked = None;
                    self.world.threads[i].state = ThreadState::Stopped;
                    self.record(i, Point::IoWoken);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn write_epoll_events(&self, addr: u64, evs: &[(u32, u64)]) -> io::Result<()> {
        let mut buf = Vec::with_capacity(evs.len() * EPOLL_EVENT_BYTES as usize);
        for (events, data) in evs {
            buf.extend_from_slice(&events.to_ne_bytes());
            buf.extend_from_slice(&data.to_ne_bytes());
        }
        ptrace::write_mem(self.leader, addr, &buf)
    }

    fn read_sockaddr(&self, addr: u64, len: u64) -> io::Result<(u32, u16)> {
        if addr == 0 || len < 8 {
            return Ok((0, 0));
        }
        let mut buf = [0u8; 8];
        ptrace::read_mem(self.leader, addr, &mut buf)?;
        let family = u16::from_ne_bytes([buf[0], buf[1]]);
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let ip = if family == libc::AF_INET as u16 {
            u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]])
        } else {
            0
        };
        Ok((ip, port))
    }

    fn write_sockaddr(&self, addr: u64, lenp: u64, ip: u32, port: u16) -> io::Result<()> {
        if addr == 0 || lenp == 0 {
            return Ok(());
        }
        let cap = ptrace::read_u32(self.leader, lenp)? as usize;
        let mut buf = [0u8; 16];
        buf[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        buf[2..4].copy_from_slice(&port.to_be_bytes());
        buf[4..8].copy_from_slice(&ip.to_be_bytes());
        ptrace::write_mem(self.leader, addr, &buf[..cap.min(16)])?;
        ptrace::write_u32(self.leader, lenp, 16)
    }

    fn read_iovecs(&self, iov: u64, count: u64) -> io::Result<Vec<(u64, usize)>> {
        let count = count.min(1024) as usize;
        let mut buf = vec![0u8; count * 16];
        ptrace::read_mem(self.leader, iov, &mut buf)?;
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
    fn read_msghdr_iov(&self, msg: u64) -> io::Result<Vec<(u64, usize)>> {
        let iov = ptrace::read_u64(self.leader, msg + 16)?;
        let iovlen = ptrace::read_u64(self.leader, msg + 24)?;
        self.read_iovecs(iov, iovlen)
    }

    fn gather(&self, iovs: &[(u64, usize)]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        for (base, len) in iovs {
            let mut buf = vec![0u8; *len];
            ptrace::read_mem(self.leader, *base, &mut buf)?;
            out.extend_from_slice(&buf);
        }
        Ok(out)
    }

    fn scatter(&self, iovs: &[(u64, usize)], mut data: &[u8]) -> io::Result<()> {
        for (base, len) in iovs {
            if data.is_empty() {
                break;
            }
            let n = (*len).min(data.len());
            ptrace::write_mem(self.leader, *base, &data[..n])?;
            data = &data[n..];
        }
        Ok(())
    }

    /// Read up to `cap` bytes from `fd` into `iovs`.
    fn do_recv(&mut self, fd: i32, iovs: &[(u64, usize)], flags: u64) -> io::Result<Emu> {
        let cap: usize = iovs.iter().map(|(_, l)| *l).sum();
        let nonblock = self.world.net.nonblock(fd);
        match self.world.net.get(fd) {
            Some(Obj::EventFd { count, .. }) => {
                if cap < 8 {
                    return Ok(Emu::Ret(-(libc::EINVAL as i64)));
                }
                if *count == 0 {
                    return Ok(would_block(nonblock));
                }
                let v = *count;
                if let Some(Obj::EventFd { count, .. }) = self.world.net.get_mut(fd) {
                    *count = 0;
                }
                self.scatter(iovs, &v.to_ne_bytes())?;
                Ok(Emu::Ret(8))
            }
            Some(Obj::Socket {
                state: SockState::Connected { client, .. },
                ..
            }) => {
                let client = *client;
                let c = &self.world.net.clients[client];
                if c.rx.is_empty() {
                    return Ok(if c.fin {
                        Emu::Ret(0)
                    } else {
                        would_block(nonblock)
                    });
                }
                let n = cap.min(c.rx.len());
                let data: Vec<u8> = c.rx[..n].to_vec();
                if flags & MSG_PEEK == 0 {
                    self.world.net.clients[client].rx.drain(..n);
                }
                self.scatter(iovs, &data)?;
                Ok(Emu::Ret(n as i64))
            }
            Some(Obj::Socket { .. }) => Ok(Emu::Ret(-(libc::ENOTCONN as i64))),
            Some(Obj::Epoll { .. }) => Ok(Emu::Ret(-(libc::EINVAL as i64))),
            None => Ok(Emu::Pass),
        }
    }

    fn do_send(&mut self, fd: i32, iovs: &[(u64, usize)]) -> io::Result<Emu> {
        let data = self.gather(iovs)?;
        match self.world.net.get(fd) {
            Some(Obj::EventFd { .. }) => {
                if data.len() < 8 {
                    return Ok(Emu::Ret(-(libc::EINVAL as i64)));
                }
                let v = u64::from_ne_bytes(data[..8].try_into().unwrap());
                let obj = self.world.net.obj_of(fd).unwrap();
                if let Some(Obj::EventFd { count, .. }) = self.world.net.get_mut(fd) {
                    *count = count.saturating_add(v);
                }
                self.world.net.signal(obj, EPOLLIN);
                self.net_changed()?;
                Ok(Emu::Ret(8))
            }
            Some(Obj::Socket {
                state: SockState::Connected { client, shut_wr },
                ..
            }) => {
                if *shut_wr {
                    return Ok(Emu::Ret(-(libc::EPIPE as i64)));
                }
                let client = *client;
                if let Some(code) = http_status(&data).filter(|c| *c >= 500) {
                    self.world.outcome = Some(Outcome::HttpError(code));
                }
                self.world.net.clients[client]
                    .response
                    .extend_from_slice(&data);
                Ok(Emu::Ret(data.len() as i64))
            }
            Some(Obj::Socket { .. }) => Ok(Emu::Ret(-(libc::ENOTCONN as i64))),
            Some(Obj::Epoll { .. }) => Ok(Emu::Ret(-(libc::EINVAL as i64))),
            None => Ok(Emu::Pass),
        }
    }

    fn emulate(&mut self, index: usize, regs: &Regs) -> io::Result<Emu> {
        let nr = regs.orig_rax as i64;
        let fd = regs.rdi as i32;
        Ok(match nr {
            n if n == libc::SYS_socket => {
                let domain = regs.rdi as i32;
                let ty = regs.rsi;
                if (domain != libc::AF_INET && domain != libc::AF_INET6)
                    || (ty & 0xf) as i32 != libc::SOCK_STREAM
                {
                    return Ok(Emu::Pass);
                }
                Emu::Ret(self.world.net.create(
                    Obj::Socket {
                        nonblock: ty & SOCK_NONBLOCK_FLAG != 0,
                        local: None,
                        state: SockState::Fresh,
                    },
                    crate::net::VFD_BASE,
                ) as i64)
            }
            n if n == libc::SYS_epoll_create1 || n == libc::SYS_epoll_create => {
                Emu::Ret(self.world.net.create(
                    Obj::Epoll {
                        interests: Default::default(),
                    },
                    crate::net::VFD_BASE,
                ) as i64)
            }
            n if n == libc::SYS_eventfd2 => Emu::Ret(self.world.net.create(
                Obj::EventFd {
                    count: regs.rdi as u32 as u64,
                    nonblock: regs.rsi & SOCK_NONBLOCK_FLAG != 0,
                },
                crate::net::VFD_BASE,
            ) as i64),
            n if n == libc::SYS_poll || n == libc::SYS_ppoll => self.do_poll(regs)?,
            n if n == libc::SYS_sched_getaffinity => {
                if regs.rsi < 8 {
                    return Ok(Emu::Ret(-(libc::EINVAL as i64)));
                }
                let mask: u64 = if self.opts.cpus >= 64 {
                    u64::MAX
                } else {
                    (1u64 << self.opts.cpus) - 1
                };
                ptrace::write_u64(self.leader, regs.rdx, mask)?;
                Emu::Ret(8)
            }
            _ if !Net::is_virtual(fd) || self.world.net.get(fd).is_none() => Emu::Pass,
            n if n == libc::SYS_close => match self.world.net.close(fd) {
                Some(_) => Emu::Ret(0),
                None => Emu::Ret(-(libc::EBADF as i64)),
            },
            n if n == libc::SYS_fcntl => match regs.rsi {
                c if c == libc::F_DUPFD as u64 || c == F_DUPFD_CLOEXEC => {
                    Emu::Ret(self.world.net.dup(fd, regs.rdx as i32).unwrap() as i64)
                }
                c if c == libc::F_GETFD as u64 => Emu::Ret(libc::FD_CLOEXEC as i64),
                c if c == libc::F_SETFD as u64 => Emu::Ret(0),
                c if c == libc::F_GETFL as u64 => Emu::Ret(
                    (libc::O_RDWR
                        | if self.world.net.nonblock(fd) {
                            libc::O_NONBLOCK
                        } else {
                            0
                        }) as i64,
                ),
                c if c == libc::F_SETFL as u64 => {
                    self.world
                        .net
                        .set_nonblock(fd, regs.rdx & libc::O_NONBLOCK as u64 != 0);
                    Emu::Ret(0)
                }
                _ => Emu::Ret(-(libc::EINVAL as i64)),
            },
            n if n == libc::SYS_dup => {
                Emu::Ret(self.world.net.dup(fd, crate::net::VFD_BASE).unwrap() as i64)
            }
            n if n == libc::SYS_dup3 => Emu::Ret(-(libc::EINVAL as i64)),
            n if n == libc::SYS_ioctl => match regs.rsi {
                FIONBIO => {
                    let on = ptrace::read_u32(self.leader, regs.rdx)? != 0;
                    self.world.net.set_nonblock(fd, on);
                    Emu::Ret(0)
                }
                FIONREAD => {
                    let n = match self.world.net.get(fd) {
                        Some(Obj::Socket {
                            state: SockState::Connected { client, .. },
                            ..
                        }) => self.world.net.clients[*client].rx.len(),
                        _ => 0,
                    };
                    let n = n as u32;
                    ptrace::write_u32(self.leader, regs.rdx, n)?;
                    Emu::Ret(0)
                }
                _ => Emu::Ret(-(libc::ENOTTY as i64)),
            },
            n if n == libc::SYS_fstat => {
                let mut st = [0u8; 144];
                st[24..28].copy_from_slice(&(libc::S_IFSOCK | 0o777).to_ne_bytes());
                ptrace::write_mem(self.leader, regs.rsi, &st)?;
                Emu::Ret(0)
            }
            n if n == libc::SYS_setsockopt => Emu::Ret(0),
            n if n == libc::SYS_getsockopt => {
                if regs.r8 != 0 && regs.r10 != 0 {
                    let cap = ptrace::read_u32(self.leader, regs.r8)? as usize;
                    ptrace::write_mem(self.leader, regs.r10, &vec![0u8; cap.min(4)])?;
                }
                Emu::Ret(0)
            }
            n if n == libc::SYS_bind => {
                let (ip, port) = self.read_sockaddr(regs.rsi, regs.rdx)?;
                Emu::Ret(self.world.net.bind(fd, ip, port))
            }
            n if n == libc::SYS_listen => Emu::Ret(self.world.net.listen(fd)),
            n if n == libc::SYS_connect => {
                self.uncontrolled
                    .push(format!("connect() refused on T{index}: no peer model"));
                Emu::Ret(-(libc::ECONNREFUSED as i64))
            }
            n if n == libc::SYS_getsockname || n == libc::SYS_getpeername => {
                let (ip, port): (u32, u16) = match self.world.net.get(fd) {
                    Some(Obj::Socket { local, state, .. }) => {
                        if n == libc::SYS_getsockname {
                            local.unwrap_or((0, 0))
                        } else {
                            match state {
                                SockState::Connected { client, .. } => {
                                    (0x7f00_0001, CLIENT_PORT_BASE + *client as u16)
                                }
                                _ => return Ok(Emu::Ret(-(libc::ENOTCONN as i64))),
                            }
                        }
                    }
                    _ => return Ok(Emu::Ret(-(libc::ENOTSOCK as i64))),
                };
                self.write_sockaddr(regs.rsi, regs.rdx, ip, port)?;
                Emu::Ret(0)
            }
            n if n == libc::SYS_accept || n == libc::SYS_accept4 => {
                let flags = if n == libc::SYS_accept4 { regs.r10 } else { 0 };
                let nonblock = self.world.net.nonblock(fd);
                match self.world.net.accept(fd, flags & SOCK_NONBLOCK_FLAG != 0) {
                    Some((new, client)) => {
                        self.write_sockaddr(
                            regs.rsi,
                            regs.rdx,
                            0x7f00_0001,
                            CLIENT_PORT_BASE + client as u16,
                        )?;
                        Emu::Ret(new as i64)
                    }
                    None => match self.world.net.get(fd) {
                        Some(Obj::Socket {
                            state: SockState::Listening { .. },
                            ..
                        }) => would_block(nonblock),
                        _ => Emu::Ret(-(libc::EINVAL as i64)),
                    },
                }
            }
            n if n == libc::SYS_shutdown => {
                let client = match self.world.net.get_mut(fd) {
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
                    Some(Obj::Socket { .. }) => return Ok(Emu::Ret(-(libc::ENOTCONN as i64))),
                    _ => return Ok(Emu::Ret(-(libc::ENOTSOCK as i64))),
                };
                if let Some(c) = client {
                    self.world.net.clients[c].server_closed = true;
                }
                Emu::Ret(0)
            }
            n if n == libc::SYS_epoll_ctl => {
                let (events, data) = if regs.r10 != 0 {
                    let mut buf = [0u8; EPOLL_EVENT_BYTES as usize];
                    ptrace::read_mem(self.leader, regs.r10, &mut buf)?;
                    (
                        u32::from_ne_bytes(buf[..4].try_into().unwrap()),
                        u64::from_ne_bytes(buf[4..].try_into().unwrap()),
                    )
                } else {
                    (0, 0)
                };
                Emu::Ret(self.world.net.epoll_ctl(
                    fd,
                    regs.rsi as i32,
                    regs.rdx as i32,
                    events,
                    data,
                ))
            }
            n if n == libc::SYS_epoll_wait
                || n == libc::SYS_epoll_pwait
                || n == libc::SYS_epoll_pwait2 =>
            {
                let max = (regs.rdx as i32).max(0) as usize;
                let evs = self.world.net.epoll_poll(fd, max);
                if !evs.is_empty() {
                    self.write_epoll_events(regs.rsi, &evs)?;
                    return Ok(Emu::Ret(evs.len() as i64));
                }
                let zero_timeout = if n == libc::SYS_epoll_pwait2 {
                    regs.r10 != 0 && self.read_timespec_ns(regs.r10)? == 0
                } else {
                    regs.r10 as i32 == 0
                };
                if zero_timeout {
                    Emu::Ret(0)
                } else {
                    Emu::Block
                }
            }
            n if n == libc::SYS_read || n == libc::SYS_recvfrom => {
                let flags = if n == libc::SYS_recvfrom { regs.r10 } else { 0 };
                self.do_recv(fd, &[(regs.rsi, regs.rdx as usize)], flags)?
            }
            n if n == libc::SYS_readv => {
                let iovs = self.read_iovecs(regs.rsi, regs.rdx)?;
                self.do_recv(fd, &iovs, 0)?
            }
            n if n == libc::SYS_recvmsg => {
                let iovs = self.read_msghdr_iov(regs.rsi)?;
                ptrace::write_u32(self.leader, regs.rsi + 48, 0)?;
                self.do_recv(fd, &iovs, regs.rdx)?
            }
            n if n == libc::SYS_write || n == libc::SYS_sendto => {
                self.do_send(fd, &[(regs.rsi, regs.rdx as usize)])?
            }
            n if n == libc::SYS_writev => {
                let iovs = self.read_iovecs(regs.rsi, regs.rdx)?;
                self.do_send(fd, &iovs)?
            }
            n if n == libc::SYS_sendmsg => {
                let iovs = self.read_msghdr_iov(regs.rsi)?;
                self.do_send(fd, &iovs)?
            }
            _ => Emu::Pass,
        })
    }

    // ----------------------------------------------------------------------------------------
    // Modelled clients
    // ----------------------------------------------------------------------------------------

    pub(super) fn client_act(&mut self, ev: ClientEvent) -> io::Result<()> {
        self.world.idle_fires = 0;
        match ev {
            ClientEvent::Connect => {
                let n = self.requests.len() as u32;
                let request = if n == 1 {
                    self.requests[0].clone()
                } else {
                    Vec::new()
                };
                let Some((client, listener)) = self.world.net.connect(request) else {
                    return Err(io::Error::other("client connect without a listener"));
                };
                self.world.net.signal(listener, EPOLLIN);
                self.record(CLIENT_THREAD, Point::Connect);
                if n >= 2 {
                    self.world.pending = Some(Pending::Payload { client, n });
                }
                self.net_changed()
            }
            ClientEvent::Send(client) => {
                if self.world.net.clients[client].remaining() > 1 {
                    self.world.pending = Some(Pending::Chunk { client });
                    Ok(())
                } else {
                    self.deliver_chunk(client, 0)
                }
            }
            ClientEvent::Close(client) => {
                self.world.net.clients[client].fin = true;
                if let Some(obj) = self.world.net.socket_of_client(client) {
                    self.world.net.signal(obj, EPOLLIN | EPOLLRDHUP);
                }
                self.record(CLIENT_THREAD, Point::ClientClose);
                self.net_changed()
            }
        }
    }

    pub(super) fn set_payload(&mut self, client: usize, choice: u32) {
        self.world.net.clients[client].request = self.requests[choice as usize].clone();
    }

    /// Deliver the next piece of `client`'s request (see `CHUNK_CHOICES`).
    pub(super) fn deliver_chunk(&mut self, client: usize, choice: u32) -> io::Result<()> {
        let rem = self.world.net.clients[client].remaining();
        let n = match choice {
            0 => rem,
            1 => (rem / 2).max(1),
            2 => (rem - 1).max(1),
            _ => 1,
        };
        self.world.net.deliver(client, n);
        if let Some(obj) = self.world.net.socket_of_client(client) {
            self.world.net.signal(obj, EPOLLIN);
        }
        self.record(CLIENT_THREAD, Point::ClientSend);
        self.net_changed()
    }
}

fn would_block(nonblock: bool) -> Emu {
    if nonblock {
        Emu::Ret(-(libc::EAGAIN as i64))
    } else {
        Emu::Block
    }
}
