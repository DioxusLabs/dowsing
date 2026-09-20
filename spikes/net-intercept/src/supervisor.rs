//! The network supervisor: dispatches notified syscalls to the fake-socket table and the peer
//! model, answering control-plane calls directly and gating data-plane calls before letting the
//! kernel run them (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`).

use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, SocketAddr},
    os::fd::{AsFd, RawFd},
};

use iterator_fuzz::{ChildRng, RangeIter, coverage::CoverageCapture};

use crate::{
    bpf::FAKE_FD_BASE,
    child::{Handled, Notification},
    dns,
    fake_socket::{FakeSocket, SockType, State, decode_sockaddr, encode_sockaddr},
    notif::{self, Answer},
    peer_model::{
        AcceptOutcome, ByteSource, ConnectOutcome, DnsOutcome, PayloadGen, PeerEvent, SendOutcome,
    },
};

const MAX_ADDR_LEN: usize = 128;
const MAX_POLL_FDS: usize = 1024;

pub struct NetSupervisor<'a, C: CoverageCapture> {
    events: RangeIter<'a, C>,
    payload: PayloadGen,
    sockets: BTreeMap<RawFd, FakeSocket>,
    next_fd: RawFd,
    closed_sent: Vec<(RawFd, Vec<u8>)>,
    pub transcript: Vec<String>,
    pub decisions: usize,
    pub events_exhausted: bool,
    pub unhandled: Vec<String>,
    pub syscalls: u64,
    pub continued: u64,
    /// Timed readiness waits answered `0` directly instead of sleeping.
    pub time_skips: u64,
    pub verbose: bool,
    /// Optional protocol-aware renderer for `Data` payloads in the transcript.
    pub describe_payload: Option<fn(&[u8]) -> String>,
}

/// Errno as `Handled`.
fn err(e: i32) -> Handled {
    Handled::Reply(Answer::Errno(e))
}

fn ok(v: i64) -> Handled {
    Handled::Reply(Answer::Value(v))
}

fn cont() -> Handled {
    Handled::Reply(Answer::Continue)
}

fn hex(bytes: &[u8]) -> String {
    let shown: String = bytes.iter().take(48).map(|b| format!("{b:02x}")).collect();
    if bytes.len() > 48 {
        format!("{shown}..({} bytes)", bytes.len())
    } else {
        shown
    }
}

impl<'a, C: CoverageCapture> NetSupervisor<'a, C> {
    pub fn new(events: RangeIter<'a, C>, payload: PayloadGen, verbose: bool) -> Self {
        Self {
            events,
            payload,
            sockets: BTreeMap::new(),
            next_fd: FAKE_FD_BASE as RawFd,
            closed_sent: Vec::new(),
            transcript: Vec::new(),
            decisions: 0,
            events_exhausted: false,
            unhandled: Vec::new(),
            syscalls: 0,
            continued: 0,
            time_skips: 0,
            verbose,
            describe_payload: None,
        }
    }

    /// Bytes the target sent on each fake socket, in fd order.
    pub fn sent(&mut self) -> Vec<(RawFd, Vec<u8>)> {
        self.pump_all();
        let mut out = self.closed_sent.clone();
        out.extend(self.sockets.iter().map(|(fd, s)| (*fd, s.sent.clone())));
        out.sort_by_key(|(fd, _)| *fd);
        out
    }

    fn next_item(&mut self) -> Option<ChildRng<'a, C>> {
        match self.events.next() {
            Some(item) => {
                self.decisions += 1;
                Some(item)
            }
            None => {
                self.events_exhausted = true;
                None
            }
        }
    }

    /// Draw one decision; when the exchange is exhausted, use `default` (the benign choice).
    fn decide<T>(&mut self, default: T, draw: impl FnOnce(&mut dyn ByteSource, &mut PayloadGen) -> T) -> T {
        match self.next_item() {
            Some(mut item) => draw(&mut item, &mut self.payload),
            None => default,
        }
    }

    fn log(&mut self, line: String) {
        if self.verbose {
            eprintln!("  [peer] {line}");
        }
        self.transcript.push(line);
    }

    fn unhandled(&mut self, what: String) {
        if self.verbose {
            eprintln!("  [unhandled] {what}");
        }
        if self.unhandled.len() < 64 {
            self.unhandled.push(what);
        }
    }

    pub fn pump_all(&mut self) {
        for s in self.sockets.values_mut() {
            if s.sock_type == SockType::Stream {
                s.pump();
            }
        }
    }

    pub fn has_sockets(&self) -> bool {
        !self.sockets.is_empty()
    }

    fn alloc_fd(&mut self) -> RawFd {
        let fd = self.next_fd;
        self.next_fd += 1;
        fd
    }

    pub fn handle(&mut self, n: &Notification<'_>) -> Handled {
        self.syscalls += 1;
        self.pump_all();
        let handled = match n.nr() {
            libc::SYS_socket => self.sys_socket(n),
            libc::SYS_connect => self.sys_connect(n),
            libc::SYS_bind => self.sys_bind(n),
            libc::SYS_listen => self.sys_listen(n),
            libc::SYS_accept => self.sys_accept(n, 0),
            libc::SYS_accept4 => self.sys_accept(n, n.arg(3) as i32),
            libc::SYS_getsockname => self.sys_getname(n, false),
            libc::SYS_getpeername => self.sys_getname(n, true),
            libc::SYS_getsockopt => self.sys_getsockopt(n),
            libc::SYS_setsockopt => self.sys_setsockopt(n),
            libc::SYS_shutdown => self.sys_shutdown(n),
            libc::SYS_close => self.sys_close(n),
            libc::SYS_read | libc::SYS_recvfrom => self.sys_recv(n, RecvKind::Buf),
            libc::SYS_readv => self.sys_recv(n, RecvKind::Iov),
            libc::SYS_recvmsg => self.sys_recv(n, RecvKind::Msg),
            libc::SYS_recvmmsg => self.sys_recv(n, RecvKind::Mmsg),
            libc::SYS_write | libc::SYS_sendto => self.sys_send(n, SendKind::Buf),
            libc::SYS_writev => self.sys_send(n, SendKind::Iov),
            libc::SYS_sendmsg => self.sys_send(n, SendKind::Msg),
            libc::SYS_sendmmsg => self.sys_send(n, SendKind::Mmsg),
            libc::SYS_poll => self.sys_poll(n, (n.arg(2) as i32) < 0),
            libc::SYS_ppoll => self.sys_poll(n, n.arg(2) == 0),
            libc::SYS_select | libc::SYS_pselect6 => {
                self.unhandled("select/pselect6: passed through without gating".into());
                cont()
            }
            libc::SYS_epoll_wait | libc::SYS_epoll_pwait => {
                self.sys_epoll_wait(n, (n.arg(3) as i32) < 0)
            }
            libc::SYS_epoll_pwait2 => self.sys_epoll_wait(n, n.arg(3) == 0),
            libc::SYS_ioctl => self.sys_ioctl(n),
            libc::SYS_fcntl => self.sys_fcntl(n),
            libc::SYS_dup | libc::SYS_dup2 | libc::SYS_dup3 => {
                self.unhandled(format!("dup family on fake fd {}: refused with EMFILE", n.fd_arg(0)));
                err(libc::EMFILE)
            }
            other => {
                self.unhandled(format!("syscall {other}: passed through"));
                cont()
            }
        };
        if let Handled::Reply(Answer::Continue) = handled {
            self.continued += 1;
        }
        handled
    }

    // ----- creation / control plane -------------------------------------------------------

    fn sys_socket(&mut self, n: &Notification<'_>) -> Handled {
        let domain = n.arg(0) as i32;
        let ty = n.arg(1) as i32;
        let base_type = ty & 0xff;
        if !(domain == libc::AF_INET || domain == libc::AF_INET6) {
            return cont();
        }
        let sock_type = match base_type {
            libc::SOCK_STREAM => SockType::Stream,
            libc::SOCK_DGRAM => SockType::Dgram,
            _ => {
                self.unhandled(format!("socket type {base_type}: passed through"));
                return cont();
            }
        };
        let nonblocking = ty & libc::SOCK_NONBLOCK != 0;
        let cloexec = ty & libc::SOCK_CLOEXEC != 0;
        let fd = self.alloc_fd();
        let sock = match FakeSocket::new(fd, domain, sock_type, nonblocking) {
            Ok(s) => s,
            Err(e) => {
                self.unhandled(format!("socketpair failed: {e}"));
                return err(libc::ENOBUFS);
            }
        };
        match n.addfd_and_return(sock.target_dup.as_fd(), fd, cloexec) {
            Ok(_) => {
                self.log(format!(
                    "socket({}, {:?}{}) = {fd}",
                    if domain == libc::AF_INET { "AF_INET" } else { "AF_INET6" },
                    sock_type,
                    if nonblocking { ", nonblocking" } else { "" }
                ));
                self.sockets.insert(fd, sock);
                Handled::Done
            }
            Err(e) => {
                self.unhandled(format!("ADDFD failed: {e}"));
                err(libc::ENOBUFS)
            }
        }
    }

    fn read_addr(&self, n: &Notification<'_>, ptr: u64, len: u64) -> Option<SocketAddr> {
        if ptr == 0 {
            return None;
        }
        let bytes = notif::read_bytes(n.pid(), ptr, len as usize, MAX_ADDR_LEN).ok()?;
        decode_sockaddr(&bytes)
    }

    fn write_addr(n: &Notification<'_>, addr_ptr: u64, len_ptr: u64, addr: SocketAddr) -> io::Result<()> {
        if addr_ptr == 0 || len_ptr == 0 {
            return Ok(());
        }
        let cap: u32 = n.read_pod(len_ptr)?;
        let bytes = encode_sockaddr(addr);
        let take = (cap as usize).min(bytes.len());
        n.write_mem(addr_ptr, &bytes[..take])?;
        n.write_pod(len_ptr, &(bytes.len() as u32))
    }

    fn sys_connect(&mut self, n: &Notification<'_>) -> Handled {
        let fd = n.fd_arg(0);
        let addr = self.read_addr(n, n.arg(1), n.arg(2));
        let Some(sock) = self.sockets.get_mut(&fd) else {
            return cont();
        };
        let Some(addr) = addr else {
            return err(libc::EAFNOSUPPORT);
        };
        match sock.sock_type {
            SockType::Dgram => {
                sock.remote = Some(addr);
                sock.state = State::Connected;
                ok(0)
            }
            SockType::Stream => {
                if sock.state == State::Connected {
                    return err(libc::EISCONN);
                }
                if sock.state == State::Connecting {
                    return err(libc::EALREADY);
                }
                let nonblocking = sock.is_nonblocking();
                let outcome = self.decide(ConnectOutcome::Ok, |rng, _| ConnectOutcome::draw(rng));
                let sock = self.sockets.get_mut(&fd).unwrap();
                sock.remote = Some(addr);
                let reply = match (outcome.errno(), nonblocking) {
                    (None, false) => {
                        sock.state = State::Connected;
                        ok(0)
                    }
                    (Some(e), false) => err(e),
                    (pending, true) => {
                        sock.state = State::Connecting;
                        sock.pending_error = pending.unwrap_or(0);
                        err(libc::EINPROGRESS)
                    }
                };
                self.log(format!(
                    "connect({fd}, {addr}) -> {outcome:?}{}",
                    if nonblocking { " (EINPROGRESS)" } else { "" }
                ));
                reply
            }
        }
    }

    fn sys_bind(&mut self, n: &Notification<'_>) -> Handled {
        let fd = n.fd_arg(0);
        let addr = self.read_addr(n, n.arg(1), n.arg(2));
        let Some(sock) = self.sockets.get_mut(&fd) else {
            return cont();
        };
        let Some(mut addr) = addr else {
            return err(libc::EAFNOSUPPORT);
        };
        if addr.port() == 0 {
            addr.set_port(sock.local.port());
        }
        if addr.ip().is_unspecified() {
            addr.set_ip(sock.local.ip());
        }
        sock.local = addr;
        self.log(format!("bind({fd}, {addr}) = 0"));
        ok(0)
    }

    fn sys_listen(&mut self, n: &Notification<'_>) -> Handled {
        let fd = n.fd_arg(0);
        let Some(sock) = self.sockets.get_mut(&fd) else {
            return cont();
        };
        sock.state = State::Listening;
        self.log(format!("listen({fd}) = 0"));
        ok(0)
    }

    fn sys_accept(&mut self, n: &Notification<'_>, flags: i32) -> Handled {
        let fd = n.fd_arg(0);
        let Some(sock) = self.sockets.get_mut(&fd) else {
            return cont();
        };
        if sock.state != State::Listening {
            return err(libc::EINVAL);
        }
        let nonblocking = sock.is_nonblocking();
        let outcome = if sock.take_listener_wakeup() {
            if sock.aborted_wakeups > 0 {
                sock.aborted_wakeups -= 1;
                AcceptOutcome::Aborted
            } else {
                AcceptOutcome::Connection
            }
        } else {
            self.decide(AcceptOutcome::Connection, |rng, _| {
                AcceptOutcome::draw(rng, nonblocking)
            })
        };
        let sock = self.sockets.get_mut(&fd).unwrap();
        let local = sock.local;
        let domain = sock.domain;
        match outcome {
            AcceptOutcome::Aborted => {
                self.log(format!("accept({fd}) -> ECONNABORTED"));
                err(libc::ECONNABORTED)
            }
            AcceptOutcome::WouldBlock => {
                sock.wants_readable = true;
                self.log(format!("accept({fd}) -> EAGAIN"));
                err(libc::EAGAIN)
            }
            AcceptOutcome::Connection => {
                let new_fd = self.alloc_fd();
                let mut conn = match FakeSocket::new(
                    new_fd,
                    domain,
                    SockType::Stream,
                    flags & libc::SOCK_NONBLOCK != 0,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        self.unhandled(format!("socketpair failed: {e}"));
                        return err(libc::ENOBUFS);
                    }
                };
                conn.state = State::Connected;
                conn.local = local;
                let client_ip: IpAddr = if domain == libc::AF_INET6 {
                    dns::SYNTHETIC_V6.into()
                } else {
                    dns::SYNTHETIC_V4.into()
                };
                let client = SocketAddr::new(client_ip, 50000 + (new_fd as u16 % 10000));
                conn.remote = Some(client);
                if let Err(e) = Self::write_addr(n, n.arg(1), n.arg(2), client) {
                    self.unhandled(format!("accept addr write failed: {e}"));
                }
                match n.addfd_and_return(conn.target_dup.as_fd(), new_fd, flags & libc::SOCK_CLOEXEC != 0) {
                    Ok(_) => {
                        self.log(format!("accept({fd}) -> {new_fd} from {client}"));
                        self.sockets.insert(new_fd, conn);
                        Handled::Done
                    }
                    Err(e) => {
                        self.unhandled(format!("ADDFD failed: {e}"));
                        err(libc::ENOBUFS)
                    }
                }
            }
        }
    }

    fn sys_getname(&mut self, n: &Notification<'_>, peer: bool) -> Handled {
        let fd = n.fd_arg(0);
        let Some(sock) = self.sockets.get(&fd) else {
            return cont();
        };
        let addr = if peer {
            match sock.remote {
                Some(a) if sock.state == State::Connected => a,
                _ => return err(libc::ENOTCONN),
            }
        } else {
            sock.local
        };
        match Self::write_addr(n, n.arg(1), n.arg(2), addr) {
            Ok(()) => ok(0),
            Err(_) => err(libc::EFAULT),
        }
    }

    fn sys_getsockopt(&mut self, n: &Notification<'_>) -> Handled {
        let fd = n.fd_arg(0);
        let level = n.arg(1) as i32;
        let optname = n.arg(2) as i32;
        let Some(sock) = self.sockets.get_mut(&fd) else {
            return cont();
        };
        if level == libc::SOL_SOCKET && optname == libc::SO_ERROR {
            let e = std::mem::take(&mut sock.pending_error);
            if sock.state == State::Connecting {
                sock.state = if e == 0 { State::Connected } else { State::Created };
            }
            let optval = n.arg(3);
            let optlen = n.arg(4);
            if optval != 0 && n.write_pod(optval, &e).is_err() {
                return err(libc::EFAULT);
            }
            if optlen != 0 {
                let _ = n.write_pod(optlen, &4u32);
            }
            self.log(format!("getsockopt({fd}, SO_ERROR) = {e}"));
            return ok(0);
        }
        if level == libc::SOL_SOCKET {
            return cont();
        }
        // TCP/IP-level options: report zero.
        let optval = n.arg(3);
        let optlen_ptr = n.arg(4);
        if optval != 0
            && optlen_ptr != 0
            && let Ok(len) = n.read_pod::<u32>(optlen_ptr)
        {
            let zeros = vec![0u8; (len as usize).min(64)];
            let _ = n.write_mem(optval, &zeros);
        }
        ok(0)
    }

    fn sys_setsockopt(&mut self, n: &Notification<'_>) -> Handled {
        let fd = n.fd_arg(0);
        let level = n.arg(1) as i32;
        if !self.sockets.contains_key(&fd) {
            return cont();
        }
        if level == libc::SOL_SOCKET {
            cont()
        } else {
            ok(0)
        }
    }

    fn sys_shutdown(&mut self, n: &Notification<'_>) -> Handled {
        let fd = n.fd_arg(0);
        if self.sockets.contains_key(&fd) {
            self.log(format!("shutdown({fd}, {})", n.arg(1)));
        }
        cont()
    }

    fn sys_close(&mut self, n: &Notification<'_>) -> Handled {
        let fd = n.fd_arg(0);
        if let Some(mut s) = self.sockets.remove(&fd) {
            s.pump();
            self.log(format!("close({fd})"));
            // Keep the sent log for the report.
            self.closed_sent.push((fd, std::mem::take(&mut s.sent)));
        }
        cont()
    }

    // ----- data plane -------------------------------------------------------------------

    fn sys_recv(&mut self, n: &Notification<'_>, kind: RecvKind) -> Handled {
        let fd = n.fd_arg(0);
        let Some(sock) = self.sockets.get_mut(&fd) else {
            return cont();
        };
        match sock.sock_type {
            SockType::Dgram => self.dgram_recv(n, fd, kind),
            SockType::Stream => {
                if sock.state == State::Listening {
                    return err(libc::EINVAL);
                }
                if let Err(e) = ensure_connected(sock) {
                    return err(e);
                }
                if sock.reset {
                    self.log(format!("recv({fd}) -> ECONNRESET"));
                    return err(libc::ECONNRESET);
                }
                if sock.target_unread() > 0 || sock.eof_sent {
                    return cont();
                }
                let may_block = sock.is_nonblocking();
                self.materialize_stream_event(fd, may_block, "recv")
            }
        }
    }

    /// Decide what the peer does next on a stream socket with nothing queued and make it so.
    /// Returns the answer for the syscall that triggered it (recv) - readiness gates ignore it.
    fn materialize_stream_event(&mut self, fd: RawFd, may_block: bool, via: &str) -> Handled {
        let event = self.decide(PeerEvent::Close, |rng, payload| {
            PeerEvent::draw(rng, may_block, payload)
        });
        let sock = self.sockets.get_mut(&fd).unwrap();
        match event {
            PeerEvent::Data(bytes) if !bytes.is_empty() => {
                if let Err(e) = sock.deliver(&bytes) {
                    self.unhandled(format!("deliver failed: {e}"));
                }
                let shown = match self.describe_payload {
                    Some(describe) => describe(&bytes),
                    None => hex(&bytes),
                };
                self.log(format!("{via}({fd}) <- Data[{}] {shown}", bytes.len()));
                cont()
            }
            PeerEvent::Data(_) | PeerEvent::WouldBlock if may_block => {
                sock.wants_readable = true;
                self.log(format!("{via}({fd}) <- WouldBlock"));
                err(libc::EAGAIN)
            }
            PeerEvent::Data(_) | PeerEvent::Close => {
                sock.send_eof();
                self.log(format!("{via}({fd}) <- Close"));
                cont()
            }
            PeerEvent::Reset => {
                sock.reset = true;
                sock.send_eof();
                self.log(format!("{via}({fd}) <- Reset"));
                err(libc::ECONNRESET)
            }
            PeerEvent::WouldBlock => unreachable!("WouldBlock is only drawn when may_block"),
        }
    }

    fn sys_send(&mut self, n: &Notification<'_>, kind: SendKind) -> Handled {
        let fd = n.fd_arg(0);
        let Some(sock) = self.sockets.get_mut(&fd) else {
            return cont();
        };
        match sock.sock_type {
            SockType::Dgram => self.dgram_send(n, fd, kind),
            SockType::Stream => {
                if let Err(e) = ensure_connected(sock) {
                    return err(e);
                }
                if sock.reset {
                    return err(libc::EPIPE);
                }
                let outcome = self.decide(SendOutcome::Accepted, |rng, _| SendOutcome::draw(rng));
                let len = match kind {
                    SendKind::Buf => n.arg(2),
                    _ => 0,
                };
                let sock = self.sockets.get_mut(&fd).unwrap();
                match outcome {
                    SendOutcome::Accepted => {
                        self.log(format!("send({fd}, {len} bytes) -> Accepted"));
                        cont()
                    }
                    SendOutcome::Pipe => {
                        sock.reset = true;
                        sock.send_eof();
                        self.log(format!("send({fd}) -> EPIPE"));
                        err(libc::EPIPE)
                    }
                    SendOutcome::Reset => {
                        sock.reset = true;
                        sock.send_eof();
                        self.log(format!("send({fd}) -> ECONNRESET"));
                        err(libc::ECONNRESET)
                    }
                }
            }
        }
    }

    // ----- datagram (DNS) emulation ------------------------------------------------------

    fn dgram_send(&mut self, n: &Notification<'_>, fd: RawFd, kind: SendKind) -> Handled {
        let pid = n.pid();
        let queries: Vec<Vec<u8>> = match kind {
            SendKind::Buf => match notif::read_bytes(pid, n.arg(1), n.arg(2) as usize, 4096) {
                Ok(b) => vec![b],
                Err(_) => return err(libc::EFAULT),
            },
            SendKind::Iov => match notif::read_iov(pid, n.arg(1), n.arg(2) as usize, 4096) {
                Ok(b) => vec![b],
                Err(_) => return err(libc::EFAULT),
            },
            SendKind::Msg => match n.read_pod::<libc::msghdr>(n.arg(1)) {
                Ok(m) => match notif::read_iov(pid, m.msg_iov as u64, m.msg_iovlen, 4096) {
                    Ok(b) => vec![b],
                    Err(_) => return err(libc::EFAULT),
                },
                Err(_) => return err(libc::EFAULT),
            },
            SendKind::Mmsg => {
                let vlen = (n.arg(2) as usize).min(16);
                let mut out = Vec::new();
                for i in 0..vlen {
                    let addr = n.arg(1) + (i * std::mem::size_of::<libc::mmsghdr>()) as u64;
                    let Ok(m) = n.read_pod::<libc::mmsghdr>(addr) else {
                        return err(libc::EFAULT);
                    };
                    let Ok(b) = notif::read_iov(pid, m.msg_hdr.msg_iov as u64, m.msg_hdr.msg_iovlen, 4096)
                    else {
                        return err(libc::EFAULT);
                    };
                    let len = b.len() as u32;
                    // msg_len follows msg_hdr.
                    let _ = n.write_pod(addr + std::mem::size_of::<libc::msghdr>() as u64, &len);
                    out.push(b);
                }
                out
            }
        };
        let count = queries.len();
        let total: usize = queries.iter().map(|q| q.len()).sum();
        for query in queries {
            match dns::parse_query(&query) {
                Some(q) => {
                    let outcome = self.decide(DnsOutcome::Resolves, |rng, _| DnsOutcome::draw(rng));
                    let reply = dns::build_reply(&q, outcome);
                    self.log(format!(
                        "dns({fd}, {} type {}) -> {outcome:?}",
                        q.name, q.qtype
                    ));
                    let sock = self.sockets.get_mut(&fd).unwrap();
                    sock.dgram_replies.push(reply);
                    sock.dgram_queries += 1;
                    if let Err(e) = sock.wake_dgram() {
                        self.unhandled(format!("dgram wake failed: {e}"));
                    }
                }
                None => {
                    self.unhandled(format!("non-DNS datagram on {fd} ({} bytes) dropped", query.len()));
                }
            }
        }
        match kind {
            SendKind::Mmsg => ok(count as i64),
            _ => ok(total as i64),
        }
    }

    fn dgram_recv(&mut self, n: &Notification<'_>, fd: RawFd, kind: RecvKind) -> Handled {
        let sock = self.sockets.get_mut(&fd).unwrap();
        if sock.dgram_replies.is_empty() {
            sock.wants_readable = true;
            return err(libc::EAGAIN);
        }
        let reply = sock.dgram_replies.remove(0);
        sock.take_dgram_wakeup();
        let from = sock.remote;
        let pid = n.pid();
        let written = match kind {
            RecvKind::Buf => {
                let cap = n.arg(2) as usize;
                let take = reply.len().min(cap);
                if n.write_mem(n.arg(1), &reply[..take]).is_err() {
                    return err(libc::EFAULT);
                }
                if n.nr() == libc::SYS_recvfrom
                    && let Some(from) = from
                {
                    let _ = Self::write_addr(n, n.arg(4), n.arg(5), from);
                }
                take
            }
            RecvKind::Iov => match write_iov(pid, n.arg(1), n.arg(2) as usize, &reply) {
                Ok(w) => w,
                Err(_) => return err(libc::EFAULT),
            },
            RecvKind::Msg => {
                let Ok(mut m) = n.read_pod::<libc::msghdr>(n.arg(1)) else {
                    return err(libc::EFAULT);
                };
                let Ok(w) = write_iov(pid, m.msg_iov as u64, m.msg_iovlen, &reply) else {
                    return err(libc::EFAULT);
                };
                if !m.msg_name.is_null()
                    && let Some(from) = from
                {
                    let bytes = encode_sockaddr(from);
                    let take = bytes.len().min(m.msg_namelen as usize);
                    let _ = n.write_mem(m.msg_name as u64, &bytes[..take]);
                    m.msg_namelen = bytes.len() as u32;
                }
                m.msg_controllen = 0;
                m.msg_flags = 0;
                let _ = n.write_pod(n.arg(1), &m);
                w
            }
            RecvKind::Mmsg => {
                self.unhandled("recvmmsg on datagram socket unsupported".into());
                return err(libc::EAGAIN);
            }
        };
        ok(written as i64)
    }

    // ----- readiness gates ----------------------------------------------------------------

    /// Before the kernel runs a readiness wait, decide what each interesting fake socket's
    /// peer does. With an infinite timeout the first gated socket may not choose `WouldBlock`
    /// so the wait cannot hang forever.
    fn gate_readable(&mut self, fd: RawFd, infinite: bool, forced: &mut bool, via: &str) {
        let Some(sock) = self.sockets.get_mut(&fd) else {
            return;
        };
        match (sock.sock_type, sock.state) {
            (SockType::Dgram, _) => {}
            (SockType::Stream, State::Listening) => {
                if sock.listen_wakeups > 0 {
                    return;
                }
                let may_block = !(infinite && !*forced);
                let outcome = self.decide(AcceptOutcome::Connection, |rng, _| {
                    AcceptOutcome::draw(rng, may_block)
                });
                let sock = self.sockets.get_mut(&fd).unwrap();
                match outcome {
                    AcceptOutcome::WouldBlock => {}
                    AcceptOutcome::Connection | AcceptOutcome::Aborted => {
                        *forced = true;
                        if outcome == AcceptOutcome::Aborted {
                            sock.aborted_wakeups += 1;
                        }
                        if let Err(e) = sock.wake_listener() {
                            self.unhandled(format!("listener wake failed: {e}"));
                        }
                        self.log(format!("{via}({fd}) <- incoming {outcome:?}"));
                    }
                }
            }
            // A pending nonblocking connect waits for writability, which the fresh socketpair
            // already has; SO_ERROR then reports the drawn outcome.
            (SockType::Stream, State::Connecting) => {}
            (SockType::Stream, State::Connected) => {
                if sock.reset || sock.eof_sent || sock.target_unread() > 0 {
                    return;
                }
                let may_block = !(infinite && !*forced);
                let before = self.decisions;
                let _ = self.materialize_stream_event(fd, may_block, via);
                let sock = self.sockets.get_mut(&fd).unwrap();
                if self.decisions > before && !sock.wants_readable {
                    *forced = true;
                }
                sock.wants_readable = false;
            }
            (SockType::Stream, _) => {}
        }
    }

    fn sys_poll(&mut self, n: &Notification<'_>, infinite: bool) -> Handled {
        let nfds = (n.arg(1) as usize).min(MAX_POLL_FDS);
        let mut fds = Vec::with_capacity(nfds);
        for i in 0..nfds {
            let addr = n.arg(0) + (i * std::mem::size_of::<libc::pollfd>()) as u64;
            match n.read_pod::<libc::pollfd>(addr) {
                Ok(p) => fds.push(p),
                Err(_) => return cont(),
            }
        }
        let interested: Vec<RawFd> = fds
            .iter()
            .filter(|p| p.fd >= FAKE_FD_BASE as RawFd && p.events & libc::POLLIN != 0)
            .map(|p| p.fd)
            .collect();
        self.readiness_wait(&interested, infinite, "poll")
    }

    /// Gate every interested fake socket, then either let the kernel run the wait or - when
    /// the peers all chose `WouldBlock` on a timed wait and nothing fake is already ready -
    /// answer `0` (timeout elapsed) directly so the target's own timeout logic runs without
    /// the sandbox sleeping through it ("time skip"). Real fds in the same set are still
    /// reported by the target's next wait; edge-triggered epoll keeps unreported edges.
    fn readiness_wait(&mut self, interested: &[RawFd], infinite: bool, via: &str) -> Handled {
        let already_ready = interested.iter().any(|fd| {
            self.sockets.get(fd).is_some_and(|s| {
                s.reset || s.eof_sent || s.target_unread() > 0 || s.listen_wakeups > 0
            })
        });
        let before = self.decisions;
        let mut forced = false;
        for fd in interested {
            self.gate_readable(*fd, infinite, &mut forced, via);
        }
        let drew_would_block = self.decisions > before && !forced;
        if drew_would_block && !infinite && !already_ready {
            self.time_skips += 1;
            return ok(0);
        }
        cont()
    }

    /// The epoll interest list comes from `/proc/<pid>/fdinfo/<epfd>` (the kernel's own view),
    /// so dup'ed epoll fds (mio's `Registry::try_clone`) and registrations made before the
    /// supervisor existed are covered without mirroring `epoll_ctl`.
    fn sys_epoll_wait(&mut self, n: &Notification<'_>, infinite: bool) -> Handled {
        if self.sockets.is_empty() {
            return cont();
        }
        let epfd = n.fd_arg(0);
        let Ok(info) = std::fs::read_to_string(format!("/proc/{}/fdinfo/{epfd}", n.pid())) else {
            return cont();
        };
        let mut interested: Vec<RawFd> = info
            .lines()
            .filter_map(parse_epoll_tfd)
            .filter(|(fd, events)| {
                *events & libc::EPOLLIN as u32 != 0 && self.sockets.contains_key(fd)
            })
            .map(|(fd, _)| fd)
            .collect();
        interested.sort_unstable();
        self.readiness_wait(&interested, infinite, "epoll_wait")
    }

    fn sys_ioctl(&mut self, n: &Notification<'_>) -> Handled {
        let fd = n.fd_arg(0);
        if !self.sockets.contains_key(&fd) {
            return cont();
        }
        let req = n.arg(1);
        if req != libc::FIONBIO && req != libc::FIONREAD {
            self.unhandled(format!("ioctl({fd}, {req:#x}) passed through"));
        }
        cont()
    }

    fn sys_fcntl(&mut self, n: &Notification<'_>) -> Handled {
        let fd = n.fd_arg(0);
        if !self.sockets.contains_key(&fd) {
            return cont();
        }
        let cmd = n.arg(1) as i32;
        match cmd {
            libc::F_DUPFD | libc::F_DUPFD_CLOEXEC => {
                self.unhandled(format!("fcntl({fd}, F_DUPFD*) refused with EMFILE"));
                err(libc::EMFILE)
            }
            _ => cont(),
        }
    }
}

/// `tfd:     1000 events:     201d data: ...` -> `(1000, 0x201d)`.
fn parse_epoll_tfd(line: &str) -> Option<(RawFd, u32)> {
    let rest = line.strip_prefix("tfd:")?;
    let mut words = rest.split_whitespace();
    let fd: RawFd = words.next()?.parse().ok()?;
    if words.next()? != "events:" {
        return None;
    }
    let events = u32::from_str_radix(words.next()?, 16).ok()?;
    Some((fd, events))
}

fn ensure_connected(sock: &mut FakeSocket) -> Result<(), i32> {
    match sock.state {
        State::Connected => Ok(()),
        State::Connecting => {
            let e = std::mem::take(&mut sock.pending_error);
            if e == 0 {
                sock.state = State::Connected;
                Ok(())
            } else {
                sock.state = State::Created;
                Err(e)
            }
        }
        State::Created | State::Closed => Err(libc::ENOTCONN),
        State::Listening => Err(libc::ENOTCONN),
    }
}

/// Scatter `data` into the target's iovec array; returns bytes written.
fn write_iov(pid: libc::pid_t, iov_addr: u64, iovcnt: usize, data: &[u8]) -> io::Result<usize> {
    let iovcnt = iovcnt.min(libc::UIO_MAXIOV as usize);
    let mut off = 0;
    for i in 0..iovcnt {
        if off >= data.len() {
            break;
        }
        let iov: libc::iovec =
            notif::read_pod(pid, iov_addr + (i * std::mem::size_of::<libc::iovec>()) as u64)?;
        let take = iov.iov_len.min(data.len() - off);
        notif::write_mem(pid, iov.iov_base as u64, &data[off..off + take])?;
        off += take;
    }
    Ok(off)
}

#[derive(Clone, Copy)]
enum RecvKind {
    Buf,
    Iov,
    Msg,
    Mmsg,
}

#[derive(Clone, Copy)]
enum SendKind {
    Buf,
    Iov,
    Msg,
    Mmsg,
}
