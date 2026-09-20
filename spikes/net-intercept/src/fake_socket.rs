//! A fake socket is an AF_UNIX socketpair: one end lives in the target at fd >= 1000, the
//! supervisor keeps the peer end (to play the remote) and a dup of the target's end (to inspect
//! its queue with FIONREAD and to drain listener wake-up bytes).

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use crate::notif;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockType {
    Stream,
    Dgram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Created,
    /// Nonblocking connect issued; `SO_ERROR` will report `pending_error`.
    Connecting,
    Connected,
    Listening,
    Closed,
}

pub struct FakeSocket {
    /// The fd number inside the target.
    pub fd: RawFd,
    pub domain: i32,
    pub sock_type: SockType,
    pub state: State,
    /// Supervisor-side end of the pair (the "remote peer").
    pub peer: OwnedFd,
    /// Dup of the target's end; shares the open file description.
    pub target_dup: OwnedFd,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub pending_error: i32,
    /// We shut down our write side: the target reads EOF.
    pub eof_sent: bool,
    /// Remote reset: reads fail with ECONNRESET, writes with EPIPE.
    pub reset: bool,
    /// The target got EAGAIN from a read/accept and will wait for readiness.
    pub wants_readable: bool,
    /// Bytes the target wrote, drained from `peer`.
    pub sent: Vec<u8>,
    /// Datagram sockets: queued DNS replies to hand out on the next recvfrom.
    pub dgram_replies: Vec<Vec<u8>>,
    pub dgram_queries: usize,
    /// For listeners: the number of pending wake-up bytes we wrote into the pair.
    pub listen_wakeups: usize,
    /// For listeners: how many of the pending wake-ups turn into ECONNABORTED.
    pub aborted_wakeups: usize,
}

impl FakeSocket {
    pub fn new(fd: RawFd, domain: i32, sock_type: SockType, nonblocking: bool) -> io::Result<Self> {
        let ty = match sock_type {
            SockType::Stream => libc::SOCK_STREAM,
            SockType::Dgram => libc::SOCK_DGRAM,
        };
        let mut fds = [0 as RawFd; 2];
        let flags = libc::SOCK_CLOEXEC | if nonblocking { libc::SOCK_NONBLOCK } else { 0 };
        if unsafe { libc::socketpair(libc::AF_UNIX, ty | flags, 0, fds.as_mut_ptr()) } < 0 {
            return Err(notif::last_error());
        }
        let target_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let peer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        // Our end is always nonblocking so pumping never stalls the supervisor.
        set_nonblocking(peer.as_raw_fd())?;
        let ip = if domain == libc::AF_INET6 {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        Ok(Self {
            fd,
            domain,
            sock_type,
            state: State::Created,
            peer,
            target_dup: target_end,
            local: SocketAddr::new(ip, 40000 + (fd as u16 % 20000)),
            remote: None,
            pending_error: 0,
            eof_sent: false,
            reset: false,
            wants_readable: false,
            sent: Vec::new(),
            dgram_replies: Vec::new(),
            dgram_queries: 0,
            listen_wakeups: 0,
            aborted_wakeups: 0,
        })
    }

    /// Bytes queued for the target to read.
    pub fn target_unread(&self) -> usize {
        let mut n: libc::c_int = 0;
        if unsafe { libc::ioctl(self.target_dup.as_raw_fd(), libc::FIONREAD, &mut n) } < 0 {
            return 0;
        }
        n.max(0) as usize
    }

    pub fn is_nonblocking(&self) -> bool {
        let flags = unsafe { libc::fcntl(self.target_dup.as_raw_fd(), libc::F_GETFL) };
        flags >= 0 && flags & libc::O_NONBLOCK != 0
    }

    /// Deliver bytes to the target.
    pub fn deliver(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut off = 0;
        while off < bytes.len() {
            let n = unsafe {
                libc::send(
                    self.peer.as_raw_fd(),
                    bytes[off..].as_ptr() as *const libc::c_void,
                    bytes.len() - off,
                    libc::MSG_NOSIGNAL,
                )
            };
            if n < 0 {
                let e = notif::last_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    // Socket buffer full: the target has >100 KiB unread. Drop the rest; the
                    // transcript still records what we decided.
                    return Ok(());
                }
                return Err(e);
            }
            off += n as usize;
        }
        self.wants_readable = false;
        Ok(())
    }

    pub fn send_eof(&mut self) {
        if !self.eof_sent {
            unsafe { libc::shutdown(self.peer.as_raw_fd(), libc::SHUT_WR) };
            self.eof_sent = true;
            self.wants_readable = false;
        }
    }

    /// Drain whatever the target wrote into our end.
    pub fn pump(&mut self) {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe {
                libc::recv(
                    self.peer.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n <= 0 {
                break;
            }
            if self.sent.len() < 1 << 20 {
                self.sent.extend_from_slice(&buf[..n as usize]);
            }
        }
    }

    /// Make a listener readable: one byte per pending connection.
    pub fn wake_listener(&mut self) -> io::Result<()> {
        let b = [0u8];
        let n = unsafe {
            libc::send(
                self.peer.as_raw_fd(),
                b.as_ptr() as *const libc::c_void,
                1,
                libc::MSG_NOSIGNAL,
            )
        };
        if n != 1 {
            return Err(notif::last_error());
        }
        self.listen_wakeups += 1;
        self.wants_readable = false;
        Ok(())
    }

    /// Consume one listener wake-up byte from the target's queue.
    pub fn take_listener_wakeup(&mut self) -> bool {
        if self.listen_wakeups == 0 {
            return false;
        }
        let mut b = [0u8];
        let n = unsafe {
            libc::recv(
                self.target_dup.as_raw_fd(),
                b.as_mut_ptr() as *mut libc::c_void,
                1,
                libc::MSG_DONTWAIT,
            )
        };
        if n == 1 {
            self.listen_wakeups -= 1;
            true
        } else {
            false
        }
    }

    /// Make a datagram socket readable (one dummy datagram per queued reply).
    pub fn wake_dgram(&mut self) -> io::Result<()> {
        let b = [0u8];
        let n = unsafe {
            libc::send(
                self.peer.as_raw_fd(),
                b.as_ptr() as *const libc::c_void,
                1,
                libc::MSG_NOSIGNAL,
            )
        };
        if n != 1 {
            return Err(notif::last_error());
        }
        Ok(())
    }

    pub fn take_dgram_wakeup(&mut self) {
        let mut b = [0u8; 16];
        unsafe {
            libc::recv(
                self.target_dup.as_raw_fd(),
                b.as_mut_ptr() as *mut libc::c_void,
                b.len(),
                libc::MSG_DONTWAIT,
            )
        };
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(notif::last_error());
        }
    }
    Ok(())
}

/// Encode a `SocketAddr` as `sockaddr_in`/`sockaddr_in6` bytes.
pub fn encode_sockaddr(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(a) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::slice::from_raw_parts(
                    &sa as *const _ as *const u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                )
            }
            .to_vec()
        }
        SocketAddr::V6(a) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: a.ip().octets(),
                },
                sin6_scope_id: 0,
            };
            unsafe {
                std::slice::from_raw_parts(
                    &sa as *const _ as *const u8,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                )
            }
            .to_vec()
        }
    }
}

/// Decode a `sockaddr` the target passed to connect/bind/sendto.
pub fn decode_sockaddr(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    match family {
        libc::AF_INET if bytes.len() >= 8 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 if bytes.len() >= 24 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}
