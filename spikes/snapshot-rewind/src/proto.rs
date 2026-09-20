//! Framed messages over `AF_UNIX` stream socketpairs, with `SCM_RIGHTS` fd passing.
//!
//! Frame = `tag: u8`, `len: u32 le`, `payload[len]`. At most one fd rides on a
//! frame; it is attached to the `sendmsg` that carries the 5-byte header, and the
//! receiver always reads the header with `recvmsg` and `CMSG_SPACE` for one fd.

use iterator_fuzz::snapshot_hooks::{DetachedExecution, StreamSpec};
use std::{
    io,
    mem::{self, MaybeUninit},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr,
};

/// One end of a control channel.
#[derive(Debug)]
pub struct Channel {
    fd: OwnedFd,
}

impl Channel {
    pub fn pair() -> io::Result<(Channel, Channel)> {
        let mut fds = [0 as RawFd; 2];
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe {
            (
                Channel {
                    fd: OwnedFd::from_raw_fd(fds[0]),
                },
                Channel {
                    fd: OwnedFd::from_raw_fd(fds[1]),
                },
            )
        })
    }

    pub unsafe fn from_raw_fd(fd: RawFd) -> Channel {
        Channel {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        }
    }

    pub fn from_owned(fd: OwnedFd) -> Channel {
        Channel { fd }
    }

    /// A placeholder channel backed by `/dev/null`: every send/recv fails.
    pub fn dead() -> Channel {
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(fd >= 0, "open /dev/null");
        Channel {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        }
    }

    pub fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }

    pub fn send(&self, message: &Message, fd: Option<RawFd>) -> io::Result<()> {
        let (tag, payload) = message.encode();
        let mut header = [0u8; 5];
        header[0] = tag;
        header[1..].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        send_with_fd(self.raw(), &header, fd)?;
        write_all(self.raw(), &payload)
    }

    /// Receive one frame. `Ok(None)` on orderly EOF before any header byte.
    pub fn recv(&self) -> io::Result<Option<(Message, Option<OwnedFd>)>> {
        let mut header = [0u8; 5];
        let (n, fd) = recv_with_fd(self.raw(), &mut header)?;
        if n == 0 {
            return Ok(None);
        }
        if n < header.len() {
            read_exact(self.raw(), &mut header[n..])?;
        }
        let len = u32::from_le_bytes(header[1..].try_into().expect("4 bytes")) as usize;
        let mut payload = vec![0u8; len];
        read_exact(self.raw(), &mut payload)?;
        let message = Message::decode(header[0], &payload)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(Some((message, fd)))
    }

    /// Wait until readable or `timeout_ms` elapses. Returns `true` when readable/hung up.
    pub fn poll(&self, timeout_ms: i32) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.raw(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if rc < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            return Ok(rc > 0);
        }
    }
}

/// Why an execution finished, from the runner's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Record coverage; nothing special.
    Keep,
    /// Do not record coverage (like `CaseRng::discard`).
    Discard,
    /// Record coverage and report the case as failing.
    Fail,
    /// The harness body panicked; coverage was recorded by `Drop`.
    Panicked,
}

impl Verdict {
    fn to_u8(self) -> u8 {
        match self {
            Verdict::Keep => 0,
            Verdict::Discard => 1,
            Verdict::Fail => 2,
            Verdict::Panicked => 3,
        }
    }

    fn from_u8(byte: u8) -> Result<Self, String> {
        Ok(match byte {
            0 => Verdict::Keep,
            1 => Verdict::Discard,
            2 => Verdict::Fail,
            3 => Verdict::Panicked,
            other => return Err(format!("bad verdict {other}")),
        })
    }
}

/// Snapshot boundary kind, mirrored from the base crate so it can be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Item,
    Variant,
    Hint,
}

impl Kind {
    fn to_u8(self) -> u8 {
        match self {
            Kind::Item => 0,
            Kind::Variant => 1,
            Kind::Hint => 2,
        }
    }

    fn from_u8(byte: u8) -> Result<Self, String> {
        Ok(match byte {
            0 => Kind::Item,
            1 => Kind::Variant,
            2 => Kind::Hint,
            other => return Err(format!("bad kind {other}")),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    // runner/continuation -> supervisor
    /// A paused holder was forked at `cursor`; its control channel rides as the fd.
    Holder {
        pid: i32,
        /// Bytes consumed before the pause.
        trace: Vec<u8>,
        kind: Kind,
        /// Wall time from run/continuation start to the boundary.
        prefix_cost_us: u64,
        /// Fork latency as seen by the runner.
        fork_us: u64,
        rss_kb: u64,
    },
    /// The policy wanted a snapshot but the runner refused.
    Refused { cursor: usize, reason: String },
    /// The harness body finished.
    Finished {
        verdict: Verdict,
        execution: Box<DetachedExecution>,
        /// Wall time spent in the body (from run/continuation start).
        body_us: u64,
    },
    /// Free-form diagnostics.
    Log(String),

    // supervisor -> holder
    /// Fork a continuation that resumes with `stream`; its supervisor channel rides as the fd.
    Spawn {
        stream: StreamSpec,
        expected_reuse: f32,
        free_slots: u32,
    },
    /// Reap a continuation the holder forked earlier.
    Reap { pid: i32 },
    Exit,

    // holder -> supervisor
    Spawned { pid: i32 },
    Reaped { pid: i32, status: i32 },
}

impl Message {
    fn encode(&self) -> (u8, Vec<u8>) {
        let mut out = Vec::new();
        let tag = match self {
            Message::Holder {
                pid,
                trace,
                kind,
                prefix_cost_us,
                fork_us,
                rss_kb,
            } => {
                put_i32(&mut out, *pid);
                put_bytes(&mut out, trace);
                out.push(kind.to_u8());
                put_u64(&mut out, *prefix_cost_us);
                put_u64(&mut out, *fork_us);
                put_u64(&mut out, *rss_kb);
                1
            }
            Message::Refused { cursor, reason } => {
                put_u64(&mut out, *cursor as u64);
                put_bytes(&mut out, reason.as_bytes());
                2
            }
            Message::Finished {
                verdict,
                execution,
                body_us,
            } => {
                out.push(verdict.to_u8());
                put_u64(&mut out, *body_us);
                out.extend_from_slice(&execution.encode());
                3
            }
            Message::Log(text) => {
                out.extend_from_slice(text.as_bytes());
                4
            }
            Message::Spawn {
                stream,
                expected_reuse,
                free_slots,
            } => {
                put_u64(&mut out, stream.seed);
                out.push(u8::from(stream.zero_tail));
                put_bytes(&mut out, &stream.prefix);
                out.extend_from_slice(&expected_reuse.to_le_bytes());
                out.extend_from_slice(&free_slots.to_le_bytes());
                5
            }
            Message::Reap { pid } => {
                put_i32(&mut out, *pid);
                6
            }
            Message::Exit => 7,
            Message::Spawned { pid } => {
                put_i32(&mut out, *pid);
                8
            }
            Message::Reaped { pid, status } => {
                put_i32(&mut out, *pid);
                put_i32(&mut out, *status);
                9
            }
        };
        (tag, out)
    }

    fn decode(tag: u8, payload: &[u8]) -> Result<Self, String> {
        let mut r = Reader {
            bytes: payload,
            pos: 0,
        };
        let message = match tag {
            1 => Message::Holder {
                pid: r.i32()?,
                trace: r.bytes()?.to_vec(),
                kind: Kind::from_u8(r.u8()?)?,
                prefix_cost_us: r.u64()?,
                fork_us: r.u64()?,
                rss_kb: r.u64()?,
            },
            2 => Message::Refused {
                cursor: r.u64()? as usize,
                reason: String::from_utf8_lossy(r.bytes()?).into_owned(),
            },
            3 => {
                let verdict = Verdict::from_u8(r.u8()?)?;
                let body_us = r.u64()?;
                let execution = DetachedExecution::decode(&payload[r.pos..])?;
                return Ok(Message::Finished {
                    verdict,
                    execution: Box::new(execution),
                    body_us,
                });
            }
            4 => return Ok(Message::Log(String::from_utf8_lossy(payload).into_owned())),
            5 => {
                let seed = r.u64()?;
                let zero_tail = r.u8()? != 0;
                let prefix = r.bytes()?.to_vec();
                let expected_reuse = f32::from_le_bytes(r.array()?);
                let free_slots = u32::from_le_bytes(r.array()?);
                Message::Spawn {
                    stream: StreamSpec {
                        seed,
                        prefix,
                        zero_tail,
                    },
                    expected_reuse,
                    free_slots,
                }
            }
            6 => Message::Reap { pid: r.i32()? },
            7 => Message::Exit,
            8 => Message::Spawned { pid: r.i32()? },
            9 => Message::Reaped {
                pid: r.i32()?,
                status: r.i32()?,
            },
            other => return Err(format!("bad tag {other}")),
        };
        if r.pos != payload.len() {
            return Err("trailing bytes".to_string());
        }
        Ok(message)
    }
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_i32(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Result<u8, String> {
        let b = *self.bytes.get(self.pos).ok_or("truncated frame")?;
        self.pos += 1;
        Ok(b)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let end = self.pos + N;
        let slice = self.bytes.get(self.pos..end).ok_or("truncated frame")?;
        self.pos = end;
        Ok(slice.try_into().expect("sized"))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn i32(&mut self) -> Result<i32, String> {
        Ok(i32::from_le_bytes(self.array()?))
    }

    fn bytes(&mut self) -> Result<&[u8], String> {
        let len = self.u64()? as usize;
        let end = self.pos + len;
        let slice = self.bytes.get(self.pos..end).ok_or("truncated frame")?;
        self.pos = end;
        Ok(slice)
    }
}

fn write_all(fd: RawFd, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}

fn read_exact(fd: RawFd, mut bytes: &mut [u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let n = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed mid-frame",
            ));
        }
        bytes = &mut bytes[n as usize..];
    }
    Ok(())
}

const CMSG_BUF: usize = 32;

fn send_with_fd(sock: RawFd, bytes: &[u8], fd: Option<RawFd>) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let mut cmsg_buf = [0u8; CMSG_BUF];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = fd {
        let space = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
        assert!(space <= CMSG_BUF);
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
            ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
        }
    }
    loop {
        let n = unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let n = n as usize;
        if n < bytes.len() {
            // The fd (if any) went with the first byte; finish the header plainly.
            return write_all(sock, &bytes[n..]);
        }
        return Ok(());
    }
}

fn recv_with_fd(sock: RawFd, bytes: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut cmsg_buf = MaybeUninit::<[u8; CMSG_BUF]>::uninit();
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = CMSG_BUF as _;
    loop {
        let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let mut fd = None;
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let (level, ty) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
            if level == libc::SOL_SOCKET && ty == libc::SCM_RIGHTS {
                let raw = unsafe { ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>()) };
                fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }
        return Ok((n as usize, fd));
    }
}
