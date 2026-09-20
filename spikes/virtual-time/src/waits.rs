//! Parked-wait bookkeeping: what a blocked tracee thread is waiting for and how to finish it.

use std::io;

use libc::pid_t;

use crate::ptrace;

/// Per-thread wait state while the thread is held in a ptrace stop.
#[derive(Debug, Clone)]
pub struct Wait {
    pub kind: WaitKind,
    /// `vnow` at which the wait times out; `None` = untimed.
    pub deadline: Option<u64>,
    /// Futex word this thread is waiting on (same-process wakes complete it).
    pub futex: Option<(pid_t, u64)>,
    /// File descriptors (in the tracee) whose readiness completes the wait.
    pub readiness: Vec<(i32, i16)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitKind {
    /// nanosleep/clock_nanosleep: parked at the seccomp stop, syscall skipped on wake.
    Sleep,
    /// futex WAIT / WAIT_BITSET: parked at the syscall-exit stop of a zero-timeout probe.
    Futex,
    /// epoll_wait/poll/select family: parked at the syscall-exit stop of a zero-timeout probe.
    Poll,
}

/// How a probe should be re-issued after a wake that is not a timeout.
#[derive(Debug, Clone, Copy)]
pub struct Restart {
    pub deadline: Option<u64>,
}

/// Decode `struct pollfd[nfds]` from the tracee.
pub fn read_pollfds(pid: pid_t, addr: u64, nfds: u64) -> io::Result<Vec<(i32, i16)>> {
    let nfds = nfds.min(1024) as usize;
    let mut buf = vec![0_u8; nfds * 8];
    ptrace::read_mem(pid, addr, &mut buf)?;
    Ok(buf
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| {
            (
                i32::from_ne_bytes(c[..4].try_into().unwrap()),
                i16::from_ne_bytes(c[4..6].try_into().unwrap()),
            )
        })
        .filter(|(fd, _)| *fd >= 0)
        .collect())
}

/// Decode the three `fd_set`s of a select call into (fd, events) pairs.
pub fn read_fdsets(
    pid: pid_t,
    nfds: u64,
    readfds: u64,
    writefds: u64,
    exceptfds: u64,
) -> io::Result<Vec<(i32, i16)>> {
    let nfds = nfds.min(1024) as usize;
    let words = nfds.div_ceil(64);
    let mut out = Vec::new();
    for (addr, events) in [
        (readfds, libc::POLLIN),
        (writefds, libc::POLLOUT),
        (exceptfds, libc::POLLPRI),
    ] {
        if addr == 0 || words == 0 {
            continue;
        }
        let mut buf = vec![0_u8; words * 8];
        ptrace::read_mem(pid, addr, &mut buf)?;
        for (w, chunk) in buf.as_chunks::<8>().0.iter().enumerate() {
            let bits = u64::from_ne_bytes(*chunk);
            for b in 0..64 {
                if bits & (1 << b) != 0 {
                    let fd = (w * 64 + b) as i32;
                    if (fd as usize) < nfds {
                        out.push((fd, events));
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Mirror the tracee's fds with `pidfd_getfd` and poll them with `timeout_ms`.
/// Returns whether any fd in `readiness` is ready.
pub fn any_ready(tgid: pid_t, readiness: &[(i32, i16)], timeout_ms: i32) -> io::Result<bool> {
    if readiness.is_empty() {
        return Ok(false);
    }
    let pidfd = ptrace::pidfd_open(tgid)?;
    let mut mirrored = Vec::with_capacity(readiness.len());
    let mut fds = Vec::with_capacity(readiness.len());
    for (fd, events) in readiness {
        match ptrace::pidfd_getfd(pidfd, *fd) {
            Ok(m) => {
                mirrored.push(m);
                fds.push(libc::pollfd {
                    fd: m,
                    events: *events,
                    revents: 0,
                });
            }
            Err(_) => {
                // Closed or unmirrorable fd: treat as always-ready (poll would report POLLNVAL).
                for m in &mirrored {
                    unsafe { libc::close(*m) };
                }
                unsafe { libc::close(pidfd) };
                return Ok(true);
            }
        }
    }
    let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    let err = io::Error::last_os_error();
    for m in &mirrored {
        unsafe { libc::close(*m) };
    }
    unsafe { libc::close(pidfd) };
    if n < 0 {
        if err.raw_os_error() == Some(libc::EINTR) {
            return Ok(false);
        }
        return Err(err);
    }
    Ok(n > 0)
}
