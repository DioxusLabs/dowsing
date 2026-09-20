//! Fork a supervised child (no exec), install the seccomp filter in it, hand the listener fd to
//! the parent, and serve notifications until the child exits.

use std::{
    io::{self, Read, Write},
    mem,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    time::{Duration, Instant},
};

use crate::{
    bpf::{self, Rule},
    notif::{self, Answer, seccomp_notif},
};

/// One pending notification plus everything a handler needs to answer it.
pub struct Notification<'a> {
    pub listener: BorrowedFd<'a>,
    pub notif: seccomp_notif,
}

impl Notification<'_> {
    pub fn nr(&self) -> i64 {
        self.notif.data.nr as i64
    }

    pub fn pid(&self) -> libc::pid_t {
        self.notif.pid as libc::pid_t
    }

    pub fn arg(&self, i: usize) -> u64 {
        self.notif.data.args[i]
    }

    pub fn fd_arg(&self, i: usize) -> RawFd {
        self.notif.data.args[i] as u32 as RawFd
    }

    /// Whether the notifying syscall is still blocked (target not killed/interrupted).
    pub fn still_valid(&self) -> bool {
        notif::id_valid(self.listener, self.notif.id)
    }

    /// Install `fd` into the target at exactly `newfd` and answer the syscall with `newfd`.
    pub fn addfd_and_return(&self, fd: BorrowedFd<'_>, newfd: RawFd, cloexec: bool) -> io::Result<RawFd> {
        notif::addfd(self.listener, self.notif.id, fd, newfd, cloexec, true)
    }

    pub fn read_mem(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        notif::read_mem(self.pid(), addr, buf)
    }

    pub fn write_mem(&self, addr: u64, buf: &[u8]) -> io::Result<()> {
        notif::write_mem(self.pid(), addr, buf)
    }

    pub fn read_pod<T: Copy>(&self, addr: u64) -> io::Result<T> {
        notif::read_pod(self.pid(), addr)
    }

    pub fn write_pod<T: Copy>(&self, addr: u64, value: &T) -> io::Result<()> {
        notif::write_pod(self.pid(), addr, value)
    }
}

/// What a handler decided about one notification.
pub enum Handled {
    /// Send this answer.
    Reply(Answer),
    /// The handler already answered (e.g. via `addfd_and_return`).
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Exited(i32),
    Signaled(i32),
    /// Killed by the supervisor after `timeout`.
    TimedOut,
}

pub struct Spawned {
    pub pid: libc::pid_t,
    pub listener: OwnedFd,
    pub pidfd: OwnedFd,
    pub sync_wake_up: bool,
    reaped: bool,
}

/// Fork; the child installs a filter for `rules`, hands the listener over, then runs `child`
/// and `_exit`s with its return value. The parent returns once it holds the listener.
///
/// Must be called from a single-threaded parent (fork semantics).
pub fn spawn(
    rules: &[Rule],
    want_sync_wake_up: bool,
    child: impl FnOnce() -> i32,
) -> io::Result<Spawned> {
    let filter = bpf::build(rules);
    let (fd_tx, fd_rx) = pipe()?; // child -> parent: listener fd number
    let (go_tx, go_rx) = pipe()?; // parent -> child: go ahead

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(notif::last_error());
    }
    if pid == 0 {
        drop(fd_rx);
        drop(go_tx);
        let code = match child_setup(&filter, fd_tx, go_rx) {
            Ok(()) => child(),
            Err(e) => {
                let _ = writeln!(io::stderr(), "net-intercept child setup failed: {e}");
                111
            }
        };
        unsafe { libc::_exit(code) };
    }
    drop(fd_tx);
    drop(go_rx);

    let mut buf = [0u8; 4];
    let mut fd_rx_file = std::fs::File::from(fd_rx);
    if let Err(e) = fd_rx_file.read_exact(&mut buf) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        return Err(io::Error::other(format!("child did not report listener fd: {e}")));
    }
    let child_listener_fd = i32::from_ne_bytes(buf);
    let pidfd = notif::pidfd_open(pid)?;
    let listener = notif::pidfd_getfd(pidfd.as_fd(), child_listener_fd)?;
    let sync_wake_up = want_sync_wake_up && notif::set_sync_wake_up(listener.as_fd()).is_ok();
    let mut go_tx_file = std::fs::File::from(go_tx);
    go_tx_file.write_all(&[1])?;
    Ok(Spawned {
        pid,
        listener,
        pidfd,
        sync_wake_up,
        reaped: false,
    })
}

fn child_setup(filter: &[libc::sock_filter], fd_tx: OwnedFd, go_rx: OwnedFd) -> io::Result<()> {
    let listener = notif::install_filter(filter)?;
    let mut tx = std::fs::File::from(fd_tx);
    tx.write_all(&listener.as_raw_fd().to_ne_bytes())?;
    let mut rx = std::fs::File::from(go_rx);
    let mut go = [0u8; 1];
    rx.read_exact(&mut go)?;
    drop(listener);
    Ok(())
}

impl Spawned {
    /// Serve notifications until the child exits or `timeout` elapses (then SIGKILL).
    /// `on_notif` is called for each notification; `on_idle` after every event so the caller can
    /// pump side channels.
    pub fn serve(
        &mut self,
        timeout: Duration,
        mut on_notif: impl FnMut(&Notification<'_>) -> Handled,
    ) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + timeout;
        let mut fds = [
            libc::pollfd {
                fd: self.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return self.kill_and_reap();
            }
            let remaining = deadline - now;
            let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            for f in &mut fds {
                f.revents = 0;
            }
            let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, ms.max(1)) };
            if n < 0 {
                let e = notif::last_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if fds[0].revents & libc::POLLIN != 0 {
                match notif::recv(self.listener.as_fd()) {
                    Ok(n) => {
                        let notification = Notification {
                            listener: self.listener.as_fd(),
                            notif: n,
                        };
                        match on_notif(&notification) {
                            Handled::Reply(answer) => {
                                // ENOENT: the task was killed/interrupted meanwhile.
                                let _ = notif::send(self.listener.as_fd(), n.id, answer);
                            }
                            Handled::Done => {}
                        }
                    }
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
                continue;
            }
            if fds[1].revents != 0 {
                return self.reap();
            }
        }
    }

    fn kill_and_reap(&mut self) -> io::Result<ExitStatus> {
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        self.reap()?;
        Ok(ExitStatus::TimedOut)
    }

    fn reap(&mut self) -> io::Result<ExitStatus> {
        let mut status: libc::c_int = 0;
        loop {
            let r = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if r < 0 {
                let e = notif::last_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            break;
        }
        self.reaped = true;
        if libc::WIFEXITED(status) {
            Ok(ExitStatus::Exited(libc::WEXITSTATUS(status)))
        } else if libc::WIFSIGNALED(status) {
            Ok(ExitStatus::Signaled(libc::WTERMSIG(status)))
        } else {
            Ok(ExitStatus::Signaled(0))
        }
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        if !self.reaped {
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
                libc::waitpid(self.pid, std::ptr::null_mut(), 0);
            }
        }
    }
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(notif::last_error());
    }
    unsafe { Ok((OwnedFd::from_raw_fd(fds[1]), OwnedFd::from_raw_fd(fds[0]))) }
}

/// Kernel/host feature probe results, for the README/bench.
#[derive(Debug, Clone, Copy)]
pub struct Features {
    pub user_notif: bool,
    pub sync_wake_up: bool,
    pub addfd: bool,
    pub pidfd_getfd: bool,
}

pub fn probe_features() -> Features {
    let mut f = Features {
        user_notif: false,
        sync_wake_up: false,
        addfd: false,
        pidfd_getfd: false,
    };
    let rules = [Rule::Notify(libc::SYS_getppid)];
    let Ok(mut spawned) = spawn(&rules, true, || {
        let _ = unsafe { libc::getppid() };
        0
    }) else {
        return f;
    };
    f.pidfd_getfd = true;
    f.user_notif = true;
    f.sync_wake_up = spawned.sync_wake_up;
    let mut addfd_ok = false;
    let _ = spawned.serve(Duration::from_secs(5), |n| {
        // Try to install stdin at fd 1000 and answer with it.
        let stdin = unsafe { BorrowedFd::borrow_raw(0) };
        addfd_ok = n.addfd_and_return(stdin, bpf::FAKE_FD_BASE as RawFd, true).is_ok();
        if addfd_ok { Handled::Done } else { Handled::Reply(Answer::Value(0)) }
    });
    f.addfd = addfd_ok;
    f
}

#[allow(dead_code)]
fn _size_checks() {
    let _ = mem::size_of::<seccomp_notif>();
}
