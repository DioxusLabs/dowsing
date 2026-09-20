//! Thin wrappers over the `seccomp_unotify(2)` ioctls.

use std::io;

/// One received notification.
#[derive(Debug, Clone, Copy)]
pub struct Notification {
    pub id: u64,
    /// Thread id of the task blocked in the syscall.
    pub tid: u32,
    pub nr: i64,
    pub args: [u64; 6],
}

/// Receive a pending notification. Callers must know the listener is readable (poll first): a
/// blocking RECV after the last filtered task exited never returns.
pub fn recv(listener: i32) -> io::Result<Notification> {
    // SAFETY: seccomp_notif is plain old data and the kernel requires it zeroed.
    let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd and pointer to a zeroed struct of the right size.
    let rc = unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_RECV, &mut req) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Notification {
        id: req.id,
        tid: req.pid,
        nr: i64::from(req.data.nr),
        args: req.data.args,
    })
}

/// Answer a notification with a return value or an errno.
pub fn send(listener: i32, id: u64, val: i64, error: i32) -> io::Result<()> {
    let resp = libc::seccomp_notif_resp {
        id,
        val,
        error: -error,
        flags: 0,
    };
    // SAFETY: valid fd and pointer.
    let rc = unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_SEND, &resp) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Let the kernel execute the original syscall.
pub fn send_continue(listener: i32, id: u64) -> io::Result<()> {
    let resp = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: 0,
        flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    };
    // SAFETY: valid fd and pointer.
    let rc = unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_SEND, &resp) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Install `srcfd` into the target and atomically return it as the syscall result.
///
/// With `newfd = Some(n)` the fd is installed at exactly `n` (closing whatever was there).
pub fn addfd_send(
    listener: i32,
    id: u64,
    srcfd: i32,
    newfd: Option<u32>,
    cloexec: bool,
) -> io::Result<i32> {
    let mut flags = libc::SECCOMP_ADDFD_FLAG_SEND as u32;
    if newfd.is_some() {
        flags |= libc::SECCOMP_ADDFD_FLAG_SETFD as u32;
    }
    let addfd = libc::seccomp_notif_addfd {
        id,
        flags,
        srcfd: srcfd as u32,
        newfd: newfd.unwrap_or(0),
        newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
    };
    // SAFETY: valid fd and pointer.
    let rc = unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

/// Check whether the notification is still valid (the target is still blocked in it).
pub fn id_valid(listener: i32, id: u64) -> bool {
    // SAFETY: valid fd and pointer.
    unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0 }
}
