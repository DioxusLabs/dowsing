//! Thin wrappers over the seccomp user-notification uapi, `pidfd_*` and `process_vm_*`.

use std::{
    io,
    mem::{self, MaybeUninit},
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
};

pub use libc::{seccomp_data, seccomp_notif, seccomp_notif_addfd, seccomp_notif_resp};

/// `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP` (kernel >= 6.6): wake the notified task on the
/// supervisor's CPU. Not in the host uapi headers / libc yet, so defined here.
pub const SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP: u64 = 1;

pub fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn check(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret < 0 { Err(last_error()) } else { Ok(ret) }
}

fn check_int(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 { Err(last_error()) } else { Ok(ret) }
}

/// Install a seccomp filter on the calling thread and return the notification listener fd.
pub fn install_filter(filter: &[libc::sock_filter]) -> io::Result<OwnedFd> {
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    unsafe {
        check_int(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
        let fd = check(libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        ))?;
        Ok(OwnedFd::from_raw_fd(fd as RawFd))
    }
}

/// Despite the `_IOW(.., __u64)` encoding the kernel takes the flags by value
/// (`seccomp_notify_set_flags(filter, arg)`), not via pointer.
pub fn set_sync_wake_up(listener: BorrowedFd<'_>) -> io::Result<()> {
    unsafe {
        check_int(libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_SET_FLAGS,
            SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP as libc::c_ulong,
        ))?;
    }
    Ok(())
}

/// Blocking receive of the next pending notification. Callers should `poll` first when they
/// cannot afford to block.
pub fn recv(listener: BorrowedFd<'_>) -> io::Result<seccomp_notif> {
    // The kernel insists on a zeroed struct.
    let mut notif: seccomp_notif = unsafe { mem::zeroed() };
    unsafe {
        check_int(libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_RECV,
            &mut notif as *mut seccomp_notif,
        ))?;
    }
    Ok(notif)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Return `val` from the syscall.
    Value(i64),
    /// Fail the syscall with `-errno`.
    Errno(i32),
    /// Let the kernel run the original syscall unchanged.
    Continue,
}

impl Answer {
    pub fn err(errno: i32) -> Self {
        Answer::Errno(errno)
    }
}

pub fn send(listener: BorrowedFd<'_>, id: u64, answer: Answer) -> io::Result<()> {
    let mut resp: seccomp_notif_resp = unsafe { mem::zeroed() };
    resp.id = id;
    match answer {
        Answer::Value(val) => resp.val = val,
        Answer::Errno(errno) => resp.error = -errno,
        Answer::Continue => resp.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    }
    unsafe {
        check_int(libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_SEND,
            &mut resp as *mut seccomp_notif_resp,
        ))?;
    }
    Ok(())
}

pub fn id_valid(listener: BorrowedFd<'_>, id: u64) -> bool {
    unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
            &id as *const u64,
        ) == 0
    }
}

/// Install `srcfd` into the notified task at exactly `newfd` (dup2 semantics if occupied). With
/// `send`, the notification is also answered with `newfd` as the syscall's return value.
pub fn addfd(
    listener: BorrowedFd<'_>,
    id: u64,
    srcfd: BorrowedFd<'_>,
    newfd: RawFd,
    cloexec: bool,
    send: bool,
) -> io::Result<RawFd> {
    let mut req: seccomp_notif_addfd = unsafe { mem::zeroed() };
    req.id = id;
    req.flags = libc::SECCOMP_ADDFD_FLAG_SETFD as u32
        | if send { libc::SECCOMP_ADDFD_FLAG_SEND as u32 } else { 0 };
    req.srcfd = srcfd.as_raw_fd() as u32;
    req.newfd = newfd as u32;
    req.newfd_flags = if cloexec { libc::O_CLOEXEC as u32 } else { 0 };
    unsafe {
        check_int(libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_ADDFD,
            &mut req as *mut seccomp_notif_addfd,
        ))
    }
}

pub fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    unsafe {
        let fd = check(libc::syscall(libc::SYS_pidfd_open, pid, 0))?;
        Ok(OwnedFd::from_raw_fd(fd as RawFd))
    }
}

pub fn pidfd_getfd(pidfd: BorrowedFd<'_>, target_fd: RawFd) -> io::Result<OwnedFd> {
    unsafe {
        let fd = check(libc::syscall(
            libc::SYS_pidfd_getfd,
            pidfd.as_raw_fd(),
            target_fd,
            0,
        ))?;
        Ok(OwnedFd::from_raw_fd(fd as RawFd))
    }
}

/// Read `buf.len()` bytes at `addr` in the notifying task's address space.
pub fn read_mem(pid: libc::pid_t, addr: u64, buf: &mut [u8]) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let n = unsafe { check(libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) as libc::c_long)? };
    if n as usize != buf.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short process_vm_readv"));
    }
    Ok(())
}

pub fn write_mem(pid: libc::pid_t, addr: u64, buf: &[u8]) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let local = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let n = unsafe { check(libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) as libc::c_long)? };
    if n as usize != buf.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "short process_vm_writev"));
    }
    Ok(())
}

pub fn read_pod<T: Copy>(pid: libc::pid_t, addr: u64) -> io::Result<T> {
    let mut value = MaybeUninit::<T>::uninit();
    let buf = unsafe {
        std::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, mem::size_of::<T>())
    };
    read_mem(pid, addr, buf)?;
    Ok(unsafe { value.assume_init() })
}

pub fn write_pod<T: Copy>(pid: libc::pid_t, addr: u64, value: &T) -> io::Result<()> {
    let buf = unsafe {
        std::slice::from_raw_parts(value as *const T as *const u8, mem::size_of::<T>())
    };
    write_mem(pid, addr, buf)
}

/// Read a NUL-free byte buffer of exactly `len` bytes, capped at `cap`.
pub fn read_bytes(pid: libc::pid_t, addr: u64, len: usize, cap: usize) -> io::Result<Vec<u8>> {
    let len = len.min(cap);
    let mut buf = vec![0u8; len];
    read_mem(pid, addr, &mut buf)?;
    Ok(buf)
}

/// Read the target's `iovec[iovcnt]` and gather up to `cap` bytes from it.
pub fn read_iov(pid: libc::pid_t, iov_addr: u64, iovcnt: usize, cap: usize) -> io::Result<Vec<u8>> {
    let iovcnt = iovcnt.min(libc::UIO_MAXIOV as usize);
    let mut out = Vec::new();
    for i in 0..iovcnt {
        let iov: libc::iovec =
            read_pod(pid, iov_addr + (i * mem::size_of::<libc::iovec>()) as u64)?;
        let remaining = cap.saturating_sub(out.len());
        if remaining == 0 {
            break;
        }
        let take = iov.iov_len.min(remaining);
        let mut chunk = vec![0u8; take];
        read_mem(pid, iov.iov_base as u64, &mut chunk)?;
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}
