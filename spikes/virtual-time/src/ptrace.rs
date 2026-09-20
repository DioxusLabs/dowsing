//! Thin `ptrace(2)` and remote-memory wrappers (x86-64).

use std::{io, mem::MaybeUninit};

use libc::{c_long, c_void, pid_t, user_regs_struct};

pub const PTRACE_EVENT_FORK: i32 = 1;
pub const PTRACE_EVENT_VFORK: i32 = 2;
pub const PTRACE_EVENT_CLONE: i32 = 3;
pub const PTRACE_EVENT_EXEC: i32 = 4;
pub const PTRACE_EVENT_EXIT: i32 = 6;
pub const PTRACE_EVENT_SECCOMP: i32 = 7;
pub const PTRACE_EVENT_STOP: i32 = 128;

/// Options set on every tracee.
pub const OPTIONS: c_long = libc::PTRACE_O_TRACESYSGOOD as c_long
    | libc::PTRACE_O_TRACESECCOMP as c_long
    | libc::PTRACE_O_TRACECLONE as c_long
    | libc::PTRACE_O_TRACEFORK as c_long
    | libc::PTRACE_O_TRACEVFORK as c_long
    | libc::PTRACE_O_TRACEEXEC as c_long
    | libc::PTRACE_O_TRACEEXIT as c_long
    | libc::PTRACE_O_EXITKILL as c_long;

fn check(r: c_long) -> io::Result<c_long> {
    if r == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

pub fn traceme() -> io::Result<()> {
    unsafe { check(libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0)).map(|_| ()) }
}

pub fn setoptions(tid: pid_t, options: c_long) -> io::Result<()> {
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            tid,
            std::ptr::null_mut::<c_void>(),
            options as *mut c_void,
        ))
        .map(|_| ())
    }
}

pub fn cont(tid: pid_t, sig: i32) -> io::Result<()> {
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_CONT,
            tid,
            std::ptr::null_mut::<c_void>(),
            sig as c_long as *mut c_void,
        ))
        .map(|_| ())
    }
}

/// Resume and stop again at the next syscall entry/exit.
pub fn syscall(tid: pid_t, sig: i32) -> io::Result<()> {
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_SYSCALL,
            tid,
            std::ptr::null_mut::<c_void>(),
            sig as c_long as *mut c_void,
        ))
        .map(|_| ())
    }
}

pub fn getregs(tid: pid_t) -> io::Result<user_regs_struct> {
    let mut regs = MaybeUninit::<user_regs_struct>::uninit();
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_GETREGS,
            tid,
            std::ptr::null_mut::<c_void>(),
            regs.as_mut_ptr() as *mut c_void,
        ))?;
        Ok(regs.assume_init())
    }
}

pub fn setregs(tid: pid_t, regs: &user_regs_struct) -> io::Result<()> {
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_SETREGS,
            tid,
            std::ptr::null_mut::<c_void>(),
            regs as *const user_regs_struct as *mut c_void,
        ))
        .map(|_| ())
    }
}

pub fn geteventmsg(tid: pid_t) -> io::Result<u64> {
    let mut msg: libc::c_ulong = 0;
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_GETEVENTMSG,
            tid,
            std::ptr::null_mut::<c_void>(),
            &mut msg as *mut libc::c_ulong as *mut c_void,
        ))?;
    }
    Ok(msg as u64)
}

/// Read `buf.len()` bytes at `addr` in the tracee's address space.
pub fn read_mem(pid: pid_t, addr: u64, buf: &mut [u8]) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut c_void,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as usize as *mut c_void,
        iov_len: buf.len(),
    };
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("short remote read at {addr:#x}: {n} of {}", buf.len()),
        ));
    }
    Ok(())
}

pub fn write_mem(pid: pid_t, addr: u64, buf: &[u8]) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let local = libc::iovec {
        iov_base: buf.as_ptr() as *mut c_void,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as usize as *mut c_void,
        iov_len: buf.len(),
    };
    let n = unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short remote write at {addr:#x}: {n} of {}", buf.len()),
        ));
    }
    Ok(())
}

pub fn read_u64(pid: pid_t, addr: u64) -> io::Result<u64> {
    let mut buf = [0_u8; 8];
    read_mem(pid, addr, &mut buf)?;
    Ok(u64::from_ne_bytes(buf))
}

pub fn write_u64(pid: pid_t, addr: u64, value: u64) -> io::Result<()> {
    write_mem(pid, addr, &value.to_ne_bytes())
}

/// `struct timespec` in the tracee (two i64s on x86-64).
pub fn read_timespec(pid: pid_t, addr: u64) -> io::Result<(i64, i64)> {
    let mut buf = [0_u8; 16];
    read_mem(pid, addr, &mut buf)?;
    Ok((
        i64::from_ne_bytes(buf[..8].try_into().unwrap()),
        i64::from_ne_bytes(buf[8..].try_into().unwrap()),
    ))
}

pub fn write_timespec(pid: pid_t, addr: u64, secs: i64, nanos: i64) -> io::Result<()> {
    let mut buf = [0_u8; 16];
    buf[..8].copy_from_slice(&secs.to_ne_bytes());
    buf[8..].copy_from_slice(&nanos.to_ne_bytes());
    write_mem(pid, addr, &buf)
}

/// Rewrite the freshly exec'd tracee's auxv so `AT_SYSINFO_EHDR` becomes `AT_IGNORE`.
///
/// glibc and musl then never find the vDSO and issue real `clock_gettime`/`gettimeofday`/`time`
/// syscalls, which the seccomp filter can trap.  Returns whether an entry was rewritten.
pub fn hide_vdso_in_auxv(pid: pid_t, rsp: u64) -> io::Result<bool> {
    const AT_IGNORE: u64 = 1;
    const AT_SYSINFO_EHDR: u64 = 33;
    const AT_NULL: u64 = 0;

    let argc = read_u64(pid, rsp)?;
    // argv pointers + NULL terminator.
    let mut p = rsp + 8 + (argc + 1) * 8;
    // envp until NULL.
    loop {
        let v = read_u64(pid, p)?;
        p += 8;
        if v == 0 {
            break;
        }
    }
    // auxv pairs.
    let mut rewritten = false;
    for _ in 0..512 {
        let key = read_u64(pid, p)?;
        if key == AT_NULL {
            break;
        }
        if key == AT_SYSINFO_EHDR {
            write_u64(pid, p, AT_IGNORE)?;
            rewritten = true;
        }
        p += 16;
    }
    Ok(rewritten)
}

/// `Tgid:` from `/proc/<tid>/status` (threads report their group leader).
pub fn tgid_of(tid: pid_t) -> io::Result<pid_t> {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status"))?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest
                .trim()
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")));
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "no Tgid line"))
}

pub fn pidfd_open(pid: pid_t) -> io::Result<i32> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd as i32)
    }
}

pub fn pidfd_getfd(pidfd: i32, targetfd: i32) -> io::Result<i32> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, targetfd, 0) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd as i32)
    }
}
