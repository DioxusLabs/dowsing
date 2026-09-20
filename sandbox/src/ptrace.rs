//! Thin `libc` wrappers around the ptrace / wait / process_vm_* calls the session needs.
//! x86_64 Linux only.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

pub type Pid = libc::pid_t;
pub type Regs = libc::user_regs_struct;

fn check(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

pub fn seize(pid: Pid, options: libc::c_ulong) -> io::Result<()> {
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_SEIZE,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            options as *mut libc::c_void,
        ))?;
    }
    Ok(())
}

pub fn interrupt(pid: Pid) -> io::Result<()> {
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_INTERRUPT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        ))?;
    }
    Ok(())
}

/// Resume `pid`; `sig` (0 = none) is delivered on resume.
pub fn cont(pid: Pid, sig: libc::c_int) -> io::Result<()> {
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            sig as usize as *mut libc::c_void,
        ))?;
    }
    Ok(())
}

/// Resume `pid` until the next syscall entry/exit stop.
pub fn syscall(pid: Pid, sig: libc::c_int) -> io::Result<()> {
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_SYSCALL,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            sig as usize as *mut libc::c_void,
        ))?;
    }
    Ok(())
}

pub fn detach(pid: Pid) -> io::Result<()> {
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_DETACH,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        ))?;
    }
    Ok(())
}

pub fn getregs(pid: Pid) -> io::Result<Regs> {
    let mut regs: Regs = unsafe { std::mem::zeroed() };
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            &mut regs as *mut Regs as *mut libc::c_void,
        ))?;
    }
    Ok(regs)
}

pub fn setregs(pid: Pid, regs: &Regs) -> io::Result<()> {
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_SETREGS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            regs as *const Regs as *mut libc::c_void,
        ))?;
    }
    Ok(())
}

pub fn geteventmsg(pid: Pid) -> io::Result<libc::c_ulong> {
    let mut msg: libc::c_ulong = 0;
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_GETEVENTMSG,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            &mut msg as *mut libc::c_ulong as *mut libc::c_void,
        ))?;
    }
    Ok(msg)
}

/// Read `dst.len()` bytes at `addr` in `pid`'s address space: one `process_vm_readv`, or
/// `/proc/pid/mem` (which ignores page protections for a tracer) when that is refused.
pub fn read_mem(pid: Pid, addr: u64, dst: &mut [u8]) -> io::Result<()> {
    let local = libc::iovec {
        iov_base: dst.as_mut_ptr() as *mut libc::c_void,
        iov_len: dst.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as usize as *mut libc::c_void,
        iov_len: dst.len(),
    };
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n == dst.len() as isize {
        return Ok(());
    }
    let mem = File::open(format!("/proc/{pid}/mem"))?;
    mem.read_exact_at(dst, addr)
}

pub fn write_mem(pid: Pid, addr: u64, src: &[u8]) -> io::Result<()> {
    let local = libc::iovec {
        iov_base: src.as_ptr() as *mut libc::c_void,
        iov_len: src.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as usize as *mut libc::c_void,
        iov_len: src.len(),
    };
    let n = unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
    if n == src.len() as isize {
        return Ok(());
    }
    let mem = File::options()
        .write(true)
        .open(format!("/proc/{pid}/mem"))?;
    mem.write_all_at(src, addr)
}

pub fn read_u32(pid: Pid, addr: u64) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    read_mem(pid, addr, &mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}

/// One decoded `waitpid(-1, __WALL)` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitEvent {
    /// `PTRACE_EVENT_*` stop (`event` is the `PTRACE_EVENT_*` number).
    Event {
        pid: Pid,
        event: i32,
    },
    /// Syscall entry/exit stop (`SIGTRAP | 0x80`, requires `TRACESYSGOOD`).
    Syscall {
        pid: Pid,
    },
    /// Signal-delivery stop.
    Signal {
        pid: Pid,
        sig: i32,
    },
    /// Group-stop (`PTRACE_EVENT_STOP` with a stop signal).
    GroupStop {
        pid: Pid,
        sig: i32,
    },
    Exited {
        pid: Pid,
        code: i32,
    },
    Killed {
        pid: Pid,
        sig: i32,
    },
}

/// Wait for any tracee. Returns `Interrupted` if a signal (the watchdog) arrives first.
pub fn wait_any() -> io::Result<WaitEvent> {
    let mut status: libc::c_int = 0;
    let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
    if pid == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(decode(pid, status))
}

pub fn wait_pid(pid: Pid) -> io::Result<WaitEvent> {
    loop {
        let mut status: libc::c_int = 0;
        let ret = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if ret == -1 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        return Ok(decode(ret, status));
    }
}

fn decode(pid: Pid, status: libc::c_int) -> WaitEvent {
    if libc::WIFEXITED(status) {
        return WaitEvent::Exited {
            pid,
            code: libc::WEXITSTATUS(status),
        };
    }
    if libc::WIFSIGNALED(status) {
        return WaitEvent::Killed {
            pid,
            sig: libc::WTERMSIG(status),
        };
    }
    debug_assert!(libc::WIFSTOPPED(status));
    let sig = libc::WSTOPSIG(status);
    let event = (status >> 16) & 0xff;
    if event != 0 {
        if event == libc::PTRACE_EVENT_STOP && sig != libc::SIGTRAP {
            return WaitEvent::GroupStop { pid, sig };
        }
        return WaitEvent::Event { pid, event };
    }
    if sig == libc::SIGTRAP | 0x80 {
        return WaitEvent::Syscall { pid };
    }
    WaitEvent::Signal { pid, sig }
}

pub const SEIZE_OPTIONS: libc::c_ulong = (libc::PTRACE_O_TRACECLONE
    | libc::PTRACE_O_TRACEEXIT
    | libc::PTRACE_O_TRACESECCOMP
    | libc::PTRACE_O_TRACESYSGOOD
    | libc::PTRACE_O_TRACEEXEC
    | libc::PTRACE_O_EXITKILL) as libc::c_ulong;

/// Resume `pid` for exactly one instruction (stops with `SIGTRAP`).
pub fn singlestep(pid: Pid) -> io::Result<()> {
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_SINGLESTEP,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        ))?;
    }
    Ok(())
}

/// `NT_X86_XSTATE`: the full XSAVE area (x87/SSE/AVX state), variable length.
pub const NT_X86_XSTATE: libc::c_ulong = 0x202;
pub const XSTATE_MAX: usize = 1 << 14;

/// Fetch a register set via `PTRACE_GETREGSET`; returns the bytes the kernel filled in.
pub fn getregset(pid: Pid, nt: libc::c_ulong) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; XSTATE_MAX];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            nt as *mut libc::c_void,
            &mut iov as *mut libc::iovec as *mut libc::c_void,
        ))?;
    }
    buf.truncate(iov.iov_len);
    Ok(buf)
}

pub fn setregset(pid: Pid, nt: libc::c_ulong, data: &[u8]) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    unsafe {
        check(libc::ptrace(
            libc::PTRACE_SETREGSET,
            pid,
            nt as *mut libc::c_void,
            &mut iov as *mut libc::iovec as *mut libc::c_void,
        ))?;
    }
    Ok(())
}

pub fn read_u64(pid: Pid, addr: u64) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    read_mem(pid, addr, &mut buf)?;
    Ok(u64::from_ne_bytes(buf))
}

pub fn write_u64(pid: Pid, addr: u64, value: u64) -> io::Result<()> {
    write_mem(pid, addr, &value.to_ne_bytes())
}

pub fn write_u32(pid: Pid, addr: u64, value: u32) -> io::Result<()> {
    write_mem(pid, addr, &value.to_ne_bytes())
}

/// Rewrite the freshly exec'd tracee's auxv so `AT_SYSINFO_EHDR` becomes `AT_IGNORE`: libc then
/// never finds the vDSO and clock reads become real syscalls. `rsp` is the initial stack pointer
/// (points at `argc`). Returns whether an entry was rewritten.
pub fn hide_vdso_in_auxv(pid: Pid, rsp: u64) -> io::Result<bool> {
    const AT_IGNORE: u64 = 1;
    const AT_SYSINFO_EHDR: u64 = 33;
    const AT_NULL: u64 = 0;
    let argc = read_u64(pid, rsp)?;
    let mut p = rsp + 8 + (argc + 1) * 8;
    loop {
        let v = read_u64(pid, p)?;
        p += 8;
        if v == 0 {
            break;
        }
    }
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
