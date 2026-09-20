//! Classic-BPF seccomp filter that returns `SECCOMP_RET_TRACE` for the time-related syscalls
//! and `SECCOMP_RET_ALLOW` for everything else.

use std::io;

use libc::{sock_filter, sock_fprog};

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

/// Reserved syscall number the instrumented target uses to announce its sancov counter range.
/// It does not exist in the kernel table, so outside the sandbox it just returns `ENOSYS`.
pub const ANNOUNCE_NR: i64 = 0x1337;

/// Every syscall the supervisor wants to see.
pub const TRACED_SYSCALLS: &[i64] = &[
    libc::SYS_clock_gettime,
    libc::SYS_gettimeofday,
    libc::SYS_time,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    libc::SYS_futex,
    libc::SYS_epoll_wait,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_select,
    libc::SYS_pselect6,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    libc::SYS_getrandom,
    ANNOUNCE_NR,
];

fn stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// Build the filter program for `syscalls`.
pub fn build_filter(syscalls: &[i64]) -> Vec<sock_filter> {
    assert!(syscalls.len() < 250, "too many traced syscalls for one BPF jump table");
    let mut prog = Vec::with_capacity(syscalls.len() + 5);
    // seccomp_data.arch is at offset 4, seccomp_data.nr at offset 0.
    prog.push(stmt(BPF_LD_W_ABS, 4));
    prog.push(jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0));
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(BPF_LD_W_ABS, 0));
    let n = syscalls.len();
    for (i, nr) in syscalls.iter().enumerate() {
        // Skip over the remaining comparisons and the ALLOW to reach the final TRACE.
        let jt = (n - i) as u8;
        prog.push(jump(BPF_JMP_JEQ_K, *nr as u32, jt, 0));
    }
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_TRACE));
    prog
}

/// Install `filter` in the calling process.  Meant to run in the child between `fork` and `exec`.
///
/// # Safety
/// Async-signal-safe only (prctl); safe to call from a `pre_exec` closure.
pub unsafe fn install(filter: &[sock_filter]) -> io::Result<()> {
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        let prog = sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut sock_filter,
        };
        if libc::prctl(libc::PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog as *const sock_fprog) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
