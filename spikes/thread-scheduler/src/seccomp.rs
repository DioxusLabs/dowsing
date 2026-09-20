//! seccomp-BPF filter: `SECCOMP_RET_TRACE` for the scheduling syscalls, `ALLOW` for everything
//! else. Installed by the child between `fork` and `execve`, so the tracer must be attached before
//! the first traced syscall (the child stops itself with `SIGSTOP` right after installing it).

use std::io;

pub const SCHEDULING_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_futex,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_sched_yield,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    libc::SYS_epoll_wait,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_select,
    libc::SYS_pselect6,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_getrandom,
    crate::shm::MARKER_SYSCALL,
];

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

const fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

const BPF_LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const BPF_JMP_JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const BPF_RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

/// Build the filter program.
pub fn program() -> Vec<libc::sock_filter> {
    let mut prog = Vec::new();
    // arch check (offset 4 = seccomp_data.arch)
    prog.push(stmt(BPF_LD_W_ABS, 4));
    prog.push(jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0));
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    // nr (offset 0)
    prog.push(stmt(BPF_LD_W_ABS, 0));
    let n = SCHEDULING_SYSCALLS.len();
    for (i, nr) in SCHEDULING_SYSCALLS.iter().enumerate() {
        // Match -> jump over the remaining comparisons and the ALLOW to the TRACE.
        let remaining = (n - 1 - i) as u8;
        prog.push(jump(BPF_JMP_JEQ_K, *nr as u32, remaining + 1, 0));
    }
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_TRACE));
    prog
}

/// Install the filter in the current process (call from `pre_exec`).
pub fn install() -> io::Result<()> {
    let prog = program();
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &fprog as *const libc::sock_fprog,
            0,
            0,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
