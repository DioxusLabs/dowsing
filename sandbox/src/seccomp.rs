//! seccomp-BPF filter: `SECCOMP_RET_TRACE` for the modelled syscalls, `ALLOW` for everything
//! else. Installed by the child between `fork` and `execve`; the tracer is attached before the
//! first traced syscall because the child stops itself with `SIGSTOP` right after installing it.
//!
//! Descriptor syscalls (`read`, `write`, `close`, ...) are traced only when the descriptor is
//! one the supervisor handed out (`>= VFD_BASE`); the target's ordinary files stay kernel-side
//! at no cost.

use crate::net::VFD_BASE;
use std::io;

/// Syscalls that always stop in the supervisor.
pub const TRACED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_futex,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_sched_yield,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    libc::SYS_clock_gettime,
    libc::SYS_gettimeofday,
    libc::SYS_time,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_getrandom,
    libc::SYS_rseq,
    libc::SYS_munmap,
    libc::SYS_epoll_wait,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_select,
    libc::SYS_pselect6,
    libc::SYS_socket,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_create,
    libc::SYS_eventfd2,
    libc::SYS_sched_getaffinity,
    crate::shm::MARKER_SYSCALL,
];

/// Syscalls that stop in the supervisor when their first argument is a virtual descriptor.
pub const FD_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    libc::SYS_recvmsg,
    libc::SYS_sendmsg,
    libc::SYS_close,
    libc::SYS_fcntl,
    libc::SYS_ioctl,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_connect,
    libc::SYS_shutdown,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    libc::SYS_epoll_ctl,
    libc::SYS_dup,
    libc::SYS_dup3,
    libc::SYS_fstat,
];

/// Offset of `args[0]`'s low word in `struct seccomp_data`.
const SECCOMP_DATA_ARG0: u32 = 16;

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
const BPF_JMP_JGE_K: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
const BPF_RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

/// Layout:
/// ```text
///   ld arch; jeq x86_64 else KILL
///   ld nr
///   jeq <always traced>  -> TRACE      (one per entry)
///   jeq <fd syscall>     -> FDCHECK    (one per entry)
///   ret ALLOW
/// FDCHECK: ld arg0; jge VFD_BASE -> TRACE; ret ALLOW
/// TRACE:   ret TRACE
/// ```
pub fn program() -> Vec<libc::sock_filter> {
    let mut prog = vec![
        stmt(BPF_LD_W_ABS, 4),
        jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD_W_ABS, 0),
    ];
    let (a, f) = (TRACED_SYSCALLS.len(), FD_SYSCALLS.len());
    // Instruction indices relative to the first `jeq`.
    let allow = a + f;
    let fdcheck = allow + 1;
    let trace = fdcheck + 3;
    for (i, nr) in TRACED_SYSCALLS.iter().enumerate() {
        prog.push(jump(BPF_JMP_JEQ_K, *nr as u32, (trace - i - 1) as u8, 0));
    }
    for (i, nr) in FD_SYSCALLS.iter().enumerate() {
        let at = a + i;
        prog.push(jump(BPF_JMP_JEQ_K, *nr as u32, (fdcheck - at - 1) as u8, 0));
    }
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARG0));
    prog.push(jump(BPF_JMP_JGE_K, VFD_BASE as u32, 1, 0));
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_TRACE));
    prog
}

/// Install the filter in the current process (async-signal-safe; called between fork and exec).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate(arch: u32, nr: u32, arg0: u32) -> u32 {
        let prog = program();
        let mut acc = 0u32;
        let mut pc = 0usize;
        loop {
            let insn = prog[pc];
            pc += 1;
            match insn.code {
                c if c == BPF_LD_W_ABS => {
                    acc = match insn.k {
                        0 => nr,
                        4 => arch,
                        SECCOMP_DATA_ARG0 => arg0,
                        k => panic!("unexpected load {k}"),
                    }
                }
                c if c == BPF_JMP_JEQ_K => {
                    pc += if acc == insn.k {
                        insn.jt as usize
                    } else {
                        insn.jf as usize
                    };
                }
                c if c == BPF_JMP_JGE_K => {
                    pc += if acc >= insn.k {
                        insn.jt as usize
                    } else {
                        insn.jf as usize
                    };
                }
                c if c == BPF_RET_K => return insn.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
        }
    }

    #[test]
    fn traces_only_modelled_syscalls() {
        for nr in TRACED_SYSCALLS {
            assert_eq!(
                evaluate(AUDIT_ARCH_X86_64, *nr as u32, 0),
                SECCOMP_RET_TRACE
            );
        }
        for nr in FD_SYSCALLS {
            assert_eq!(
                evaluate(AUDIT_ARCH_X86_64, *nr as u32, 3),
                SECCOMP_RET_ALLOW
            );
            assert_eq!(
                evaluate(AUDIT_ARCH_X86_64, *nr as u32, VFD_BASE as u32),
                SECCOMP_RET_TRACE
            );
            assert_eq!(
                evaluate(AUDIT_ARCH_X86_64, *nr as u32, VFD_BASE as u32 + 17),
                SECCOMP_RET_TRACE
            );
        }
        for nr in [libc::SYS_mmap, libc::SYS_openat, libc::SYS_brk] {
            assert_eq!(
                evaluate(AUDIT_ARCH_X86_64, nr as u32, VFD_BASE as u32),
                SECCOMP_RET_ALLOW
            );
        }
        assert_eq!(
            evaluate(0xdead_beef, libc::SYS_futex as u32, 0),
            SECCOMP_RET_KILL_PROCESS
        );
    }
}
