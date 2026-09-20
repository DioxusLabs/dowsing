//! seccomp-BPF filter: `SECCOMP_RET_TRACE` for the modelled syscalls, `ALLOW` for everything
//! else. One program, composed from the core's syscalls ([`CORE`]) and every installed model's
//! [`Filter`]; built by the supervisor and installed by the child between `fork` and `execve`.
//! The tracer is attached before the first traced syscall because the child stops itself with
//! `SIGSTOP` right after installing it.
//!
//! Descriptor syscalls (`read`, `write`, `close`, ...) are traced only when the descriptor is
//! one a model handed out (`>= VFD_BASE`); the target's ordinary files stay kernel-side at no
//! cost.

use crate::model::{Filter, VFD_BASE};
use std::io;

/// What the core itself stops for: the scheduler's syscalls (futex, clone, yield, exit), the
/// target runtime's marker, and the two the snapshot mechanism must see.
pub const CORE: Filter = Filter {
    always: &[
        libc::SYS_futex,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_rseq,
        libc::SYS_munmap,
        crate::shm::MARKER_SYSCALL,
    ],
    vfd: &[],
};

/// A ready-to-install program.
#[derive(Debug, Clone)]
pub struct Program {
    insns: Vec<libc::sock_filter>,
}

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

impl Program {
    /// Compose one program from `filters`. A syscall in any `always` list is always traced; one
    /// only in `vfd` lists is traced when `arg0 >= VFD_BASE`. Layout:
    /// ```text
    ///   ld arch; jeq x86_64 else KILL
    ///   ld nr
    ///   jeq <always traced>  -> TRACE      (one per entry)
    ///   jeq <fd syscall>     -> FDCHECK    (one per entry)
    ///   ret ALLOW
    /// FDCHECK: ld arg0; jge VFD_BASE -> TRACE; ret ALLOW
    /// TRACE:   ret TRACE
    /// ```
    pub fn compose(filters: &[Filter]) -> Self {
        let mut always: Vec<libc::c_long> = Vec::new();
        let mut vfd: Vec<libc::c_long> = Vec::new();
        for f in filters {
            for nr in f.always {
                if !always.contains(nr) {
                    always.push(*nr);
                }
            }
        }
        for f in filters {
            for nr in f.vfd {
                if !always.contains(nr) && !vfd.contains(nr) {
                    vfd.push(*nr);
                }
            }
        }
        let (a, f) = (always.len(), vfd.len());
        assert!(a + f + 4 < 256, "filter too large for 8-bit BPF jumps");
        let mut insns = vec![
            stmt(BPF_LD_W_ABS, 4),
            jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
            stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
            stmt(BPF_LD_W_ABS, 0),
        ];
        // Instruction indices relative to the first `jeq`.
        let allow = a + f;
        let fdcheck = allow + 1;
        let trace = fdcheck + 3;
        for (i, nr) in always.iter().enumerate() {
            insns.push(jump(BPF_JMP_JEQ_K, *nr as u32, (trace - i - 1) as u8, 0));
        }
        for (i, nr) in vfd.iter().enumerate() {
            let at = a + i;
            insns.push(jump(BPF_JMP_JEQ_K, *nr as u32, (fdcheck - at - 1) as u8, 0));
        }
        insns.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        insns.push(stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARG0));
        insns.push(jump(BPF_JMP_JGE_K, VFD_BASE as u32, 1, 0));
        insns.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        insns.push(stmt(BPF_RET_K, SECCOMP_RET_TRACE));
        Self { insns }
    }

    pub fn len(&self) -> usize {
        self.insns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }
}

/// Install `prog` in the current process. Allocation-free, so it is safe between fork and exec.
pub fn install(prog: &Program) -> io::Result<()> {
    let fprog = libc::sock_fprog {
        len: prog.insns.len() as u16,
        filter: prog.insns.as_ptr() as *mut libc::sock_filter,
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
    use crate::{
        model::Model,
        models::{Entropy, Net, Time},
    };

    fn filters() -> [Filter; 4] {
        [CORE, Time::FILTER, Entropy::FILTER, Net::FILTER]
    }

    fn evaluate(arch: u32, nr: u32, arg0: u32) -> u32 {
        let prog = Program::compose(&filters()).insns;
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
        let always: Vec<libc::c_long> = filters().iter().flat_map(|f| f.always).copied().collect();
        let vfd: Vec<libc::c_long> = filters().iter().flat_map(|f| f.vfd).copied().collect();
        assert!(always.contains(&libc::SYS_futex) && always.contains(&libc::SYS_socket));
        assert!(vfd.contains(&libc::SYS_read));
        for nr in &always {
            assert_eq!(
                evaluate(AUDIT_ARCH_X86_64, *nr as u32, 0),
                SECCOMP_RET_TRACE
            );
        }
        for nr in &vfd {
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
