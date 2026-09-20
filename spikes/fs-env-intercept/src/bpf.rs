//! seccomp-BPF program for the sandbox filter and its installation on the calling thread.
//!
//! The program traps (`SECCOMP_RET_USER_NOTIF`) exactly the syscalls the supervisor models and
//! lets everything else through at native speed. `read`-family calls are trapped only when their
//! fd argument is inside the fixed fd window used for injected entropy fds.

use std::io;

/// First fd of the window into which `/dev/urandom` fds are injected. Each sandbox in a process
/// gets its own window (`URANDOM_FD_BASE + k * URANDOM_FD_SLOTS`, see [`install`]) because the fd
/// table is process-wide; `read`/`pread` on fds in the window are trapped, all other reads are
/// native.
pub const URANDOM_FD_BASE: u32 = 1000;
pub const URANDOM_FD_SLOTS: u32 = 8;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const PR_SET_SECCOMP: u64 = 22;

const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0_LO: u32 = 16;
const OFF_ARG0_HI: u32 = 20;

/// Syscalls that are always trapped (path based, entropy, identity).
pub const TRAPPED: &[libc::c_long] = &[
    libc::SYS_openat,
    libc::SYS_open,
    libc::SYS_openat2,
    libc::SYS_statx,
    libc::SYS_newfstatat,
    libc::SYS_stat,
    libc::SYS_lstat,
    libc::SYS_readlink,
    libc::SYS_readlinkat,
    libc::SYS_access,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_getrandom,
    libc::SYS_getpid,
    libc::SYS_gettid,
    libc::SYS_uname,
    libc::SYS_sysinfo,
];

/// `read`-family syscalls trapped only when `args[0]` is in the urandom fd window.
pub const FD_TRAPPED: &[libc::c_long] = &[
    libc::SYS_read,
    libc::SYS_pread64,
    libc::SYS_readv,
    libc::SYS_preadv,
    libc::SYS_preadv2,
];

#[derive(Clone, Copy)]
enum Target {
    Next,
    Allow,
    Notif,
    Eperm,
    FdCheck,
    PrctlCheck,
}

struct Insn {
    code: u16,
    k: u32,
    jt: Target,
    jf: Target,
}

fn stmt(code: u32, k: u32) -> Insn {
    Insn {
        code: code as u16,
        k,
        jt: Target::Next,
        jf: Target::Next,
    }
}

fn jump(code: u32, k: u32, jt: Target, jf: Target) -> Insn {
    Insn {
        code: code as u16,
        k,
        jt,
        jf,
    }
}

/// Build the filter program.
pub fn program(urandom_base: u32) -> Vec<libc::sock_filter> {
    let mut insns = Vec::new();
    insns.push(stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, OFF_ARCH));
    insns.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        AUDIT_ARCH_X86_64,
        Target::Next,
        Target::Allow,
    ));
    insns.push(stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, OFF_NR));
    for nr in FD_TRAPPED {
        insns.push(jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            *nr as u32,
            Target::FdCheck,
            Target::Next,
        ));
    }
    for nr in TRAPPED {
        insns.push(jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            *nr as u32,
            Target::Notif,
            Target::Next,
        ));
    }
    insns.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        libc::SYS_seccomp as u32,
        Target::Eperm,
        Target::Next,
    ));
    insns.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        libc::SYS_prctl as u32,
        Target::PrctlCheck,
        Target::Allow,
    ));
    let fd_check = insns.len();
    insns.push(stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, OFF_ARG0_HI));
    insns.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        0,
        Target::Next,
        Target::Allow,
    ));
    insns.push(stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, OFF_ARG0_LO));
    insns.push(jump(
        libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K,
        urandom_base,
        Target::Next,
        Target::Allow,
    ));
    insns.push(jump(
        libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K,
        urandom_base + URANDOM_FD_SLOTS,
        Target::Allow,
        Target::Notif,
    ));
    let prctl_check = insns.len();
    insns.push(stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, OFF_ARG0_HI));
    insns.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        0,
        Target::Next,
        Target::Allow,
    ));
    insns.push(stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, OFF_ARG0_LO));
    insns.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        PR_SET_SECCOMP as u32,
        Target::Eperm,
        Target::Allow,
    ));
    let notif = insns.len();
    insns.push(stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_USER_NOTIF));
    let eperm = insns.len();
    insns.push(stmt(
        libc::BPF_RET | libc::BPF_K,
        libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
    ));
    let allow = insns.len();
    insns.push(stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW));
    let _ = SECCOMP_RET_KILL_PROCESS;

    let resolve = |index: usize, target: Target| -> u8 {
        let dest = match target {
            Target::Next => index + 1,
            Target::Allow => allow,
            Target::Notif => notif,
            Target::Eperm => eperm,
            Target::FdCheck => fd_check,
            Target::PrctlCheck => prctl_check,
        };
        u8::try_from(dest - index - 1).expect("bpf jump offset fits in u8")
    };
    insns
        .iter()
        .enumerate()
        .map(|(index, insn)| libc::sock_filter {
            code: insn.code,
            jt: resolve(index, insn.jt),
            jf: resolve(index, insn.jf),
            k: insn.k,
        })
        .collect()
}

/// Install the filter on the calling thread and return the notification listener fd.
///
/// The filter is permanent for the lifetime of the thread and is inherited by threads it spawns
/// afterwards. Sets `PR_SET_NO_NEW_PRIVS`.
pub fn install(urandom_base: u32) -> io::Result<i32> {
    let mut program = program(urandom_base);
    let prog = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
    // SAFETY: plain prctl with integer arguments.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `prog` points at a live, correctly sized filter array.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd as i32)
}
