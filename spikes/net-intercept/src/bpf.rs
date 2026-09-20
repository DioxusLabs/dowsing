//! Classic-BPF seccomp filter builder.
//!
//! The filter is a linear chain of per-syscall rules. Fd-taking syscalls are only notified when
//! the fd argument is `>= FAKE_FD_BASE`, so ordinary file I/O in the target never leaves the
//! kernel.

use libc::sock_filter;

pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// Fake sockets are installed at this fd and above so the filter can tell them apart from files.
pub const FAKE_FD_BASE: u32 = 1000;

#[derive(Debug, Clone, Copy)]
pub enum Rule {
    /// Always notify the supervisor.
    Notify(i64),
    /// Notify only if the given (0-based) argument, read as a 32-bit fd, is `>= FAKE_FD_BASE`.
    NotifyIfFakeFd(i64, u8),
    /// Fail with this errno without notifying.
    Errno(i64, i32),
}

const fn stmt(code: u32, k: u32) -> sock_filter {
    sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u32, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

const LD_W_ABS: u32 = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
const JEQ_K: u32 = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
const JGE_K: u32 = libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K;
const RET_K: u32 = libc::BPF_RET | libc::BPF_K;

const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const fn off_arg_lo(i: u8) -> u32 {
    16 + 8 * i as u32
}

pub fn build(rules: &[Rule]) -> Vec<sock_filter> {
    let mut f = Vec::with_capacity(4 + rules.len() * 5);
    f.push(stmt(LD_W_ABS, OFF_ARCH));
    f.push(jump(JEQ_K, AUDIT_ARCH_X86_64, 1, 0));
    f.push(stmt(RET_K, libc::SECCOMP_RET_KILL_PROCESS));
    f.push(stmt(LD_W_ABS, OFF_NR));
    for rule in rules {
        match *rule {
            Rule::Notify(nr) => {
                f.push(jump(JEQ_K, nr as u32, 0, 1));
                f.push(stmt(RET_K, libc::SECCOMP_RET_USER_NOTIF));
            }
            Rule::Errno(nr, errno) => {
                f.push(jump(JEQ_K, nr as u32, 0, 1));
                f.push(stmt(RET_K, libc::SECCOMP_RET_ERRNO | (errno as u32 & 0xffff)));
            }
            Rule::NotifyIfFakeFd(nr, arg) => {
                f.push(jump(JEQ_K, nr as u32, 0, 4));
                f.push(stmt(LD_W_ABS, off_arg_lo(arg)));
                f.push(jump(JGE_K, FAKE_FD_BASE, 0, 1));
                f.push(stmt(RET_K, libc::SECCOMP_RET_USER_NOTIF));
                f.push(stmt(LD_W_ABS, OFF_NR));
            }
        }
    }
    f.push(stmt(RET_K, libc::SECCOMP_RET_ALLOW));
    assert!(f.len() < 4096);
    f
}

/// The full network-interception rule set.
pub fn network_rules() -> Vec<Rule> {
    use Rule::*;
    use libc::*;
    vec![
        // Creation: always ours.
        Notify(SYS_socket),
        // Readiness: always ours so we can gate the fds we own.
        Notify(SYS_poll),
        Notify(SYS_ppoll),
        Notify(SYS_select),
        Notify(SYS_pselect6),
        Notify(SYS_epoll_wait),
        Notify(SYS_epoll_pwait),
        Notify(SYS_epoll_pwait2),
        // Bypass routes we cannot supervise.
        Errno(SYS_io_uring_setup, ENOSYS),
        // Fd-scoped: only when the fd is one of ours.
        NotifyIfFakeFd(SYS_connect, 0),
        NotifyIfFakeFd(SYS_bind, 0),
        NotifyIfFakeFd(SYS_listen, 0),
        NotifyIfFakeFd(SYS_accept, 0),
        NotifyIfFakeFd(SYS_accept4, 0),
        NotifyIfFakeFd(SYS_getsockopt, 0),
        NotifyIfFakeFd(SYS_setsockopt, 0),
        NotifyIfFakeFd(SYS_getsockname, 0),
        NotifyIfFakeFd(SYS_getpeername, 0),
        NotifyIfFakeFd(SYS_shutdown, 0),
        NotifyIfFakeFd(SYS_close, 0),
        NotifyIfFakeFd(SYS_read, 0),
        NotifyIfFakeFd(SYS_readv, 0),
        NotifyIfFakeFd(SYS_recvfrom, 0),
        NotifyIfFakeFd(SYS_recvmsg, 0),
        NotifyIfFakeFd(SYS_recvmmsg, 0),
        NotifyIfFakeFd(SYS_write, 0),
        NotifyIfFakeFd(SYS_writev, 0),
        NotifyIfFakeFd(SYS_sendto, 0),
        NotifyIfFakeFd(SYS_sendmsg, 0),
        NotifyIfFakeFd(SYS_sendmmsg, 0),
        NotifyIfFakeFd(SYS_ioctl, 0),
        NotifyIfFakeFd(SYS_fcntl, 0),
        NotifyIfFakeFd(SYS_dup, 0),
        NotifyIfFakeFd(SYS_dup2, 0),
        NotifyIfFakeFd(SYS_dup3, 0),
    ]
}
