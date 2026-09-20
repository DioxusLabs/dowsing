//! Per-syscall interception cost (no Criterion: `harness = false`, plain wall-clock timing).
//!
//! Run with `cargo bench --bench roundtrip` (release). Each row forks a child that issues
//! `getppid` N times; the parent answers every notification the same way. Numbers are
//! wall-clock per syscall as seen by the child, including the supervisor's answer.

use std::{
    io::Write,
    os::fd::{AsRawFd, BorrowedFd},
    time::{Duration, Instant},
};

use net_intercept::{
    bpf::Rule,
    child::{self, Handled},
    notif::{self, Answer},
    probe_features,
};

const N: u64 = 200_000;

fn pin_to_cpu0() {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(0, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

fn unpin() {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        for i in 0..libc::CPU_SETSIZE as usize {
            libc::CPU_SET(i, &mut set);
        }
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

fn getppid_loop(n: u64) -> i32 {
    for _ in 0..n {
        unsafe { libc::syscall(libc::SYS_getppid) };
    }
    0
}

/// Child hits `getppid` N times; parent answers with `answer`. Returns ns/syscall.
fn measure(rules: &[Rule], sync: bool, n: u64, mut on: impl FnMut(&child::Notification<'_>) -> Handled) -> (f64, bool) {
    let start = Instant::now();
    let mut spawned = child::spawn(rules, sync, move || getppid_loop(n)).expect("spawn");
    let sync_on = spawned.sync_wake_up;
    spawned
        .serve(Duration::from_secs(120), |nf| on(nf))
        .expect("serve");
    let elapsed = start.elapsed();
    (elapsed.as_nanos() as f64 / n as f64, sync_on)
}

fn row(name: &str, ns: f64, note: &str) {
    println!("{name:<52} {ns:>9.1} ns/syscall  {note}");
    let _ = std::io::stdout().flush();
}

fn main() {
    let features = probe_features();
    println!("features: {features:?}");
    println!("N = {N} syscalls per row\n");

    // Baseline: no filter at all (plain fork).
    {
        let start = Instant::now();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            getppid_loop(N);
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        row("getppid, no seccomp filter", start.elapsed().as_nanos() as f64 / N as f64, "");
    }
    // Filter installed but getppid falls through to RET_ALLOW.
    {
        let (ns, _) = measure(&[Rule::Notify(libc::SYS_io_uring_setup)], true, N, |_| unreachable!());
        row("getppid, filter installed, RET_ALLOW", ns, "");
    }

    let rules = [Rule::Notify(libc::SYS_getppid)];
    for pinned in [false, true] {
        if pinned {
            pin_to_cpu0();
        } else {
            unpin();
        }
        let pin = if pinned { "pinned cpu0" } else { "unpinned" };
        for sync in [false, true] {
            let (ns, on) = measure(&rules, sync, N, |_| Handled::Reply(Answer::Value(1)));
            row(
                &format!("notify -> Value, SYNC_WAKE_UP={}, {pin}", if on { "on" } else { "off" }),
                ns,
                "",
            );
            let (ns, on) = measure(&rules, sync, N, |_| Handled::Reply(Answer::Continue));
            row(
                &format!("notify -> CONTINUE, SYNC_WAKE_UP={}, {pin}", if on { "on" } else { "off" }),
                ns,
                "(kernel runs getppid after the answer)",
            );
        }
        // Reading 64 bytes of target memory per notification (process_vm_readv).
        let (ns, _) = measure(&rules, true, N, |nf| {
            let mut buf = [0u8; 64];
            let _ = nf.read_mem(nf.notif.data.instruction_pointer, &mut buf);
            Handled::Reply(Answer::Value(1))
        });
        row(&format!("notify + process_vm_readv(64B) -> Value, sync, {pin}"), ns, "");
        // ADDFD per notification: install our stdin at a fresh fd and answer with it.
        let (ns, _) = measure(&rules, true, N / 10, |nf| {
            let stdin = unsafe { BorrowedFd::borrow_raw(std::io::stdin().as_raw_fd()) };
            let _ = nf.addfd_and_return(stdin, 1000, true);
            Handled::Done
        });
        row(&format!("notify + ADDFD(SETFD 1000|SEND), sync, {pin}"), ns, &format!("(N={})", N / 10));
    }
    unpin();

    // Per-case fixed cost: fork + filter install + listener handoff + exit + reap.
    {
        let iters = 300;
        let start = Instant::now();
        for _ in 0..iters {
            let mut s = child::spawn(&rules, true, || 0).expect("spawn");
            s.serve(Duration::from_secs(10), |_| Handled::Reply(Answer::Value(1))).unwrap();
        }
        let per = start.elapsed() / iters;
        println!(
            "\nfork + filter + pidfd_getfd handoff + exit + reap: {:.1} us/case (RSS {} KiB)",
            per.as_secs_f64() * 1e6,
            rss_kib()
        );
    }
    let _ = notif::errno();
}

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0)
}
