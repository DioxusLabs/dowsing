# RESULTS — `virtual-time` prototype

Machine: Ubuntu, kernel `6.8.0-1061-aws`, x86-64, 8 vCPU, Rust 1.98.1, `ptrace_scope=1`,
`unprivileged_userfaultfd=0`, unprivileged user, no container seccomp restrictions on
`ptrace`/`seccomp`/`pidfd_getfd`/`process_vm_readv` (all worked without capabilities).
All binaries built with `cargo build --release` unless noted; wall times are from single runs and
vary by ±20 % between invocations.

## 1. std timing API probe (`vt_run -- probe_target`)

```
unix time at start: 1767225600
thread::sleep(1s): observed 1.000000s expected 1.000s ok
park_timeout(2s): observed 2.000000s expected 2.000s ok
Condvar::wait_timeout(3s): observed 3.000000s expected 3.000s ok
recv_timeout(4s): observed 4.000000s expected 4.000s ok
worker sleep(5s) + recv(): observed 5.000000s expected 5.000s ok
10 x sleep(100ms) in worker: observed 1.000000s expected 1.000s ok
SystemTime elapsed: observed 16.000002s expected 16.000s ok
timerfd_gettime after arming 7s: 7s
timerfd 7s via poll(): observed 7.000000s expected 7.000s ok
select(500ms): observed 0.500000s expected 0.500s ok
spin on Instant::now(): 9999 reads to pass 1ms
total virtual 23.501003s failures 0
outcome Exited(0)  virtual 23.501003s  wall 111.436ms  hash 0x45486b61b46ad1f7
stats StopStats { stops: 10077, clock_reads: 10030, sleeps: 12, futex_probes: 7, futex_parked: 5,
  poll_probes: 3, poll_parked: 2, wakes: 1, restarts: 3, jumps: 17, natural_jumps: 17,
  getrandom: 1, timerfd: 1, threads: 3 }
```

The 111 ms wall are the 10 030 emulated clock reads of the 1 ms spin (100 ns quantum). The
`SystemTime` value is 2 µs ahead of the monotonic one because `SystemTime::now()` is itself a
quantised read. `Instant`, `SystemTime`, `thread::sleep`, `park_timeout`, `Condvar::wait_timeout`,
`mpsc::recv_timeout`, untimed `recv` woken by a sleeping worker, `timerfd`+`poll`, `select` — all
exact.

Control without auxv hiding (`vt_run --no-hide-vdso --wall-limit 2 -- probe_target`):

```
outcome Hang  virtual 1.000000s  wall 2000.630ms
stats StopStats { stops: 160582, clock_reads: 0, sleeps: 1, futex_probes: 80289, ... }
```

Zero `clock_gettime` reach the kernel (all served by the vDSO), so `park_timeout(2s)` spins on real
time that barely moves while its futex timeout is virtual and expires instantly → watchdog `Hang`.
Hiding `AT_SYSINFO_EHDR` is what makes glibc fall back to the syscall.

## 2. Demo: `backoff_target` (std)

Bug: `sleep(min(backoff, remaining) + jitter)` overshoots the 120 s deadline, next iteration's
`deadline.checked_duration_since(now).expect(..)` panics (exit 101). Needs ≥ 120 s of program time.

### `curious()` with sancov coverage, release target (`backoff_sandbox --target target/sancov/release/backoff_target`)

```
found failure after 4 runs in 5.7ms wall (13 coverage features, 33 counter bytes):
  Exited(101) virtual=133.739s wall=1.53ms stops=44 jumps=3 non_natural=3 rng_bytes=40
minimised in 357.7ms: 300 variants, 65 reproduced; best rng bytes 52 cost CaseCost(120):
  Exited(101) virtual=120.888s wall=1.44ms stops=44 jumps=0 non_natural=0 rng_bytes=40
replays identical (event log hash): 100/100; same outcome + virtual time: 100/100 (1.49ms each)
```

Same with the debug-profile instrumented target (more inlining barriers ⇒ more counters):
`found failure after 4 runs in 5.8ms wall (162 coverage features, 316 counter bytes)`, same
minimised case, `100/100` replays.

### `NoCoverage` control (`backoff_sandbox --no-coverage --target target/release/backoff_target`)

```
found failure after 2 runs in 3.0ms wall:
  Exited(101) virtual=132.080s wall=1.65ms stops=43 jumps=2 non_natural=2 rng_bytes=40
minimised in 369.3ms: 300 variants, 75 reproduced; best rng bytes 52 cost CaseCost(121):
  Exited(101) virtual=121.652s wall=1.51ms stops=43 jumps=0 non_natural=0 rng_bytes=40
replays identical (event log hash): 100/100; same outcome + virtual time: 100/100 (1.50ms each)
```

The bug is shallow enough that coverage does not matter for discovery (both find it within 4
runs); the point of the sancov run is that coverage extraction from the sandboxed process works
end to end (`announce` syscall → `process_vm_readv` at `exit_group` → `ExecutionFeedback`).

Shrink quality: the discovered case used 2–3 non-natural (overshoot) jumps; `cautious()` removed
all of them (`jumps=0 non_natural=0`) and kept the 40 bytes of `getrandom` seed + 12 bytes of
per-run decisions (`rng bytes 52`). Cost = `jumps*1000 + non_natural*10000 + virtual_secs` = 120.

Failing run: **≥ 120 s virtual, 1.5 ms wall, 44 stops** (≈ 34 µs per stop including the target's
fork/exec/exit; see §5 for the per-clock-read cost).

## 3. Demo: `backoff_tokio_target` (tokio 1.53, real timers)

### `current_thread` (`backoff_sandbox --no-coverage --target target/release/backoff_tokio_target`)

```
found failure after 1 runs in 5.9ms wall:
  Exited(101) virtual=129.887s wall=5.91ms stops=423 jumps=8 non_natural=8 rng_bytes=56
minimised in 721.6ms: 300 variants, 42 reproduced; best rng bytes 68 cost CaseCost(120):
  Exited(101) virtual=120.991s wall=6.17ms stops=447 jumps=0 non_natural=0 rng_bytes=56
replays identical (event log hash): 100/100; same outcome + virtual time: 100/100 (6.20ms each)
```

tokio's timer driver reads `Instant::now()` (emulated), parks in `epoll_wait` with the next
timer's timeout (probed with timeout 0, parked, completed by the virtual deadline), and the
runtime's blocking `block_on` path uses `futex`. ~450 stops per run.

### `multi_thread` (`... backoff_tokio_target -- --multi`)

```
found failure after 1 runs in 6.3ms wall:
  Exited(101) virtual=129.887s wall=6.33ms stops=496 jumps=8 non_natural=8 rng_bytes=88
minimised in 1196.3ms: 300 variants, 90 reproduced; best rng bytes 100 cost CaseCost(120):
  Exited(101) virtual=120.708s wall=6.42ms stops=512 jumps=0 non_natural=0 rng_bytes=88
replays identical (event log hash): 0/100; same outcome + virtual time: 90/100 (6.28ms each)
```

Timers are virtual and the bug is found just as fast, but replays diverge. `diff` of two event
logs of the same case (`vt_run --events`):

```
<   t2 @500 probe nr=202 result=-11 block=false
<   t0 @500 getrandom 32
<   t2 @500 futex_wake 1
<   t2 @600 getrandom 16
<   t1 @800 futex_wake 1
---
>   t0 @500 getrandom 32
>   t2 @500 getrandom 16
>   t1 @900 futex_wake 1
```

Two runnable worker threads reach their next stop in kernel-scheduler order; because every clock
read adds the quantum, the interleaving changes the virtual timestamps of everything after it, and
in 10–21/100 replays the final virtual time differs (the panic still reproduced in 79–90/100 across
three fresh-clone runs). This is
the risk (1) of the memo and is left to the deterministic-scheduling spike; `current_thread`
programs and plain std programs whose threads only interact through supervised waits replay
exactly.

## 4. Coverage extraction

* `__sanitizer_cov_8bit_counters_init` (provided by the target-side `announce.rs`) issues
  `syscall(0x1337, start, end)`; the supervisor records the range (event `announce 316`).
* At `exit_group` / fatal signal the counters are copied with `process_vm_readv` (works on a
  ptrace-stopped tracee without extra privileges) and bucketed like `src/sancov.rs`
  (`0|1→0, 2→1, 3→2, 4..7→3, 8..15→4, 16..31→5, 32..127→6, else 7`), feature id
  `index << 8 | bucket`.
* Debug target: 316 counter bytes, 162 features hit; release target: 33 bytes, 13 features.
* `trace-compares` callbacks are no-ops in the target (no shared page yet) — the dictionary
  feedback is lost across the process boundary, as anticipated.

## 5. Overhead

```
$ ./target/release/probe_target bench 10000000          # native
bench: 10000000 reads ... 0.25 s wall                    → 25 ns per Instant::now()
$ ./target/release/vt_run --quiet -- target/release/probe_target bench 100000
outcome Exited(0)  virtual 0.010000s  wall 1099.439ms  stops: 100006, clock_reads: 100002
                                                         → 11.0 µs per emulated read (~440×)
$ ./target/release/vt_run --no-hide-vdso -- target/release/probe_target bench 100000
outcome Exited(0)  virtual 0.000000s  wall 3.724ms  clock_reads: 0    (vDSO, nothing trapped)
```

One emulated read = seccomp stop + `waitpid` + `PTRACE_GETREGS` + `process_vm_writev` +
`PTRACE_SETREGS` + `PTRACE_CONT` ≈ 11 µs, in line with the memo's 10.1 µs measurement. A sleep
costs one stop (deadline recorded, `nr=-1`, result written at the same stop); a futex/poll probe
costs two stops (entry rewrite + zero-timeout re-execution via `PTRACE_SYSCALL`) plus one restart
when it is completed by a wake/readiness.

Baseline per-run cost (fork + exec + auxv hide + exit): ~1.3 ms wall for a 44-stop release run.

## 6. Kernel/permission walls hit

None blocking. Verified unprivileged: `PTRACE_TRACEME` + seccomp `RET_TRACE` with
`PTRACE_O_TRACESECCOMP`, `PTRACE_EVENT_EXEC` auxv rewrite via `process_vm_writev`,
`pidfd_open`+`pidfd_getfd` on a ptrace-stopped tracee (needs `PTRACE_MODE_ATTACH_REALCREDS`, which
the tracer has), `timerfd` mirrors, `process_vm_readv` of sancov counters. `unprivileged_userfaultfd=0`
is irrelevant to this spike. Threads blocked in unsupervised syscalls are only caught by the
wall-clock watchdog (test `hang_in_unsupervised_syscall_is_reported_by_the_watchdog`).

## 7. Regression

* Root crate (`cd ../.. && cargo test && cargo clippy --all-targets`): 54 tests pass; clippy reports
  no errors (the two `isolate_lowest_one` / `for` loop warnings are pre-existing on the base branch;
  no root files changed).
* `spikes/virtual-time`: `cargo test` — 4 unit tests (clock conversions, seccomp filter shape) +
  5 end-to-end tests (std probe under sandbox, vDSO control, backoff failure + 100 identical
  replays, tokio current_thread + 20 identical replays, watchdog on an unsupervised block) pass in
  ~0.7 s running in parallel; `cargo clippy --all-targets` clean.
