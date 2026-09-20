# `virtual-time` — a deterministic virtual clock for sandboxed fuzz targets

Prototype for the [design memo](DESIGN.md): the target runs **unmodified** under a
ptrace + seccomp supervisor that owns the clock. Every time-related syscall is answered by the
harness from a virtual timeline that only advances when every thread of the target is blocked
(or when the fuzzer decides to jump). A retry/backoff bug that needs two minutes of wall-clock
time is found in ~1.5 ms of wall time, minimised with `cautious()`, and replays bit-for-bit.

Standalone crate (`[workspace]` table, depends on the root crate as `iterator-fuzz`); the root
`Cargo.toml` and `src/` are untouched. Linux x86-64 only.

## How it works (as built)

* **Spawn.** `Sandbox::run` forks; the child calls `PTRACE_TRACEME`, installs a classic-BPF seccomp
  filter (`seccomp.rs`) that returns `SECCOMP_RET_TRACE` for the time syscalls only
  (`clock_gettime`, `gettimeofday`, `time`, `nanosleep`, `clock_nanosleep`, `futex`, `epoll_wait`
  family, `poll`/`ppoll`, `select`/`pselect6`, `timerfd_settime`/`gettime`, `getrandom`, plus a
  reserved "announce" syscall `0x1337`) and `SECCOMP_RET_ALLOW` for everything else, then execs.
* **vDSO.** At the exec stop the supervisor walks the tracee's initial stack and rewrites
  `AT_SYSINFO_EHDR` to `AT_IGNORE` (`ptrace::hide_vdso_in_auxv`). glibc then issues real
  `clock_gettime` syscalls, which the filter traps. `vt_run --no-hide-vdso` shows the control:
  zero clock reads reach the supervisor and the target hangs (real time never moves while virtual
  sleeps complete instantly).
* **Clock reads** are answered at the single seccomp stop (`orig_rax = -1`, result written into
  the tracee's `timespec`/`timeval`/`time_t`) from `clock.rs`: monotonic = `1e6 s + vnow`,
  realtime = `2026-01-01 + vnow (+ optional step)`. Each read adds a small quantum
  (`variant(4)` per run: 100 ns / 1 µs / 10 µs / 0) so spin loops terminate.
* **Waits.** Sleeps become virtual deadlines and the thread is parked. `futex WAIT/WAIT_BITSET`,
  `epoll_wait`, `poll`, `select` are re-issued with a **zero timeout** (the kernel keeps doing the
  atomic compare / readiness check); on "would block" the thread is parked with the translated
  deadline. Parked threads resume on `FUTEX_WAKE` to the same address, on thread exit
  (`CLONE_CHILD_CLEARTID` joins), on readiness of the watched fds — mirrored into the supervisor
  with `pidfd_getfd` and polled there — or when the virtual clock reaches their deadline.
  A resumed wait is restarted (`rip -= 2`, registers restored) so the kernel performs the real
  operation; timed-out waits get `ETIMEDOUT`/`0` written directly.
* **timerfd.** `timerfd_settime` is recorded as a virtual timer and the tracee's timer is left
  disarmed; when virtual time reaches the deadline the supervisor arms a 1 ns timer on its
  `pidfd_getfd` mirror of the same file, so the target's `read`/`poll`/`epoll` see one expiration.
  `timerfd_gettime` is answered from the virtual queue.
* **Quiescence.** When every thread is parked the supervisor draws a jump from the harness
  `CaseRng`: `range(0..=MAX_JUMPS)` of items with `variant(4)` kind (0 = advance to the earliest
  deadline, 1 = to the latest, 2/3 = overshoot the earliest/latest by a `variant(6)` magnitude
  bucket). Once the range is exhausted the clock advances naturally, so `cautious()` shrinks toward
  "natural" schedules. Nothing parked and nothing ready ⇒ `Outcome::Deadlock`; a wall-clock
  watchdog turns a thread stuck in an unsupervised syscall into `Outcome::Hang`.
* **Entropy.** `getrandom` is filled from `rng.fill_bytes` so the target's `rand::rng()` seed is a
  recorded, shrinkable fuzzer input.
* **Coverage.** A sancov-instrumented target announces its 8-bit counter range via the reserved
  syscall (`src/bin/announce.rs` supplies `__sanitizer_cov_8bit_counters_init`); at
  `exit_group`/fatal signal the supervisor copies the counters via `process_vm_readv`, buckets them
  like `src/sancov.rs`, and `SandboxCoverage: CoverageCapture` turns them into
  `ExecutionFeedback` for `curious()`.

## Build and run (fresh clone)

```sh
git clone https://github.com/DioxusLabs/dowsing.git
cd dowsing
git checkout devin/spike/virtual-time
cd spikes/virtual-time

cargo build --release

# sancov-instrumented copy of the std target (for coverage-guided discovery)
cargo rustc --release --bin backoff_target --target-dir target/sancov -- \
  -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares

# 1. std::time probe: sleep, park_timeout, Condvar, recv_timeout, cross-thread wakeups,
#    SystemTime, timerfd+poll, select, Instant spin — all must report the requested virtual time
./target/release/vt_run -- target/release/probe_target
./target/release/vt_run --no-hide-vdso --wall-limit 2 -- target/release/probe_target   # control: Hang

# 2. the demo: curious() discovery -> cautious() minimisation -> 100 replays
./target/release/backoff_sandbox --target target/sancov/release/backoff_target       # sancov coverage
./target/release/backoff_sandbox --no-coverage --target target/release/backoff_target # NoCoverage control
./target/release/backoff_sandbox --no-coverage --target target/release/backoff_tokio_target            # tokio current_thread
./target/release/backoff_sandbox --no-coverage --target target/release/backoff_tokio_target -- --multi # tokio multi_thread (nondeterministic, exit 2)

# 3. one run with the event log, e.g. the tokio target with random jumps
./target/release/vt_run --events --fuzz --quiet -- target/release/backoff_tokio_target

# 4. per-stop overhead: 100k Instant::now() reads under the sandbox vs native
./target/release/vt_run --quiet -- target/release/probe_target bench 100000
./target/release/probe_target bench 10000000

# tests (unit + end-to-end against the built binaries) and lints
cargo test
cargo clippy --all-targets
```

`backoff_sandbox` exits 0 when all replays match the minimised case's event-log hash, 2 otherwise.
Options: `--runs N` (discovery budget, default 2000), `--shrink N` (300), `--replays N` (100),
`--max-jumps N` (8), `--show-target` (target stdout/stderr during discovery).

## Measured (this box: Ubuntu, kernel 6.8, Rust 1.98, ptrace_scope=1, unprivileged)

Full numbers and raw output are in [RESULTS.md](RESULTS.md).

| | std `backoff_target` | tokio `current_thread` | tokio `multi_thread` |
| --- | --- | --- | --- |
| runs / wall to first failure (`curious()`, sancov) | 4 runs / 5.7 ms | — | — |
| runs / wall to first failure (`NoCoverage`) | 2 runs / 3.0 ms | 1 run / 5.9 ms | 1 run / 6.3 ms |
| failing run: virtual / wall | 120.9 s / 1.5 ms | 121.0 s / 6.2 ms | 120.7 s / 6.4 ms |
| stops per failing run | 44 | 447 | ~510 |
| `cautious()` 300 variants: reproduced / time | 65 / 358 ms | 42 / 722 ms | 90 / 1196 ms |
| minimised case | 40 rng bytes, 0 jumps, cost 120 | 56 bytes, 0 jumps, cost 120 | 88 bytes, 0 jumps, cost 120 |
| 100 replays identical (event-log hash) | **100/100** | **100/100** | 0/100 (90/100 same outcome+virtual time) |

* `probe_target` (single run): 23.501 s virtual in 111 ms wall, 10 077 stops (10 030 of them the
  1 ms `Instant::now()` spin at a 100 ns quantum), every std API exact to the nanosecond.
* Clock read cost: 100 000 sandboxed `Instant::now()` in 1.10 s ⇒ **~11 µs per read**
  (seccomp stop + `GETREGS` + `write_mem` + `SETREGS` + `CONT`) vs 25 ns native vDSO (~440×).
* Root crate untouched: `cargo test` 54 passed, `cargo clippy --all-targets` no errors (two
  pre-existing warnings); this crate: 9 tests pass, clippy clean.

## What works

* Rust `std`: `Instant`, `SystemTime`, `thread::sleep`, `thread::park_timeout`,
  `Condvar::wait_timeout`, `mpsc::recv_timeout`, untimed `recv`/`join` woken by another thread's
  virtual sleep, busy-wait on `Instant::now()` (quantum), `rand::rng()` seeded from the fuzzer.
* libc: `timerfd_create/settime/gettime` + `poll`/`read`, `select` with timeout, `poll` timeout,
  `nanosleep`/`clock_nanosleep` (relative and `TIMER_ABSTIME`), `futex` timed and untimed waits,
  `getrandom`.
* tokio 1.53 `current_thread`: `tokio::time::sleep`, `tokio::time::timeout`, `Instant` — exact
  virtual durations, deterministic replay (epoll_wait probe + parking; the driver's `Instant` reads
  come through the emulated clock).
* tokio `multi_thread`: timers are virtual and the bug is found (120.7 s virtual in 6.4 ms), but
  replays are not bit-identical — see below.
* Coverage-guided `curious()` over the sandboxed process via sancov counters read from tracee
  memory (162 features on the debug build, 13 on release), `cautious()` shrinking to natural
  schedules with `discard()` for non-reproducing variants, `Outcome::Hang` and `Outcome::Deadlock`.
* Several `Sandbox`es on different threads of one harness process (`waitpid(..., __WNOTHREAD)`);
  the test suite runs them in parallel.

## What does not (yet)

* **Multi-thread replay.** The virtual clock is exact but *which* runnable thread hits the next
  stop first is still decided by the kernel scheduler: two tokio workers interleave their clock
  reads (each read advances `vnow` by the quantum) and `FUTEX_WAKE`s differently, so the event log
  hash differs in 100/100 replays and 10 % of replays even get a different final virtual time. The
  outcome (panic) reproduced in 90/100. Fixing this is the deterministic-scheduling spike
  (resume exactly one runnable thread at a time).
* **Unsupervised blocking syscalls** (`read` on a fifo/socket, `accept`, `waitpid`, `open` of a
  FIFO) are invisible to quiescence detection: the wall-clock watchdog reports `Hang` after
  `wall_limit`. Networking/files are the next spike.
* **Performance path.** ~11 µs per clock read is fine for these targets but the designed
  shared-page vDSO patch (`clock_gettime` answered from a page the supervisor writes) was not
  built; `--no-hide-vdso` is only useful as the control.
* Not emulated: `setitimer`/`alarm`/`timer_create` POSIX timers, `CLOCK_PROCESS_CPUTIME_ID`
  (passed through natively), `epoll_pwait2`/`ppoll` signal masks (ignored), `EINTR` delivery to
  interrupted sleeps. `timerfd` interval timers re-arm virtually but each expiry reports a count
  of 1 (skipped periods are not accumulated) and only one-shot timers were tested.
* `fork()`-based snapshotting, x86-32/aarch64, non-Linux.

## Deviations from DESIGN.md

* Standalone crate under `spikes/virtual-time` with binaries instead of a `sandbox` feature +
  examples in the root crate (required by the spike rules); flat `src/*.rs` instead of
  `src/sandbox/*`; `tokio` is a normal dependency of the demo binary rather than a dev-dependency.
* The sancov announce hook lives in the target binaries (`src/bin/announce.rs`) instead of
  `src/sancov.rs`, so the root crate is unmodified.
* Counters are read with `process_vm_readv` rather than `/proc/pid/mem` (same permission model,
  fewer syscalls); zero-timeout `timespec`s are written 512 bytes below the tracee's `rsp` (past the red zone;
  the memo's "scratch below rsp" hack), no scratch page is injected.
* The minimised failing case has **zero** non-natural jumps: the target's own `clamp + jitter`
  sleep overshoots the deadline, so `cautious()` correctly shrinks the schedule to the natural one
  and the bug is a pure "let the clock run" reproduction. Overshoot jumps still exist and are
  used during discovery (3 of 4 discovery runs used them).
* `timerfd` (stretch goal) is implemented; the shared-page vDSO fast path is not.

## Next steps

1. Deterministic thread scheduling: at every stop resume exactly one runnable thread chosen from
   the `CaseRng` (the supervisor already has the per-thread state table), making the multi-thread
   event log replayable.
2. Network/file syscalls through the same filter (`SECCOMP_RET_TRACE` on `read`/`write`/`accept`/
   `connect`/`recvfrom`…) so blocked I/O becomes a parked wait with fuzzer-provided data.
3. Shared clock page: inject an `mmap` into the tracee at the exec stop and patch
   `__vdso_clock_gettime` to read it, dropping the per-read stop.
4. `fork()`-without-exec snapshots of a parked state (needs 3, since there is no exec stop).
5. Move `Sandbox`/`SandboxCoverage` into the root crate behind a `sandbox` feature once the API
   settles.
