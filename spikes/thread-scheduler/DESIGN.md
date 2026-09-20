# Spike: deterministic, fuzzer-controlled thread scheduling

Status: prototype built and measured; see [README.md](README.md) for the
commands and the full numbers, and ["Prototype results"](#prototype-results-what-was-built-and-what-deviated)
below for what deviated from this memo.
Scope: Linux x86_64, single machine, no KVM, no CRIU, unprivileged user.

## TL;DR

Recommendation: **ptrace as the control plane, seccomp `RET_TRACE` to pick the
syscalls that stop, futex emulated in the supervisor, and the target's own
SanitizerCoverage `trace-pc-guard` callback used as a deterministic
preemption budget.** The supervisor is the dowsing harness process; the target
is a child process. Every scheduling decision is a `CaseRng::variant` and
every preemption budget is a `CaseRng::variant` too, so `curious()` explores
interleavings and `cautious()` shrinks them with no new shrinking machinery.

Two findings drove this, both measured on this box:

1. **Syscall-only scheduling points are not enough for Rust.** Rust's
   `Mutex`/`RwLock`/`Once`/`Arc` fast paths are lock-free CAS loops; an
   uncontended `lock()`/`unlock()` makes *no* syscall. A program doing 4000
   `lock()`/`unlock()` pairs across two threads with a real lost-update bug
   issued exactly one `futex` syscall in total (the `join`). A scheduler that
   only switches at syscalls can never expose that bug. We need a preemption
   point that is (a) cheap, (b) deterministic, (c) available unprivileged
   under a hypervisor. Hardware counters fail (c) here
   (`perf_event_paranoid=4`, `perf stat` denied), single-step fails (a)
   (13 µs/instruction). The sancov edge callback satisfies all three: ~1.3 ns
   per edge, exact, and already required for dowsing's parallel coverage path.

2. **ptrace and seccomp-unotify cost the same per stop (~9–10 µs)**, so the
   choice is about control, not speed. Only ptrace can (i) hold a freshly
   cloned thread before it executes a single user instruction
   (`PTRACE_O_TRACECLONE`), (ii) stop a thread that is not in a syscall,
   (iii) see and rewrite syscall return values. Seccomp-unotify can do none of
   these; it cannot enforce "one thread at a time" across `clone3`.

Everything below is either **[measured]** on this machine (kernel
`6.8.0-1061-aws`, rustc 1.98.1, glibc 2.35, 8 vCPU Xeon 8375C under a
hypervisor, `ptrace_scope=1`, `unprivileged_userfaultfd=0`,
`perf_event_paranoid=4`, no `criu`) or marked **[inference]** /
**[recollection]** when it is a design claim or prior-art memory I did not
re-verify.

## Measurements

Throwaway sources live outside the repo (`~/exp/*.c`, `~/exp/*/src/main.rs`);
they are a few dozen lines each and are not part of the deliverable. Numbers
are medians of a single run of 200k iterations unless noted.

### Interception mechanisms

| Mechanism | Cost | Notes |
|---|---|---|
| plain allowed syscall (`getpid`) | 0.13 µs | baseline |
| seccomp user-notif round trip (`getppid` trapped, `SECCOMP_IOCTL_NOTIF_RECV`/`SEND`) | 9.0 µs | works **unprivileged** with `PR_SET_NO_NEW_PRIVS`; filter inherited by `clone3` children; `user_notif` listed in `/proc/sys/kernel/seccomp/actions_avail` |
| `PTRACE_SYSCALL` (entry + exit stop per syscall) | 17.2 µs | two stops |
| seccomp `RET_TRACE` + `PTRACE_CONT` (one stop, `GETREGS`/`SETREGS`, syscall skipped) | 10.2 µs | only the filtered syscalls stop |
| seccomp `RET_TRACE` stop → skip (`orig_rax = -1`) → `PTRACE_SYSCALL` → exit-stop → inject `rax` | 1 extra stop (~+8 µs) | **[measured]** the exit stop arrives with `rax = -ENOSYS`; injected `4242` and `-EAGAIN` were observed by the tracee |
| `PTRACE_SEIZE` + `PTRACE_INTERRUPT` + resume (asynchronous preemption) | 8.7 µs | needs an external trigger to be useful |
| `PTRACE_SINGLESTEP` | 13.0 µs/instruction | 1 M instructions ≈ 13 s |
| hardware watchpoint via `PTRACE_POKEUSER u_debugreg[0..7]` | fires (3/3 writes trapped, `dr6=0xffff0ff1`) | debug registers work under this hypervisor |
| `fork()` + child touch one page + `_exit` + `wait` at RSS 10 / 100 / 500 MB | 0.30 / 1.58 / 6.21 ms | relevant to a forkserver, not to scheduling |

Rust specifics (rustc 1.98.1 stable):

| Fact | Evidence |
|---|---|
| `std::thread::spawn` → `clone3(CLONE_VM\|CLONE_THREAD\|CLONE_CHILD_CLEARTID\|…)`; new thread runs `set_robust_list` and `rseq` before user code; `join` → `futex(FUTEX_WAIT_BITSET_PRIVATE)` on the child's TID word; `Condvar::wait` → `FUTEX_WAIT_BITSET_PRIVATE`; `notify_one` → `FUTEX_WAKE_PRIVATE`; `yield_now` → `sched_yield`; `sleep` → `clock_nanosleep(CLOCK_MONOTONIC)`; thread end → `exit` | `strace -f` of a plain std program |
| Uncontended `Mutex::lock`/`unlock`: **zero** syscalls (4000 pairs → 1 `futex`, the join) | `strace -f -c` of `~/exp/uncont` |
| The same program's lost update (`let v = *m.lock(); *m.lock() = v + 1;` on two threads) never manifests natively: 20/20 runs printed `count=2000`. Thread start-up latency hides the race. | native runs |
| `-Cpasses=sancov-module` with `-inline-8bit-counters` **and** `-trace-pc-guard` together instruments every edge with both (`367` guards, `367` counters, each block starts `call __sanitizer_cov_trace_pc_guard; incb counter(%rip)`) | `objdump -d` |
| `-sanitizer-coverage-trace-loads/-stores` are accepted by rustc 1.98's LLVM and instrument plain **and atomic loads/stores** (`AtomicU32::load` is preceded by `__sanitizer_cov_load4`), but **not** lock-prefixed RMW (`lock incl` from `fetch_add` has no callback). 595 load callbacks in a ~100-line program. | `objdump -d` |
| A `trace_pc_guard` callback that decrements a `thread_local!` budget and branches costs ~1.3 ns/edge (`50 M` iterations of a 2-edge loop: 1.30 ns/iter → 3.7 ns/iter; ~2.9× on a branch-dense microbenchmark, far less on real code) | `~/exp/budget` |
| Only the crate compiled with the sancov flags is instrumented; precompiled `std` is not. Inlined std fast paths (the `Mutex` CAS loop) *are* instrumented because they are monomorphised/inlined into the user crate. | `objdump -d` |

## Goal restated as invariants

At every instant at most one target thread is runnable in the kernel sense
(all others are ptrace-stopped or emulated-blocked). The supervisor only
makes progress at **scheduling points**:

* S1: the running thread enters one of the scheduling syscalls
  (`futex`, `clone`/`clone3`, `sched_yield`, `nanosleep`/`clock_nanosleep`,
  `epoll_wait`/`epoll_pwait(2)`/`poll`/`ppoll`/`select`, `exit`,
  `exit_group`, plus `getrandom` for determinism — see below).
* S2: the running thread exhausts its **edge budget** and calls the
  yield marker syscall from the `trace_pc_guard` callback.
* S3: the running thread dies (`PTRACE_EVENT_EXIT`) or a new thread is born
  (`PTRACE_EVENT_CLONE`; the child is auto-attached and starts stopped).
* S4: the running thread receives a signal (`SIGSEGV` etc.) → crash outcome.

At each point the supervisor computes the runnable set `R` (created, not
exited, not emulated-blocked) and asks the `CaseRng`:

```rust
// index 0 == "keep running the current thread if it is still runnable,
//            else the lowest-index runnable thread"
let pick = rng.variant(R.len());
let budget = BUDGET_TABLE[rng.variant(BUDGET_TABLE.len())]; // index 0 == no preemption
```

If `R` is empty and at least one thread is emulated-blocked, that is a
**deadlock**: report it, dump per-thread state (blocked futex address, the
Rust-level construct if we can map it, the last syscall), and finish.

### Why `variant` and why index 0 means "don't switch"

`cautious()` runs with `zero_tail: true` (`src/iter/run.rs`), i.e. every draw
beyond the recorded prefix reads zero. The `Variant` semantic pass in
`src/iter/shrink.rs` tries to zero or reduce each variant byte. If index 0 is
"continue the current thread, no preemption budget", then:

* a zeroed schedule is *run to completion in creation order* — the most
  sequential, most readable interleaving;
* every non-zero variant in the minimized case is a context switch or a
  preemption that is **necessary** for the failure; the "minimized schedule
  length" the success criterion asks for is literally the count of non-zero
  variant spans;
* `Length`/`Item` deletion passes can drop whole scheduling decisions when the
  decision list is wrapped in `rng.range(..)` (see "encoding" below), and
  removing decisions towards the tail is always safe because the tail becomes
  zeros anyway.

This is the same "shortlex, zero is simplest" ordering Hypothesis uses for its
choice sequence **[recollection]**; dowsing already implements it.

## Architecture

```
harness process (dowsing, CaseRng, CoverageCapture)  ──ptrace──►  target process
  ├─ Scheduler { threads: Vec<Thread>, waiters: FutexTable }        ├─ sancov trace-pc-guard  → shm bitmap  (coverage)
  ├─ CoverageCapture impl reads shm bitmap                          ├─ trace-pc-guard callback → edge budget → yield marker syscall
  └─ per-case: spawn target, drive until exit/deadlock/crash        └─ seccomp filter: RET_TRACE on scheduling syscalls, ALLOW rest
```

Components (names are proposals for the prototype, not commitments):

* `dowsing-sched` (supervisor library, in-tree under `src/sched/` or a
  workspace crate): `fork`s, the child installs the seccomp filter and
  `raise(SIGSTOP)`s, the parent `PTRACE_SEIZE`s it (no `PTRACE_TRACEME`, so
  `PTRACE_INTERRUPT`/`PTRACE_LISTEN` are available later), sets
  `PTRACE_O_TRACECLONE | TRACEEXIT | TRACESECCOMP | TRACESYSGOOD | EXITKILL`,
  and the child disables ASLR (`personality(ADDR_NO_RANDOMIZE)`) before
  `execve`; then the parent runs the scheduling loop above. One supervisor thread per target process (ptrace requires all
  requests from the tracer thread).
* `dowsing-target-rt` (tiny runtime linked into the target binary): defines
  `__sanitizer_cov_trace_pc_guard{,_init}` (sets bits in a `MAP_SHARED`
  bitmap inherited via an fd, exactly the AFL forkserver layout **[recollection]**)
  and keeps the `thread_local!` edge budget. When the budget hits zero it
  executes the **yield marker**: `syscall(SYS_sched_yield /* or a dedicated nr */)`
  and stores the return value as the next budget. No other code in the
  target changes; `std::thread`, `Mutex`, `Condvar`, atomics are the real
  ones.
* Futex emulation in the supervisor. On `FUTEX_WAIT{,_BITSET}` the
  supervisor reads `*uaddr` with `process_vm_readv` (or `PEEKDATA`); the
  world is quiescent so the read is race-free. If `*uaddr != val` → skip the
  syscall, inject `-EAGAIN`. Else record `(tid, uaddr, bitset, timeout?)`,
  skip the syscall, leave the thread stopped as **blocked**. On
  `FUTEX_WAKE{,_BITSET}` → skip, pick up to `nr_wake` matching waiters, inject
  `0` into each (they become runnable, still stopped), inject the count into
  the waker. Wake order is FIFO by default; making it a `variant` is a cheap
  follow-up. `FUTEX_WAIT` with a timeout: the timeout is a *fuzzer choice*
  (`variant(2)` at each subsequent scheduling point: keep waiting / return
  `-ETIMEDOUT`), never wall-clock. Unknown futex ops (`REQUEUE`, `WAKE_OP`,
  PI) pass through to the kernel and are logged as "uncontrolled" so we notice.
* `clone3`: let the kernel do it (we need the real thread). The
  `PTRACE_EVENT_CLONE` stop gives us the new tid; the child starts in a
  ptrace stop before its first instruction, so "one at a time" holds through
  thread creation. Record the `child_tid`/`CLEARTID` address from
  `clone_args` so that on the child's `PTRACE_EVENT_EXIT` we wake emulated
  joiners waiting on it (the kernel will also clear the word; harmless).
* `sched_yield`, `nanosleep`, `clock_nanosleep`: skip the syscall, inject
  `0`, treat as a plain scheduling point (sleep duration is irrelevant under
  a logical clock; `Instant::now` is a vDSO read and is not intercepted in
  this spike — see risks).
* `epoll_wait`/`poll`/`select` **without** fds of interest (timeout-only)
  behave like sleep. With real fds this spike lets them through to the
  kernel as ordinary stops (the network/file interception belongs to the
  sandbox spike); they are still scheduling points.
* `exit`/`exit_group`: `PTRACE_EVENT_EXIT` handles thread death; the
  process-wide exit ends the case.
* `getrandom`: skip and fill from the `CaseRng` (the current decision's
  `ChildRng` implements `RngCore`, so `item.fill_bytes(..)` records the bytes
  inside that decision's `Item` span), so `HashMap` seeds are part of the case. Cheap and removes the last common
  source of non-schedule nondeterminism in std.

### Encoding scheduling decisions in the `CaseRng`

```rust
// in the supervisor, once per case
let mut decisions = rng.range(0..MAX_DECISIONS);        // Length span: how many "interesting" decisions
loop {
    let point = scheduler.run_until_scheduling_point()?; // resumes exactly one thread
    let Some(mut item) = decisions.next() else { break }; // Item span per decision; deletable by cautious()
    let runnable = scheduler.runnable();
    let pick   = item.variant(runnable.len());            // 0 => stay / lowest index
    let budget = item.variant(BUDGET_TABLE.len());        // 0 => run until next syscall
    scheduler.resume(runnable[pick], BUDGET_TABLE[budget]);
}
// after the range is exhausted, schedule deterministically (index 0 everywhere)
```

Rationale: the `range` gives the `Length` pass (weight 0, cheapest) a handle
to truncate the schedule and the `Item` pass (weight 8) a handle to delete a
single decision, while `Variant` (weight 16) simplifies the survivors. All
three exist today in `src/iter/shrink.rs`; nothing new is needed. The
`BUDGET_TABLE` is geometric (`[∞, 1, 2, 4, 8, 16, 32, 64, 128, 256, 1k, 4k, 16k]`
edges) so a single variant byte spans "preempt immediately" to "let it run
a while"; in `curious()` the distribution is uniform over the table, which is
roughly log-uniform in edges — the same intuition as PCT's random change
points **[recollection]**, without needing PCT's priority bookkeeping.
Deterministic replay does not depend on the table being clever; only the
exploration efficiency does.

Determinism argument: given the same bytes, the same thread is chosen at
each point, the same budgets are handed out, and the edge count of a thread
between two scheduling points is a pure function of its instruction stream
and the memory it observes — which is the same because all other threads are
stopped. Therefore the interleaving is a pure function of (binary, input
bytes). The two known leaks are wall-clock reads (`Instant::now`, vDSO) and
uninstrumented code that observes shared memory (std internals not inlined
into the user crate) — both discussed under risks; neither affects the demo.

### Integration with `curious()` / `cautious()` / `CoverageCapture`

* `CoverageCapture`: new `ShmSancovCoverage` (parallel-safe by construction:
  one bitmap per target process) — `start_capture` clears the target's
  bitmap region, `finish_capture` folds set bits into a `CoverageSet` +
  hit-count weight into `ExecutionFeedback`. Comparison operands
  (`trace-compares`) can be forwarded through the same shm ring later; for
  the spike, edge bits are enough. This lets `curious()`'s search prefer
  schedules that reach new code, including code only reachable under a
  specific interleaving (the lost-update branch, the deadlock's second
  `lock()`), which is the whole reason to do this inside dowsing rather than
  with a standalone PCT tool.
* `curious()` loop: `for mut rng in curious().with_coverage(shm).take(N)`;
  per case spawn target, run scheduler, `rng.coverage()`; on
  `Outcome::{Deadlock, LostUpdate, Crash}` call `rng.fork_case()` to seed
  `cautious()`.
* `cautious()` loop: `cautious().with_coverage(shm).with_case(case)`; replay,
  `rng.coverage_with_cost(cost)` where `cost = non_zero_decisions +
  total_edges_run / 1024` (fewer switches first, then shorter runs);
  `rng.discard()` when the outcome differs from the original, so
  non-reproducing variants do not pollute the corpus. Because a shrunk
  schedule that no longer fails is discarded rather than accepted, the
  minimized case is guaranteed to reproduce the same outcome class.
* Replay: `Case` serialised via the existing prefix bytes + spans; running
  the same `Case` twice must produce an identical **schedule trace**
  (sequence of `(thread_index, point_kind, edges_run)`) — the demo hashes it
  and asserts equality. That is the "byte-for-byte" check.
* Scheduling-decision overhead is reported by the demo as (a) stops/case and
  µs/stop from the supervisor's `waitpid` loop, (b) wall time of a case
  under the scheduler vs. native, (c) edge-callback overhead of the target
  binary vs. an uninstrumented build.

## Alternatives considered and rejected

### seccomp user-notification alone

Works unprivileged, same cost as ptrace (9.0 µs vs 10.2 µs), inherited by
threads, and the futex emulation prototype (hold the notification, respond
later) worked **[measured]**. Rejected as the primary control plane because
it cannot enforce the core invariant:

* After `SECCOMP_USER_NOTIF_FLAG_CONTINUE` on `clone3`, **both** parent and
  child run freely until each hits its next filtered syscall; there is no
  per-thread stop primitive without ptrace (`SIGSTOP` stops the whole group).
  The child's first syscalls (`set_robust_list`, `rseq`) come from glibc
  start-up, so the window is small but real, and the parent's return path is
  entirely uncontrolled (the parent's next syscall might be seconds away).
* It cannot stop a thread at a non-syscall point, so the edge budget would
  have to *be* a syscall anyway — at which point we are paying for a syscall
  stop and still lacking register access. (Return-value injection via
  `resp.val` does work, so the budget hand-off would be possible.)
* No view of syscall results after `CONTINUE`; we would have to infer `clone3`
  success from `/proc/<pid>/task`.
* No signal/crash interception: a `SIGSEGV` in the target is not visible to
  the supervisor except as process death.

Keep in mind as the *fast path* for the sandbox spike (fd injection via
`SECCOMP_IOCTL_NOTIF_ADDFD` is something ptrace cannot do), possibly combined
with ptrace for scheduling. Combining both on the same thread is legal (the
filter runs before the ptrace seccomp stop) but doubles the stop cost for
syscalls that are both scheduling points and sandboxed; decide per syscall.

### `LD_PRELOAD` pthread interposition

Rejected. Rust's `std::sync` on Linux issues `futex` via raw `syscall`
instructions (verified in `strace`; there is no `pthread_mutex_lock` to
interpose), `parking_lot` likewise; only `pthread_create`/`pthread_join`
would be visible. Static-PIE and musl targets have no `LD_PRELOAD` at all.
It would also require the target to be dynamically linked against a
dowsing-specific shim, which is the kind of mock the vision rules out. The
one legitimate use — a start-up hook in every new thread — is unnecessary
because `PTRACE_O_TRACECLONE` already delivers the thread stopped at birth.

### Pure in-process schedulers (Shuttle / Loom style)

Shuttle (random + PCT scheduling, compact schedule replay) and Loom (DPOR,
bounded preemption) both work by **replacing** `std::sync` and `std::thread`
with their own types compiled into the test **[recollection]**. They cannot
schedule code that uses real std, so they fail the "no mocks" requirement.
Their *search strategies* (PCT, bounded preemptions, DPOR-ish "did this
switch matter") are the right reference for improving `curious()` later,
and Shuttle's observation that most concurrency bugs need few preemptions
(depth ≤ 3) is what makes "index 0 = don't switch" a good zero for
shrinking.

### rr chaos mode as-is

rr is the closest existing system: ptrace + seccomp `RET_TRACE`, one tracee
thread at a time, syscall buffering via an injected library, and *chaos mode*
randomises priorities and time-slices **[recollection]**. Its preemption is
built on a hardware performance counter (retired conditional branches) which
is unavailable here (`perf_event_paranoid=4`, hypervisor PMU not exposed to
unprivileged users) **[measured: `perf stat` denied]**. rr also records the
whole execution for later replay; we want the opposite — a schedule that is a
pure function of a byte string, replayable without a trace. The design
borrows rr's control plane and swaps the tick source for the sancov edge
counter, which is deterministic by construction and needs no privilege.

### gVisor systrap, Nyx/kAFL, Antithesis

* gVisor's systrap replaced its ptrace platform because ptrace stops cost
  ~10 µs; systrap uses seccomp `RET_TRAP` + a `SIGSYS` handler in a stub
  thread + shared-memory hand-off to the sentry, an order of magnitude
  cheaper **[recollection]**. That is the right *long-term* direction for
  syscall-heavy targets and for the sandbox spike, but it requires code in
  the target's address space handling every trapped syscall — which we would
  have to write and which cannot stop threads that make no syscalls. Not
  needed for the scheduling problem at the ~10 µs/point we measured.
* Nyx/kAFL: KVM-based full-VM snapshots + Intel PT. Out of scope by the
  "no KVM" constraint; also PT is unavailable under this hypervisor.
* Antithesis: deterministic hypervisor for whole systems; proprietary and
  again a hypervisor. Its lesson we do keep: the *only* nondeterminism
  sources should be the fuzzer's choices, so time and entropy must be
  intercepted (`getrandom`, later `clock_gettime`/vDSO).

### Non-syscall preemption options

| Option | Verdict |
|---|---|
| Hardware perf counter (rr-style ticks) | **Not worth pursuing now.** Unavailable unprivileged here (`perf_event_paranoid=4`), typically imprecise/non-deterministic under hypervisors **[recollection]**, needs `CAP_PERFMON` on CI machines. |
| `PTRACE_SINGLESTEP` budgets | **Not worth it for exploration**: 13 µs/instruction. Keep as a *microscope*: once a minimized case is found, single-step the ≤ few-thousand-instruction window around a preemption to report the exact instruction pair that raced. |
| Timer-based `PTRACE_INTERRUPT` | Rejected: not reproducible from bytes. |
| Hardware watchpoints (`DR0–DR3`) | **Works here [measured]**, 4 per thread, deterministic. Not needed for the demo; valuable later for a "watch this address" mode targeted from `trace-loads/stores` data or for catching races inside uninstrumented std code. |
| `trace-loads`/`trace-stores` callbacks as preemption points | Works for plain and atomic loads/stores (not RMW). ~5× more callbacks than edges. Optional *second budget* for a "memory-access granularity" mode; the demo uses edges only. |
| **sancov edge budget** | **Chosen.** ~1.3 ns/edge, deterministic, unprivileged, zero extra flags for the parallel coverage build. |

## Demo target and what "success" will look like

`examples/sched_lost_update.rs` (target, plain std, no dowsing dependency
except the tiny target runtime):

```rust
// two threads, real std::sync::Mutex, a real check-then-act bug
let counter = Arc::new(Mutex::new(0u64));
let t = thread::spawn({ let c = counter.clone(); move || for _ in 0..N { let v = *c.lock().unwrap(); *c.lock().unwrap() = v + 1; } });
for _ in 0..N { let v = *counter.lock().unwrap(); *counter.lock().unwrap() = v + 1; }
t.join().unwrap();
assert_eq!(*counter.lock().unwrap(), 2 * N); // fails => process exit code != 0 => Outcome::LostUpdate
```

Natively this never fails (20/20) and makes one `futex` syscall; under the
scheduler it needs exactly one non-zero decision: preempt the main thread a
few edges after `clone3` returns, run the child through one iteration, and
switch back. Expected minimized schedule: **one** switch plus **one** budget
byte, i.e. ≤ 2 non-zero variant spans.

`examples/sched_deadlock.rs`: two `Mutex`es acquired in opposite order by two
threads. Requires one preemption between the two `lock()` calls (edge budget)
and then exercises futex emulation on the contended path plus deadlock
detection (`R = ∅`, two emulated waiters). Expected minimized schedule: one
switch. A third, `sched_missed_notify.rs` (`Condvar` checked without a loop /
flag read outside the lock), exercises `FUTEX_WAKE` with no waiters followed
by a forever `FUTEX_WAIT` → detected as deadlock, not as a hang.

Demo harness `examples/sched_fuzz.rs` (supervisor side, uses dowsing):
`curious()` until an outcome ≠ `Ok`, `fork_case`, `cautious()` to minimize,
then replay the minimized case twice and assert the two schedule traces are
identical; print the schedule in human form (`T0 runs 143 edges → clone3;
T0 preempted after 4 edges → T1 runs → futex WAIT …`).

Measurements to report from the demo:

* stops per case, µs per stop (supervisor `waitpid` loop), wall time per
  case under the scheduler vs native — target ≤ 2× native for the demo
  binaries (they are syscall-poor; the edge callback dominates);
* edge-callback overhead (instrumented vs plain build of the same target);
* cases-to-first-failure for `curious()` (median over 20 seeds) and the
  minimized schedule length / number of `cautious()` executions;
* replay determinism: schedule-trace hash equal over 100 replays, with ASLR
  disabled and enabled (to prove decisions do not leak addresses).

## Prototype results (what was built and what deviated)

All milestones a–e were built and run (`spikes/thread-scheduler/`, commands
in the README). Everything in this section is **[measured]** on the same box.

| planned | result |
|---|---|
| stops/case, µs/stop | 19 ptrace stops / 12 scheduling points per `lost_update` case; **10.7–11.1 µs per scheduling stop** marginal (10 000 `sched_yield` under the supervisor vs 0.24 µs native). Slightly above the 10.2 µs microbenchmark: each stop also runs the scheduler, records the trace event and rewrites the budget word in the shared page |
| wall vs native ≤ 2× | 1.9× (`lost_update` 0.68 → 1.29 ms), 1.8× (`deadlock`), 1.7× (`missed_notify`); dominated by fork/exec/seize |
| edge callback ~1.3 ns/edge | **~1.6 ns/edge** on the critical path (3-edge loop 2.56 → 7.30 ns/iter), ~0.3 ns/edge when hidden behind a dependency chain. Attached (shared page) and unattached (early return) cost the same, so the `call` itself is the cost |
| cases-to-first-failure, 20 seeds | `lost_update` 3 / 18 / 57 (min/median/max), `deadlock` 2 / 23 / 83, `missed_notify` 1 / 16 / 36; **20/20 seeds** for each |
| minimized length ≤ 2 (`lost_update`), 1 (`deadlock`) | **3 / 5 / 9** for `lost_update`, **2 / 3 / 5** for `deadlock`, 0 for `missed_notify` — see deviation 4 |
| trace hash equal over 100 replays, ASLR on/off | 100/100 identical for every demo and every minimized case; same hash with `setarch -R` and without |

Deviations from the memo:

1. **Standalone crates instead of a feature-gated `src/sched` module.** The
   spike rules require `spikes/<name>/` with its own `[workspace]`, and the
   target must not link dowsing at all, so there are three packages:
   `thread-scheduler` (supervisor, depends on `iterator-fuzz`), `sched-target-rt`
   (sancov callbacks + shm attach, `libc` only) and `sched-targets`. Nothing in
   the root crate changed; `ShmCoverage` implements the existing
   `CoverageCapture` trait unmodified.
2. **The edge budget is a single `u32` in the shared page, not a
   `thread_local!`.** With exactly one running thread there is only ever one
   live budget; the supervisor writes it before `PTRACE_CONT` and the callback
   decrements it with plain load/store. The bitmap and edge counter use plain
   load/store for the same reason: switching from `fetch_or`/`fetch_add` to
   load/store took the attached throughput loop from 23.7 to 7.3 ns/iter.
3. **The yield marker is `getppid(0x5eed5ced)`** (risk 8 in the memo,
   resolved): it is distinguishable from a user `yield_now()` in the trace
   (`preempt` vs `yield`) and the filter only traces `getppid`, it does not
   need a dedicated syscall number.
4. **Minimized lost-update schedules are 3+ non-zero spans, not ≤ 2.** The
   race window is between the first `unlock` and the second `lock`; the
   geometric `BUDGET_TABLE` (…8, 12, 16…) usually lands the preemption while
   the mutex is still held, so the other thread parks on the futex and one
   more non-zero `pick` is needed to hand control back, then another to
   switch again. `cautious()` reaches the 3-span path for some seeds (median 5,
   worst 9 over 20 seeds). Fix: exact small budgets or a "preempt at the next instrumented
   store" budget kind. Risk 2 ("budget granularity is a guess") is confirmed.
5. **Edge coverage alone is a weak signal for interleavings** (the failing
   outcome is not a new edge, and the demos are ~100 edges), so the harness
   also feeds the schedule shape (`(index, thread, point kind)` per decision)
   as features via `ShmCoverage::add_features`; `coverage_with_cost` ranks
   shrunk variants by `non_zero_decisions*1000 + edges/1024`. **[inference]**
   how much either signal contributes versus plain random schedules was not
   measured separately (an A/B against `NoCoverage` is a cheap follow-up).
6. **`missed_notify` needs no search**: the FIFO (all-zero) schedule runs the
   main thread to `notify_one` before the worker starts, and the worker's
   `FUTEX_WAIT` with no possible waker is reported as `deadlock` in 2 ms
   instead of hanging. Natively 0/50 runs fail.
7. **Timed futex waits use virtual time** rather than a fuzzer choice: a
   timed waiter is expired (`-ETIMEDOUT`) only when no other thread can run,
   which keeps the outcome deterministic without spending case bytes. No demo
   exercises this path.
8. **Startup**: `PTRACE_SEIZE` of the self-`SIGSTOP`ped child reports
   `PTRACE_EVENT_STOP`, then `SIGCONT` delivery and `PTRACE_EVENT_EXEC`
   arrive in either order; the spawn code consumes both. A failed `execve`
   shows up as a seccomp stop on `exit_group` before the exec event and is
   reported as such.
9. **Non-blocking `poll(_, _, 0)`** (Rust std's stdio fd check at startup) is
   allowed straight through instead of being a scheduling point; every other
   `poll`/`epoll_wait`/`select` still stops and is logged as uncontrolled.

## Prototype plan (as written before building; kept for the record)

1. `src/sched/mod.rs`, `src/sched/ptrace.rs` (thin safe wrappers over
   `libc::ptrace`, `waitpid(__WALL)`, `process_vm_readv`), `src/sched/futex.rs`
   (emulated futex table), `src/sched/scheduler.rs` (state machine above).
   Feature-gated `sched` so `cargo test`/`cargo clippy --all-targets` stay
   green on the base crate; the feature pulls in `libc` (new dependency,
   feature-gated; the crate currently depends only on `rand` and `rayon`).
2. `src/sched/target_rt.rs` compiled into the target via
   `#[cfg(feature = "sched-target")]`-only symbols: `__sanitizer_cov_trace_pc_guard{,_init}`,
   budget `thread_local!`, yield marker, shm attach from an inherited fd.
   Build recipe (adds one flag to the README's parallel recipe):
   `cargo rustc --features sched-target --example sched_lost_update -- -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 -Cllvm-args=-sanitizer-coverage-trace-pc-guard -Cllvm-args=-sanitizer-coverage-pc-table`.
3. `src/sched/coverage.rs`: `ShmSancovCoverage: CoverageCapture` (serial
   first; the shm is per-process so `ParallelCoverageCapture` is a follow-up).
4. Seccomp filter (BPF built in Rust, ~15 instructions): `RET_TRACE` for
   `futex, clone, clone3, sched_yield, nanosleep, clock_nanosleep, epoll_wait,
   epoll_pwait, epoll_pwait2, poll, ppoll, select, pselect6, exit, exit_group,
   getrandom` and the yield marker; `ALLOW` everything else.
5. Milestones, each with a test:
   a. spawn + seize + run single-threaded target to completion, coverage
      bits arrive (existing `buggy_stack` as target);
   b. two threads, syscall-only scheduling, deterministic replay of the
      trace hash;
   c. futex emulation: `Condvar` ping-pong target terminates under every
      random schedule, deadlock target reports deadlock;
   d. edge budget: `sched_lost_update` fails under `curious()`;
   e. `cautious()` minimization + replay assertion + overhead report.
6. Docs: README section "Scheduling real threads"; keep this memo updated
   with measured results replacing the estimates above.

Estimated effort: milestones a–c one session, d–e one session.

## Risks and unknowns

* **Uninstrumented code between scheduling points.** Races whose window lies
  entirely inside precompiled `std` (or any non-instrumented dependency)
  cannot be preempted. Mitigations, in order: instrument dependencies via
  `RUSTFLAGS` (works today for crates, not std); `-Zbuild-std` (nightly);
  hardware watchpoints on hot shared addresses; single-step microscope.
  The demo bugs are in user code and unaffected.
* **Edge budget granularity vs. exploration cost.** A geometric table is a
  guess; if `curious()` needs too many cases to hit the lost update, add a
  PCT-style "one change point per thread" mode. Coverage feedback should
  help: the racy branch (`v + 1` observing a stale `v`) is not a new edge, so
  the failure is found by the *outcome*, not by coverage — worth measuring
  how much coverage guidance actually contributes here.
* **Wall-clock leakage.** `Instant::now()`/`SystemTime::now()` use the vDSO
  and are invisible to ptrace/seccomp. Programs that branch on elapsed time
  are not deterministic under this design. Fix belongs to the sandbox spike
  (remap the vDSO or `prctl(PR_SET_TIMERSLACK)`-style tricks do not help;
  rr patches the vDSO **[recollection]**).
* **Futex emulation fidelity.** Rust std uses `WAIT_BITSET`/`WAKE` only
  (verified); glibc internals may use `WAKE_OP`/`REQUEUE` (`pthread_cond`
  in C dependencies). Unknown ops pass through and are logged; correctness
  of those cases is not guaranteed. `FUTEX_WAIT` with `CLONE_CHILD_CLEARTID`
  wake on exit is handled explicitly; robust-futex lists on abnormal thread
  death are not.
* **Signals in the target.** `SIGSEGV` etc. are outcomes; `SIGCHLD`, timers
  and `pthread_cancel` are not modelled. Async-signal delivery is another
  nondeterminism source; the spike forwards signals but does not schedule
  their delivery.
* **ptrace ergonomics.** Exactly one tracer per tracee: while dowsing
  supervises, `gdb`/`rr` cannot attach. For debugging a minimized case, add a
  `--detach-at <decision>` switch that `PTRACE_DETACH`es with all but one
  thread `SIGSTOP`ped so gdb can attach. `PTRACE_O_EXITKILL` guarantees no
  orphaned targets when the harness panics.
* **`PTRACE_EVENT_SECCOMP` + `PTRACE_SYSCALL` exit-stop ordering.** Verified
  on 6.8 (**[measured]**); older kernels (< 4.8) differ. Not a concern for the
  stated environment.
* **Throughput.** ~10 µs per stop and a few hundred stops per case gives
  ≥ 100 cases/s for syscall-poor targets; `tokio`-style targets with tens of
  thousands of `epoll_wait`/`futex` per case will be dominated by stop cost
  (~1 s per 100k stops). If that matters, the systrap-style in-target fast
  path is the escape hatch; the scheduler logic is unchanged.
* **Hypervisor PMU.** Not needed by this design; recorded here only because
  it rules out the rr approach on this class of machine.
* **Yield marker choice.** Reusing `sched_yield` conflates user
  `yield_now()` with budget preemption; a dedicated unused syscall number
  (e.g. `SYS_getppid` with a magic `rdi`) keeps them distinguishable in the
  schedule trace. Decide in milestone d.
* **Output/`exit code` as oracle.** Detecting a lost update requires the
  target to assert; the harness sees exit status/signal. That is faithful to
  "no mocks" but means bugs that do not crash or hang are invisible unless
  the target checks its own invariants (or we add a `trace-compares`
  dictionary channel later).
