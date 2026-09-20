# thread-scheduler spike: fuzzer-controlled deterministic thread scheduling

A prototype that runs a real multithreaded Rust program (plain `std::thread`,
`Mutex`, `Condvar`, no mocks) as a ptrace'd child of a dowsing harness, lets
exactly one target thread run at a time, and lets the dowsing `CaseRng` decide
which thread runs next and for how many CFG edges. Interleavings become
byte-for-byte replayable dowsing cases: `curious()` explores them and
`cautious()` shrinks them with no scheduler-specific shrinking code.

Everything in this README was executed on the machine described in
[`DESIGN.md`](DESIGN.md) (kernel 6.8.0-1061-aws, rustc 1.98.1, 8 vCPU under a
hypervisor, `ptrace_scope=1`, unprivileged user). Numbers are from that box.

## Layout

```
spikes/thread-scheduler/
├── Cargo.toml            supervisor crate `thread-scheduler` (own [workspace], depends on ../..)
├── src/
│   ├── ptrace.rs         PTRACE_SEIZE/CONT/GETREGS/SETREGS/PEEK/POKE, waitpid(__WALL) decoding
│   ├── seccomp.rs        classic-BPF filter: RET_TRACE for the scheduling syscalls, ALLOW the rest
│   ├── shm.rs            memfd shared with the target: budget word, edge counter, edge bitmap;
│   │                     ShmCoverage: CoverageCapture (bitmap -> ExecutionFeedback)
│   ├── supervisor.rs     the scheduler state machine, futex emulation, deadlock detection,
│   │                     RunReport + schedule trace + trace hash; FifoScheduler
│   └── dowsing.rs        CaseScheduler: turns a CaseRng into scheduling decisions
├── examples/sched_fuzz.rs   harness: run | fuzz | seeds | bench | replay
├── target-rt/            `sched-target-rt`: linked into targets; __sanitizer_cov_trace_pc_guard,
│                         shm attach, edge budget + yield-marker syscall (depends only on libc)
├── targets/              `sched-targets`: the demo programs (depend only on sched-target-rt)
│   └── src/bin/{sched_lost_update,sched_deadlock,sched_missed_notify,sched_edge_bench,sched_stop_bench}.rs
├── build-targets.sh      builds the targets with sancov trace-pc-guard instrumentation
├── DESIGN.md             design memo, updated with what the prototype measured
└── README.md
```

Three separate Cargo packages (each with an empty `[workspace]`) because the
target must not link dowsing or the supervisor, and `cargo rustc` applies the
sancov flags only to the final crate, so the runtime that *implements* the
sancov callbacks is naturally left uninstrumented (otherwise the callback would
call itself). No root `Cargo.toml` or root `src/` edits were needed.

## Build and run from a fresh clone

```sh
git clone https://github.com/DioxusLabs/dowsing.git
cd dowsing
git checkout devin/spike/thread-scheduler
cd spikes/thread-scheduler

# 1. instrumented demo targets (+ an uninstrumented copy of the edge benchmark)
./build-targets.sh

# 2. supervisor + harness, unit tests (seccomp program, CaseScheduler determinism)
cargo build --release --example sched_fuzz
cargo test

F=./target/release/examples/sched_fuzz
T=targets/target/release

# 3. the bugs do not show natively
$T/sched_lost_update;   echo "native lost_update exit $?"    # 0
$T/sched_deadlock;      echo "native deadlock exit $?"       # 0
$T/sched_missed_notify; echo "native missed_notify exit $?"  # 0

# 4. one supervised run under the FIFO (all-zero) schedule; prints the schedule trace
$F run $T/sched_lost_update
$F run $T/sched_deadlock
$F run $T/sched_missed_notify   # FIFO alone already deadlocks: detected, not a hang

# 5. dowsing: curious() finds a failing schedule, fork_case -> cautious() minimizes it,
#    the minimized case is replayed 100x and the trace hashes must all be equal
$F fuzz $T/sched_lost_update 0     # seed 0
$F fuzz $T/sched_deadlock 0
$F fuzz $T/sched_missed_notify 0

# 6. measurements
$F seeds $T/sched_lost_update 20   # cases-to-first-failure + minimized length over 20 seeds (~1 min)
$F seeds $T/sched_deadlock 20
$F seeds $T/sched_missed_notify 20
$F bench $T/sched_lost_update 50   # native vs scheduled wall, stops/case
$F replay $T/sched_lost_update 100                 # 100 FIFO replays, ASLR on
setarch x86_64 -R $F replay $T/sched_lost_update 100   # same, ASLR off -> same hash
$T/sched_stop_bench; $F run $T/sched_stop_bench    # us per scheduling stop (10k sched_yield)
targets/target/plain/release/sched_edge_bench      # edge callback overhead: plain,
$T/sched_edge_bench                                #   instrumented unattached,
$F run $T/sched_edge_bench                         #   instrumented + attached to the supervisor
```

`SCHED_VERBOSE=1` prints every decision as it is taken.
`SCHED_DISCOVERY_CASES` (default 2000) and `SCHED_MIN_CASES` (default 1500)
cap `curious()` and `cautious()`.

The root crate is untouched: `cargo test` (54 tests) and
`cargo clippy --all-targets` at the repository root are unchanged by this
branch (clippy reports the same two pre-existing warnings, no errors).

## Approach

Control plane: `fork`; in the child install the seccomp filter, `SIGSTOP`
self, `execve`. The parent `PTRACE_SEIZE`s with
`TRACECLONE|TRACEEXEC|TRACEEXIT|TRACESECCOMP|EXITKILL`. From then on:

* Only the syscalls in `seccomp::SCHEDULING_SYSCALLS` stop the target
  (`futex`, `clone`, `clone3`, `sched_yield`, `nanosleep`, `clock_nanosleep`,
  `epoll_wait*`, `poll`, `ppoll`, `select`, `pselect6`, `exit`, `exit_group`,
  `getrandom`, and the yield marker `getppid(0x5eed5ced)`). Everything else
  runs at native speed.
* The supervisor keeps every thread stopped except one. At each scheduling
  point it asks the `Scheduler` for `(pick, budget)`; `pick` indexes the
  runnable set (0 = keep the current/lowest thread), `budget` indexes
  `BUDGET_TABLE` (0 = run to the next syscall, k > 0 = preempt after
  `BUDGET_TABLE[k]` edges). The budget is written into the shared page before
  the thread is resumed.
* `PTRACE_EVENT_CLONE` hands the new thread over stopped; it never executes a
  user instruction until scheduled (`threadstart` in the trace).
* `futex` is emulated: `FUTEX_WAIT[_BITSET]` reads `*uaddr` via
  `PTRACE_PEEKDATA` (race-free, everyone is stopped), injects `-EAGAIN` if it
  differs, otherwise skips the syscall (`orig_rax = -1`) and parks the thread
  as an emulated waiter; `FUTEX_WAKE[_BITSET]` wakes matching waiters FIFO and
  injects the count. The kernel's `CLONE_CHILD_CLEARTID` wake on thread exit is
  handled by re-checking waiters' words after every exit. Timed waits use
  virtual time: they only "expire" when nothing else can run. Empty runnable
  set with parked waiters = `Outcome::Deadlock`, killed and reported instead
  of hanging.
* `sched_yield`/`nanosleep` are skipped (a scheduling point, nothing else).
  `getrandom` is answered from the case bytes.
* Preemption inside syscall-free code comes from the target's own
  `__sanitizer_cov_trace_pc_guard`: it sets a bit in the shared bitmap,
  increments an edge counter and decrements the budget word; at zero it
  issues the yield-marker syscall, which the seccomp filter turns into a
  scheduling stop. Plain loads/stores (no atomics) suffice because the
  supervisor guarantees a single running thread.
* `RunReport` records `(thread, point kind, edges run)` per scheduling point;
  its hash is the replay oracle.

dowsing integration (`src/dowsing.rs`, `examples/sched_fuzz.rs`):

```rust
let mut decisions = rng.range(0..MAX_DECISIONS);   // Length span
// per scheduling point:
let item = decisions.next()?;                        // Item span (deletable)
let pick   = item.variant(runnable.len());           // 0 = keep current
let budget = item.variant(BUDGET_TABLE.len());       // 0 = no preemption
// getrandom bytes: item.fill_bytes(..)
// after the range is exhausted: pick = 0, budget = 0 forever (deterministic)
```

`curious().with_coverage(ShmCoverage)` runs cases until the outcome is not
`exit(0)` (coverage = target edge bitmap ∪ schedule-shape features);
`fork_case()` seeds `cautious().with_case(..)`; each shrunk variant is
accepted with `coverage_with_cost(non_zero_decisions*1000 + edges/1024)`
when it reproduces the same outcome class and `discard()`ed otherwise; the
best case is replayed 100× and the harness asserts a single trace hash.
Because `cautious()` zero-fills the tail and the Variant/Item/Length passes
zero/delete spans, a fully shrunk schedule is "run in creation order", and
the minimized schedule length is the number of non-zero variant spans.

## What was measured

### The demos (all three: native passes, supervised finds it, 20/20 seeds)

| target | bug | native (50 runs) | FIFO schedule | `curious()` cases to first failure, 20 seeds min/median/max | minimized non-zero variant spans min/median/max | 100 replays |
|---|---|---|---|---|---|---|
| `sched_lost_update` | `let v = *m.lock(); *m.lock() = v+1;` on 2 threads | 0/50 fail | passes | 3 / 18 / 57 | 3 / 5 / 9 | 1 hash |
| `sched_deadlock` | AB / BA lock order | 0/50 fail | passes | 2 / 23 / 83 | 2 / 3 / 5 | 1 hash |
| `sched_missed_notify` | `Condvar::wait` without predicate loop | 0/50 fail | **deadlock detected** | 1 / 16 / 36 | 0 / 0 / 0 | 1 hash |

Seed 0 of `sched_lost_update`, verbatim (discovery 65 ms, minimization 2.65 s,
219/1500 `cautious()` variants reproduced, 6 remaining decisions of which 3
are non-zero):

```
seed 0: failure after 45 cases (65.32ms): exit(101)
...
minimized in 2.65s: 219/1500 variants reproduced; best cost 3000: 3 non-zero variant spans, 6 decisions consumed, outcome exit(101)
minimized schedule:
outcome exit(101) | threads 3 | scheduling points 16 | ptrace stops 23 | decisions 6 (3 non-zero) | edges 94 | wall 1.87ms
    0: T0 ran      1 edges -> getrandom
    1: T0 ran      7 edges -> clone
    2: T1 ran      0 edges -> threadstart
    3: T0 ran      4 edges -> clone
    4: T2 ran      0 edges -> threadstart
    5: T0 ran      0 edges -> futexwait        (join)
    6: T1 ran     12 edges -> preempt          (budget 12: between the two lock() calls)
    7: T2 ran      4 edges -> futexwait        (T1 still holds the mutex here)
    8: T1 ran      3 edges -> futexwake        (unlock; the stale `v` is written later)
    9: T2 ran      0 edges -> futexwoken
   ...
decisions: [0/0, 0/0, 0/7, 1/0, 1/0, 0/0]
100 replays of the minimized case in 145.95ms: 1 distinct trace hash(es) 0x6c0e5348425d4104
```

Replay determinism with and without ASLR (`setarch -R`), FIFO schedule, 100
replays each: one distinct hash per target, identical across ASLR on/off
(`0x2ea7700f01baf138`, `0x9ebc5cf4975b11ea`, `0xed2bdde71c46c5b5`). The
`fuzz` run of seed 0 also produces the same minimized case and hash with ASLR
on and off. Nothing in the decision path sees an address: the trace records
thread indices, point kinds and edge counts.

### Overhead

| quantity | measured |
|---|---|
| scheduling stop, marginal (`sched_stop_bench`: 10 000 `sched_yield`, 1 thread) | native 0.24 µs/yield; supervised **10.7–11.1 µs/yield** (3 runs: 11.05, 10.71, 10.69) |
| ptrace stops per demo case (FIFO) | 19 (`lost_update`, `deadlock`), 8 (`missed_notify`); 12 / 12 / 6 scheduling points |
| wall per case, native vs supervised FIFO (50 runs, includes fork+exec+seize) | `lost_update` 0.68 ms → 1.29 ms (**1.9×**); `deadlock` 0.71 → 1.27 ms (1.8×); `missed_notify` 0.91 → 1.51 ms (1.7×) |
| edge callback (`sched_edge_bench`, 20 M iterations) | latency loop (2 edges/iter): plain 4.06 ns → instrumented 4.74 (unattached) / 4.67 (attached) ns/iter ⇒ ~0.3 ns/edge hidden behind the dependency chain; throughput loop (3 edges/iter): 2.56 → 7.53 / 7.30 ns/iter ⇒ **~1.6 ns/edge** on the critical path |
| `cautious()` minimization | 1500 variants in 2.0–2.7 s (~1.5 ms per supervised case) |

Per case the fixed cost is process creation (~0.7 ms native already), so the
"≤ 2× native" target from the memo is met for these tiny targets. The stop
cost (~11 µs) is what dominates syscall-heavy targets: a case with 100 k
scheduling points would take ~1 s.

## What works

* ptrace + seccomp `RET_TRACE` control plane, one runnable thread at a time,
  new threads held at `PTRACE_EVENT_CLONE` until scheduled.
* futex `WAIT`/`WAIT_BITSET`/`WAKE`/`WAKE_BITSET` emulation with race-free
  word reads, `EAGAIN` fast path, virtual-time timeouts, `CLEARTID` wake on
  thread exit, deadlock detection (reported as an outcome, never a hang).
* Edge-budget preemption through the target's sancov callback with a yield
  marker syscall; this is what finds the lost update (which makes one real
  `futex` syscall per thread in total).
* dowsing integration exactly as designed: `range` length span, one `Item`
  per decision, two `variant`s, `fill_bytes` for `getrandom`, zero after
  exhaustion; `curious()` discovery with `ShmCoverage: CoverageCapture`;
  `fork_case` → `cautious().with_case`, `coverage_with_cost`, `discard`.
* Deterministic replay: 100/100 identical trace hashes for every demo and for
  every minimized case, with ASLR on and off.
* Three real bugs found from every one of 20 seeds each, and minimized.

## What does not work / limitations found

* **Minimized lost-update schedules are 3–9 non-zero spans, not the ≤ 2 the
  memo predicted.** The bug needs a preemption *exactly* between `unlock` of
  the first `lock()` and the second `lock()`; the geometric `BUDGET_TABLE`
  usually lands the preemption while the mutex is still held, so the other
  thread blocks on the futex and one extra non-zero `pick` is needed to get
  back, then another to switch again. The minimum (3) is the cheapest path
  the table offers. A finer table around small budgets, or a "budget =
  exactly n edges" variant, would bring this to 2.
* `sched_missed_notify` is exposed by the FIFO schedule itself (0 non-zero
  spans): the main thread runs to its `notify_one` before the worker is ever
  scheduled. Good for the deadlock detector, but it means this demo does not
  exercise search.
* Only Rust std's futex operations are emulated. `FUTEX_REQUEUE`,
  `WAKE_OP`, PI ops pass through to the kernel and are logged in
  `RunReport::uncontrolled` (none occurred in the demos). Robust futex lists
  on abnormal thread death are not handled.
* Preemption only exists in instrumented code; precompiled `std` internals
  that are not inlined into the target crate run atomically between syscalls.
  Fine for the demos (the `Mutex` fast path is inlined); a race entirely
  inside an uninstrumented dependency cannot be reached.
* Wall clock via vDSO (`Instant::now`) is invisible and not virtualised; the
  scheduler is deterministic, a time-dependent target may not be.
* `epoll_wait`/`poll`/`select` with a non-zero timeout stop the target but
  are not emulated: they are logged in `uncontrolled` and passed through to
  the kernel (a blocking one would hang until the 5 s watchdog reports
  `timeout`); no async-runtime target was tried.
* `MAX_DECISIONS = 64` scheduling decisions per case are fuzzer-controlled;
  beyond that the schedule is FIFO. Enough for the demos, a knob for larger
  targets.
* Signals other than crash signals are forwarded but their delivery point is
  not scheduled.
* One supervisor = one target process; `ShmCoverage` is serial (no
  `ParallelCoverageCapture`).
* Hardware watchpoints and the single-step "microscope" from the memo were
  not built into the prototype (they were only measured standalone).

## Next steps

1. Budget table: add small exact budgets (1..32 in steps of 1) or an
   "edges until the next instrumented store" mode so lost-update schedules
   minimize to 2 non-zero spans; try PCT-style one-change-point-per-thread
   as an alternative encoding and compare cases-to-first-failure.
2. Virtualise the remaining blocking syscalls (`epoll_wait`, `poll`, `ppoll`
   timeouts → virtual time) and try a small tokio target; measure how the
   ~11 µs stop cost scales.
3. Instrument dependencies (`RUSTFLAGS` with the sancov passes) so races in
   third-party code are reachable; evaluate `-Zbuild-std` on nightly.
4. Move `ShmCoverage`/the supervisor behind a `sched` feature of the root
   crate once the interface settles; expose `RunReport` traces as dowsing
   dictionary values so the schedule itself becomes a coverage signal.
5. Wall-clock virtualisation (vDSO remap) belongs to the sandbox spike; the
   `getrandom` path here shows the "answer a syscall from the case bytes"
   pattern it will reuse.
6. A `--detach-at <decision>` switch that `PTRACE_DETACH`es so gdb can attach
   at a chosen point of a minimized schedule.
