# Comparison matrix

Every number here was measured on one machine, in one sitting, by `./run.sh` (raw lines in
`results.txt`). Host: Linux 6.8.0-1061-aws, 8 vCPU Intel Xeon Platinum 8559C (KVM), 31 GB.
Targets are the real binaries in `sandbox/targets` (std `Mutex`/`Condvar`/`thread::sleep`,
built `--release` with sancov edge instrumentation); the model checkers get the same logic
ported to their own `sync`/`thread` modules (`src/lib.rs`) because they cannot run a binary.

## Tasks

| id | target | bug | why it is hard |
|---|---|---|---|
| T1 | `lost_update` | two threads do `v = *lock(); *lock() = v + 1` twice; final count is checked | every access is mutex-protected, so it is a *logical* race, not a data race; natively 1 failure in 20 000 runs |
| T2 | `deadlock` | `variant(4)==3` makes one thread take locks in the opposite order | needs one specific harness choice *and* one specific interleaving |
| T3 | `sleep_race` | worker `sleep(5ms)` then publishes; main `wait_timeout(50ms)`; the bug is the timeout path | only reachable if time can run ahead of the worker; natively 0 failures in 2 000 runs |
| T4 | `slow_setup` | 64 MB table built before a T1-style race | how much does resuming after an expensive prefix cost, vs re-executing it |

## Matrix

"runs" = executions of the target until the first failure (3 seeds for the sandbox; loom/shuttle
are deterministic and give one number). Time is wall-clock to the first failure, including
supervisor/snapshot overhead. `—` means the tool has no way to express the task; `0/N` means
it ran and did not find the bug.

| tool | runs unmodified binary | T1 lost update | T2 deadlock | T3 timeout path | T4 resume after 64 MB setup | replay of a failure |
|---|---|---|---|---|---|---|
| **native loop** | yes | 1/20 000 runs, 36.8 s (1.83 ms/run) | 0/2 000, 4.0 s | 0/2 000, 14.0 s | 41–46 ms/run (re-executes setup) | not reproducible (1 in 20 000) |
| **rr 5.9 `record -h` (chaos)** | yes | 0/300, 90 s (300 ms/run) | 0/300, 64 s | 4/300, 77 s (256 ms/run) | — (record/replay only, no resume) | yes; `rr replay` 79.8 ms |
| **hermit** (v1 @20622f9) default / `Random` / `StickyRandom` / `--chaos` pt=100k / pt=10k | yes | 0/100 each; 80 / 27 / 32 / 117 / 864 ms/run (plus 0/1000 `Random`, 0/20 pt=1000 at 5.3 s/run) | 0/100 each; 25 / 24 / 23 / 104 / 865 ms/run — harness `variant` is clock-seeded and hermit's clock is deterministic, so always the same variant | 0/100 each; 27 / 25 / 27 / 108 / 856 ms/run | — (no snapshot; re-executes) | yes; `--verify` (2 runs + log diff) 0.28 s, deterministic |
| **loom 0.7** (exhaustive) | no — ported to `loom::sync` | 10 iterations, 0.4 ms | 17 iterations (4 variants), 89 ms | **—** `wait_timeout` never times out in loom; 7 iterations, no bug | — | yes (deterministic, by construction) |
| **shuttle 0.8** random / PCT(2) / DFS | no — ported to `shuttle::sync` | 1 / 4 / 111 iterations, ≤0.8 ms | 4 / 56 / 182 iterations, ≤0.8 ms | **—** `sleep` is a yield; 100 000 / 100 000 / 40 (DFS exhausted) iterations, no bug | — | yes (schedule seed) |
| **ThreadSanitizer** (nightly `-Zsanitizer=thread`) | recompiled | 0/200, 3.1 s (15.5 ms/run) — not a data race | not run | not run | — | — |
| **fork/CoW** (single-thread holder) | yes | n/a (baseline only) | n/a | n/a | 38–45 ms setup once, then **1.8–1.9 ms/run** | — (holder cannot hold two live threads) |
| **CRIU 4.1** | yes | n/a | n/a | n/a | dump 64–77 ms (65.7 MB image), **restore 39–41 ms/run** | full-process, not per-decision |
| **dowsing sandbox, milestone 1** (coverage novelty only, budget table) | yes, plus 1 harness call for T2 | 62 / 66 / 155 runs, **0.16 / 0.11 / 0.25 s** | 20 / 45 / 70 runs, **0.03 / 0.06 / 0.10 s** | 2 / 9 / 31 runs, **0.006 / 0.014 / 0.052 s** | root 100 ms once, then **1.8 ms/restore**, 3.0 ms/run incl. supervision; 49 runs to the bug | 100/100 replays identical, 1.0–2.8 ms each; shrinks to 14 / 5 / 15–17 decisions |
| **dowsing sandbox, PCT + coverage-guided tree** (this branch) | yes, plus 1 harness call for T2 | **9 / 6 / 4 runs, 0.014 / 0.014 / 0.005 s** (10-seed median 5.5, max 17) | **1 / 53 / 14 runs, 0.001 / 0.080 / 0.021 s** (10-seed median 9.5, max 53) | **6 / 1 / 1 runs, 0.013 / 0.001 / 0.002 s** (10-seed median 1.5, max 7) | root 104 ms once, then **1.9 ms/restore**; 10 / 11 / 4 runs to the bug | 100/100 replays identical, 1.2–2.7 ms each; shrinks to 12 / 5 / 13–15 decisions |

Rates for the sandbox after the soft-dirty fix: 386–620 runs/s on T1, 659–784 on T2, 321–646 on T3,
262 on T4 (with the 64 MB image live). Before the fix (soft-dirty scan treating never-touched
stack pages as dirty) it was 33/s on T1 and 30/s on T4; the fix is what makes the T4 restore
(1.8 ms) match fork/CoW (1.9 ms) while keeping both threads.

## Reading it honestly

- **Loom and shuttle win T1/T2 by 100–1000× on time** and that is real: they run the logic in one
  process with no syscalls, and their exhaustive/DFS search is complete for these tiny models. The
  cost is the column they lose: you rewrite the program against their `sync` module, and the
  model has no notion of time, so T3 is not merely slow, it is unreachable (loom's
  `Condvar::wait_timeout` returns immediately without timing out; shuttle documents `sleep` as
  a context switch). Both are the right tool for lock-free data structures; neither runs a binary.
- **rr chaos mode is the only other tool here that runs the unmodified binary and perturbs
  scheduling**. It found T3 (4/300) because its chaos mode also randomizes real sleeps; it did not
  find T1 or T2 in 300 runs at ~250 ms/run (the same wall time the sandbox used to find all three
  bugs on all seeds ~100× over). rr searches by re-recording from scratch; it has no notion of a
  decision node to return to, and no coverage feedback.
- **Hermit is the closest design** — unmodified binary, ptrace+seccomp, one thread at a time,
  virtual time, deterministic by construction (`--verify` agrees) — and it found none of the three
  bugs in 1 500+ runs. Its schedule decisions happen at syscalls, and T1's window (between two uncontended
  `Mutex` ops, no syscall) never contains one; `--chaos` adds branch-counter
  preemption but at a 10 000-RCB quantum the run costs 0.86 s and still misses (one seed in 100
  crashed hermit itself with SIGSTKFLT, not the target). Under hermit's virtual clock T3's `sleep(5ms)`
  is always shorter than the `wait_timeout(50ms)` deadline (time is a function of the schedule,
  not a search dimension), so the timeout branch was never taken in 500 runs; the sandbox treats "how far does the clock
  jump" as a decision and finds T3 in 2–31 runs. Hermit also has no harness decision API: T2's
  `variant(4)` falls back to a clock-seeded RNG that hermit makes constant.
- **TSan does not find T1** and this is correct behaviour for TSan: every access is under the
  mutex. Detecting "the invariant was violated between two critical sections" needs an oracle
  (the target's own assert) plus a schedule that violates it — which is the search problem.
- **T4 is the snapshot number that matters.** Fresh execution of the setup costs 41–46 ms;
  CRIU restores a full 64 MB image in ~40 ms (it rewrites every page); fork/CoW resumes in 1.9 ms
  but a `fork()` holder keeps only the calling thread, so it cannot represent a state in which the
  race has already started. The sandbox restore writes only the pages that changed since the
  snapshot (avg 18 pages) plus register sets for every thread, in 1.8 ms, and does so at any
  decision node.
- **Runs-to-failure vs shuttle**: shuttle's random scheduler found T1 in 1 iteration and T2 in 4,
  its PCT(2) in 4 and 56. Milestone 1 needed 62–155 and 20–70: its preemption points were a
  coarse budget table (many nodes per critical section, few of them useful) and the frontier was
  sampled by coverage novelty alone. The second row is the same supervisor with PCT rollouts on
  the tree (random thread priorities, `d ≤ 3` change points, exact edge-distance budgets), budget
  candidates limited to one per distinct edge of the thread's segment, interleaving features
  (stop point + last edge + next thread) counted as novelty next to edge coverage, and UCB
  selection down the tree instead of a flat frontier draw. That closes the gap to shuttle's PCT
  (median 5.5 / 9.5 runs vs 4 / 56) on an unmodified binary; per-seed spread is still wide
  (T2 seed 2: 53 runs), see `sandbox/sweep.sh` for the 10-seed numbers.
- **Shrink** is where the sandbox is weakest: T1 shrinks to 12 decisions (5 non-default) while
  the minimal interleaving is ~4 decisions; the shrinker does not yet merge adjacent
  preemption budgets (DESIGN.md §8).

## A real program: axum through the socket API

`sandbox/targets/src/bin/axum_counter.rs` is an unmodified axum 0.8 service on a 2-worker
tokio runtime (~13 000 instrumented edges; the only sandbox-specific line is
`dowsing_target_rt::init()`, which keeps the sancov callbacks linked). The sandbox plays the
HTTP clients: connection order, which corpus request each carries, how the bytes are split
across `read()`s, when a client closes, plus the workers' interleaving and the runtime's timers
are all decisions in one tree; the kernel network stack is never involved (`docs/DESIGN.md` §9).
Oracles: the server's own `assert!` (panic on stderr), any HTTP 5xx, an unanswered request.

Three bugs, `./run.sh axum`, seeds 1–3, raw lines in `results.txt`:

| bug | native (real sockets, python client: 2 concurrent POSTs + GET /check per round) | sandbox: runs to first failure, wall | replay | shrink (non-default choices) |
|---|---|---|---|---|
| A1 `POST /inc`: read counter, `await` an audit call, write counter+1 (lost update) | found in round 1 (3 requests), 3/3 tries — the await makes it near-certain | **5 / 28 / 26 runs, 0.05 / 0.40 / 0.39 s** | 10/10 one trace hash, 3–4 ms each | 61→50 / 65→64 / 104→93 |
| A2 `POST /sum`: parses the first body frame as the whole JSON body (500 on a split body) | not found: over loopback a 20-byte body is always one segment; needs a client that fragments | **66 / 8 / 3 runs, 0.92 / 0.12 / 0.04 s** (the `Chunk` decision delivers half / all-but-one / one byte) | 10/10 one trace hash, 1–4 ms each | 37→20 / 64→22 / 85→84 |
| A3 `POST /inc_nowait`: same as A1 with no await — a few dozen instructions between two atomics | found in 21 / 99 / 204 rounds (63–612 requests), ≤0.2 s | **0 in 14 505 runs / 600 s; 0 in 14 375 / 600 s; found on run 10 856 (364 s)** | 10/10 one trace hash (seed 3), 17 ms each | 64→48 |

Throughput 65–105 runs/s at `--snapshot-every 32` for the short searches (a run is a full
request/response exchange on a fresh restore), 24–30/s over the 600 s ones as the tree deepens,
against 400–780/s on the two-thread targets: the axum runs are 50–200 decisions deep and each
restore rewrites more pages.

Reading it:

- **A2 is the case that needs this kind of tool**: no amount of native load finds a framing
  bug that loopback never triggers, and it is not a schedule bug either. Here it is one
  `Chunk` decision, found in 3–66 runs, and the shrunk case says exactly which delivery split
  it (`explore ... --corpus sandbox/corpus/axum --seed 3` prints it).
- **A1 shows the search working on a real runtime** — two workers, hyper, tokio's timer wheel
  and I/O driver, mio's eventfd waker, all under the supervisor with zero uncontrolled
  syscalls — but the bug itself is easy: the await hands the worker back to the scheduler, and
  the other connection's handler runs in the gap. Native finds it in one round.
- **A3 is where the sandbox loses, and by a lot.** The window is a handful of edges inside a
  syscall-free segment that spans hyper's parse, the handler and hyper's encode (hundreds to
  thousands of edges; the whole binary has 13 075); the preemption must land there *and* the
  other worker must be holding the second request. Budget candidates are one per
  distinct edge of the segment and `--fanout 8` samples eight of them per node, so most rollouts
  preempt somewhere useless and the interleaving-novelty signal is spread over thousands of
  equally-new points; one seed in three gets there after ~11 000 runs. The kernel scheduler, by
  contrast, preempts on timer ticks and the two hyper tasks are genuinely parallel on two
  cores, so ~1 in 100 rounds hits. What would close
  this: preempt only where the segment touches shared memory (atomic RMW / lock words, which
  the target runtime can flag next to the edge id) instead of uniformly over edges — the same
  observation as T1's 60→5 runs, one level down.
- **Shrink on a 50–100-decision case reduces the non-default choices by 1–65 %** within its
  400-run budget and sometimes leaves the total longer (a different path has more decision
  points): the objective is non-default choices, and deleting a decision shifts every later
  one. Adequate for A2 (20 choices), not for A1.
- **Cost of running the real thing**: 24–105 runs/s means a 600 s budget is ~15 000–60 000
  runs; native stress does that many requests in a few seconds. The sandbox pays this for determinism
  (one trace hash on every replay above) and for control over the protocol; it only wins where
  that control is what the bug needs (A2) or where the schedule is reachable in its tree (A1,
  T1–T3).

## Not in the matrix

- **AFL++ / libFuzzer / cargo-fuzz**: input-byte fuzzers. These targets take no input; the task
  is schedule/time search, which they do not do (and the sandbox does not replace them for byte
  inputs — dowsing's existing in-process coverage-guided loop is that lane). Not measured.
- **Hermit at HEAD**: neither the upstream `main` (autocargo `Cargo.toml` misses the
  `detcore-dbi`/`reverie-kvm` path deps) nor the maintained fork (`rrnewton/hermit`, needs
  Linux ≥ 6.9 `PIDFD_THREAD`; fails with `EINVAL` on 6.8) starts here; the row above is the last
  v1 commit built as described in `hermit_sweep.sh`.

## Reproduce

```
sandbox/build-targets.sh
cd sandbox/compare
./run.sh                          # all sections → results.txt
./run.sh sandbox snapshot         # subsets: native rr sandbox loom shuttle snapshot tsan axum
./run.sh axum                     # axum rows (needs python3; ~30 min, most of it the A3 600 s budgets)
python3 axum_native_stress.py ../targets/target/release/axum_counter 60 /inc_nowait   # native A1/A3 baseline
HERMIT=/path/to/hermit ./hermit_sweep.sh 100   # hermit row (build notes in the script header)
../sweep.sh 10 2000 [--pct-depth D --fanout N --ucb C]   # sandbox runs-to-failure over 10 seeds
CRIU=/path/to/criu ./run.sh snapshot   # CRIU ≥ 4.x (Ubuntu's 3.16 segfaults on restore); needs passwordless sudo
```

The TSan row needs `cd tsan && RUSTFLAGS=-Zsanitizer=thread cargo +nightly build -Zbuild-std --target x86_64-unknown-linux-gnu --release` first.
