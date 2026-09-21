# Comparison matrix

Every number here was measured on one machine, in one sitting, by `./run.sh` (raw lines in
`results.txt`; last full re-run 2026-09-21, on the modular supervisor). Host: Linux 6.8.0-1061-aws, 8 vCPU Intel Xeon Platinum 8559C (KVM), 31 GB.
Targets are the real binaries in `sandbox/targets` (std `Mutex`/`Condvar`/`thread::sleep`,
built `--release` with sancov edge instrumentation); the model checkers get the same logic
ported to their own `sync`/`thread` modules (`src/lib.rs`) because they cannot run a binary.

## Tasks

| id | target | bug | why it is hard |
|---|---|---|---|
| T1 | `lost_update` | two threads do `v = *lock(); *lock() = v + 1` twice; final count is checked | every access is mutex-protected, so it is a *logical* race, not a data race; natively 1–3 failures in 20 000 runs |
| T2 | `deadlock` | `variant(4)==3` makes one thread take locks in the opposite order | needs one specific harness choice *and* one specific interleaving |
| T3 | `sleep_race` | worker `sleep(5ms)` then publishes; main `wait_timeout(50ms)`; the bug is the timeout path | only reachable if time can run ahead of the worker; natively 0 failures in 2 000 runs |
| T4 | `slow_setup` | 64 MB table built before a T1-style race | how much does resuming after an expensive prefix cost, vs re-executing it |

## Matrix

"runs" = executions of the target until the first failure (3 seeds for the sandbox; loom is
deterministic and gives one number, shuttle's random/PCT schedulers reseed per invocation). Time is wall-clock to the first failure, including
supervisor/snapshot overhead. `—` means the tool has no way to express the task; `0/N` means
it ran and did not find the bug.

| tool | runs unmodified binary | T1 lost update | T2 deadlock | T3 timeout path | T4 resume after 64 MB setup | replay of a failure |
|---|---|---|---|---|---|---|
| **native loop** | yes | 3/20 000 runs, 31.3 s (1.56 ms/run) | 0/2 000, 3.0 s | 0/2 000, 13.3 s | 40–48 ms/run (re-executes setup) | not reproducible (≈1 in 7 000) |
| **rr 5.9 `record -h` (chaos)** | yes | 0/300, 82 s (272 ms/run) | 0/300, 61 s (203 ms/run) | 8/300, 74 s (248 ms/run) | — (record/replay only, no resume) | yes; `rr replay` 25 ms |
| **hermit** (v1 @20622f9) default / `Random` / `StickyRandom` / `--chaos` pt=100k / pt=10k | yes | 0/100 each; 27 / 26 / 27 / 98 / 853 ms/run (earlier sitting: also 0/1000 `Random`, 0/20 pt=1000 at 5.3 s/run) | 0/100 each; 23 / 23 / 23 / 95 / 844 ms/run — harness `variant` is clock-seeded and hermit's clock is deterministic, so always the same variant | 0/100 each; 23 / 22 / 23 / 95 / 861 ms/run | — (no snapshot; re-executes) | yes; `--verify` (2 runs + log diff) 0.31 s, deterministic |
| **loom 0.7** (exhaustive) | no — ported to `loom::sync` | 10 iterations, 0.8 ms | 17 iterations (4 variants), 110 ms | **—** `wait_timeout` never times out in loom; 7 iterations, no bug | — | yes (deterministic, by construction) |
| **shuttle 0.8** random / PCT(2) / DFS | no — ported to `shuttle::sync` | 1 / 2 / 111 iterations, ≤0.8 ms (earlier sitting 1 / 4 / 111) | 16 / 13 / 182 iterations, ≤0.7 ms (earlier sitting 4 / 56 / 182) | **—** `sleep` is a yield; 100 000 / 100 000 / 40 (DFS exhausted) iterations, no bug, 0.32 s | — | yes (schedule seed) |
| **ThreadSanitizer** (nightly `-Zsanitizer=thread`) | recompiled | 0/200, 2.5 s (12.7 ms/run) — not a data race | not run | not run | — | — |
| **fork/CoW** (single-thread holder) | yes | n/a (baseline only) | n/a | n/a | 36 ms setup once, then **1.5 ms/run** | — (holder cannot hold two live threads) |
| **CRIU 4.1** | yes | n/a | n/a | n/a | dump 95 ms (65.7 MB image), **restore 34.5 ms/run** | full-process, not per-decision |
| **dowsing sandbox, milestone 1** (coverage novelty only, budget table; earlier sitting) | yes, plus 1 harness call for T2 | 62 / 66 / 155 runs, **0.16 / 0.11 / 0.25 s** | 20 / 45 / 70 runs, **0.03 / 0.06 / 0.10 s** | 2 / 9 / 31 runs, **0.006 / 0.014 / 0.052 s** | root 100 ms once, then **1.8 ms/restore**, 3.0 ms/run incl. supervision; 49 runs to the bug | 100/100 replays identical, 1.0–2.8 ms each; shrinks to 14 / 5 / 15–17 decisions |
| **dowsing sandbox, PCT + coverage-guided tree, modular supervisor** (this branch) | yes, plus 1 harness call for T2 | **3 / 15 / 4 runs, 0.009 / 0.036 / 0.008 s** (10-seed median 5, max 15) | **1 / 23 / 9 runs, 0.003 / 0.032 / 0.010 s** (10-seed median 10.5, max 23) | **10 / 1 / 1 runs, 0.017 / 0.001 / 0.002 s** (10-seed median 1.5, max 10) | root 91 ms once, then **1.6 ms/restore**; 8 runs to the bug, 136 runs/s with the 64 MB image live | 100/100 replays identical, 1.0–3.2 ms each; shrinks to 10 / 5 / 15 decisions (5 / 4 / 3 non-default) |

Rates for the sandbox in this sitting: 329–514 runs/s on T1, 306–917 on T2, 566–900 on T3, 136 on
T4 (with the 64 MB image live). The previous sitting on the same binaries and seeds gave 9 / 6 / 4,
1 / 53 / 14, 6 / 1 / 1 runs (10-seed medians 5.5 / 9.5 / 1.5): the search is deterministic per
seed within one boot (repeated, pinned to one CPU and under an 8-way CPU hog it returns the same
run each time, and the pre-modular supervisor gives the same new numbers), but the target's
edge trace shifted between VM boots on some seeds. That cross-boot dependence is not
understood yet and is listed as a gap; the medians are the number to compare.

Before the soft-dirty fix (scan treating never-touched stack pages as dirty) the sandbox ran at
33/s on T1 and 30/s on T4; the fix is what makes the T4 restore (1.6–1.9 ms) match fork/CoW
(1.5–1.9 ms) while keeping both threads.

## Reading it honestly

- **Loom and shuttle win T1/T2 by 100–1000× on time** and that is real: they run the logic in one
  process with no syscalls, and their exhaustive/DFS search is complete for these tiny models. The
  cost is the column they lose: you rewrite the program against their `sync` module, and the
  model has no notion of time, so T3 is not merely slow, it is unreachable (loom's
  `Condvar::wait_timeout` returns immediately without timing out; shuttle documents `sleep` as
  a context switch). Both are the right tool for lock-free data structures; neither runs a binary.
- **rr chaos mode is the only other tool here that runs the unmodified binary and perturbs
  scheduling**. It found T3 (8/300 this sitting, 4/300 the previous one) because its chaos mode also
  randomizes real sleeps; it did not find T1 or T2 in 600 runs at 200–270 ms/run (the same wall
  time the sandbox used to find all three bugs on all seeds ~100× over). rr searches by re-recording from scratch; it has no notion of a
  decision node to return to, and no coverage feedback.
- **Hermit is the closest design** — unmodified binary, ptrace+seccomp, one thread at a time,
  virtual time, deterministic by construction (`--verify` agrees) — and it found none of the three
  bugs in 3 000+ runs over two sittings. Its schedule decisions happen at syscalls, and T1's window (between two uncontended
  `Mutex` ops, no syscall) never contains one; `--chaos` adds branch-counter
  preemption but at a 10 000-RCB quantum the run costs 0.85 s and still misses (in the previous
  sitting one seed in 100 crashed hermit itself with SIGSTKFLT, not the target). Under hermit's virtual clock T3's `sleep(5ms)`
  is always shorter than the `wait_timeout(50ms)` deadline (time is a function of the schedule,
  not a search dimension), so the timeout branch was never taken in 1 000 runs; the sandbox treats "how far does the clock
  jump" as a decision and finds T3 in 1–31 runs. Hermit also has no harness decision API: T2's
  `variant(4)` falls back to a clock-seeded RNG that hermit makes constant.
- **TSan does not find T1** and this is correct behaviour for TSan: every access is under the
  mutex. Detecting "the invariant was violated between two critical sections" needs an oracle
  (the target's own assert) plus a schedule that violates it — which is the search problem.
- **T4 is the snapshot number that matters.** Fresh execution of the setup costs 40–48 ms;
  CRIU restores a full 64 MB image in 35–41 ms (it rewrites every page); fork/CoW resumes in 1.5–1.9 ms
  but a `fork()` holder keeps only the calling thread, so it cannot represent a state in which the
  race has already started. The sandbox restore writes only the pages that changed since the
  snapshot (avg 18 pages) plus register sets for every thread, in 1.6–1.8 ms, and does so at any
  decision node.
- **Runs-to-failure vs shuttle**: shuttle's random scheduler found T1 in 1 iteration and T2 in
  4–16, its PCT(2) in 2–4 and 13–56 (two sittings). Milestone 1 needed 62–155 and 20–70: its preemption points were a
  coarse budget table (many nodes per critical section, few of them useful) and the frontier was
  sampled by coverage novelty alone. The second row is the same supervisor with PCT rollouts on
  the tree (random thread priorities, `d ≤ 3` change points, exact edge-distance budgets), budget
  candidates limited to one per distinct edge of the thread's segment, interleaving features
  (stop point + last edge + next thread) counted as novelty next to edge coverage, and UCB
  selection down the tree instead of a flat frontier draw. That closes the gap to shuttle's PCT
  (median 5 / 10.5 runs vs shuttle PCT's 2–4 / 13–56 across sittings) on an unmodified binary;
  per-seed spread is still wide (T2: 1 to 23 runs over 10 seeds, 53 in the previous sitting), see
  `sandbox/sweep.sh` for the 10-seed numbers.
- **Shrink** is where the sandbox is weakest: T1 shrinks to 8–10 decisions (3–5 non-default)
  while the minimal interleaving is ~4 decisions; the shrinker does not yet merge adjacent
  preemption budgets (DESIGN.md §8).
- **rr and hermit need `kernel.perf_event_paranoid ≤ 1`**; this VM came back from a restore
  with it at 4, under which every `rr record` exits non-zero (a naive loop reports 300/300
  "failures") and hermit silently resets `--preemption-timeout` to 0 and runs at 9 ms/run with no
  preemption at all. `run.sh` and `hermit_sweep.sh` now check and write a `skipped` line instead.

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
| A1 `POST /inc`: read counter, `await` an audit call, write counter+1 (lost update) | found in round 1 (3 requests), 4/4 tries across sittings — the await makes it near-certain | **5 / 28 / 26 runs, 0.06 / 0.42 / 0.43 s** | 10/10 one trace hash, 3–4 ms each | 61→50 / 65→64 / 104→93 |
| A2 `POST /sum`: parses the first body frame as the whole JSON body (500 on a split body) | not found: over loopback a 20-byte body is always one segment; needs a client that fragments | **66 / 8 / 3 runs, 0.99 / 0.14 / 0.04 s** (the `Chunk` decision delivers half / all-but-one / one byte) | 10/10 one trace hash, 1–5 ms each | 37→20 / 64→22 / 85→84 |
| A3 `POST /inc_nowait`: same as A1 with no await — a few dozen instructions between two atomics | found in 18 rounds (54 requests), <0.1 s (earlier sitting: 21 / 99 / 204 rounds) | **0 in 14 534 / 14 497 / 14 348 runs, 600 s each** (earlier sitting: 0 / 0 / found on run 10 856 at 364 s) | 10/10 one trace hash on the one seed that found it, 17 ms each | 64→48 |

The axum rows reproduced run-for-run across the two sittings (A1 5 / 28 / 26, A2 66 / 8 / 3),
unlike some T1–T3 seeds. Throughput 59–89 runs/s at `--snapshot-every 32` for the short
searches (a run is a full request/response exchange on a fresh restore), 24/s over the 600 s ones
as the tree deepens, against 300–900/s on the two-thread targets: the axum runs are 50–200 decisions deep and each
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
  equally-new points; one seed in six (over two sittings, ~87 000 runs) got there, after
  ~11 000 runs. The kernel scheduler, by contrast, preempts on timer ticks and the two hyper
  tasks are genuinely parallel on two cores, so ~1 in 20–200 rounds hits. What would close
  this: preempt only where the segment touches shared memory (atomic RMW / lock words, which
  the target runtime can flag next to the edge id) instead of uniformly over edges — the same
  observation as T1's 60→5 runs, one level down.
- **Shrink on a 50–100-decision case reduces the non-default choices by 1–65 %** within its
  400-run budget and sometimes leaves the total longer (a different path has more decision
  points): the objective is non-default choices, and deleting a decision shifts every later
  one. Adequate for A2 (20 choices), not for A1.
- **Cost of running the real thing**: 24–90 runs/s means a 600 s budget is ~15 000–55 000
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
sudo sysctl kernel.perf_event_paranoid=1   # rr and hermit need perf counters (not persisted across reboots)
HERMIT=/path/to/hermit ./hermit_sweep.sh 100   # hermit row (build notes in the script header)
../sweep.sh 10 2000 [--pct-depth D --fanout N --ucb C]   # sandbox runs-to-failure over 10 seeds
CRIU=/path/to/criu ./run.sh snapshot   # CRIU ≥ 4.x (Ubuntu's 3.16 segfaults on restore); needs passwordless sudo
```

The TSan row needs `cd tsan && RUSTFLAGS=-Zsanitizer=thread cargo +nightly build -Zbuild-std --target x86_64-unknown-linux-gnu --release` first.
