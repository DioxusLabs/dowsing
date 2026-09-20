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
| **loom 0.7** (exhaustive) | no — ported to `loom::sync` | 10 iterations, 0.4 ms | 17 iterations (4 variants), 89 ms | **—** `wait_timeout` never times out in loom; 7 iterations, no bug | — | yes (deterministic, by construction) |
| **shuttle 0.8** random / PCT(2) / DFS | no — ported to `shuttle::sync` | 1 / 4 / 111 iterations, ≤0.8 ms | 4 / 56 / 182 iterations, ≤0.8 ms | **—** `sleep` is a yield; 100 000 / 100 000 / 40 (DFS exhausted) iterations, no bug | — | yes (schedule seed) |
| **ThreadSanitizer** (nightly `-Zsanitizer=thread`) | recompiled | 0/200, 3.1 s (15.5 ms/run) — not a data race | not run | not run | — | — |
| **fork/CoW** (single-thread holder) | yes | n/a (baseline only) | n/a | n/a | 38–45 ms setup once, then **1.8–1.9 ms/run** | — (holder cannot hold two live threads) |
| **CRIU 4.1** | yes | n/a | n/a | n/a | dump 64–77 ms (65.7 MB image), **restore 39–41 ms/run** | full-process, not per-decision |
| **dowsing sandbox (this PR)** | yes, plus 1 harness call for T2 | 62 / 66 / 155 runs, **0.16 / 0.11 / 0.25 s** | 20 / 45 / 70 runs, **0.03 / 0.06 / 0.10 s** | 2 / 9 / 31 runs, **0.006 / 0.014 / 0.052 s** | root 100 ms once, then **1.8 ms/restore**, 3.0 ms/run incl. supervision | 100/100 replays identical, 1.0–2.8 ms each; shrinks to 14 / 5 / 15–17 decisions |

Rates for the sandbox after the fix in this PR: 386–620 runs/s on T1, 659–784 on T2, 321–646 on T3,
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
- **TSan does not find T1** and this is correct behaviour for TSan: every access is under the
  mutex. Detecting "the invariant was violated between two critical sections" needs an oracle
  (the target's own assert) plus a schedule that violates it — which is the search problem.
- **T4 is the snapshot number that matters.** Fresh execution of the setup costs 41–46 ms;
  CRIU restores a full 64 MB image in ~40 ms (it rewrites every page); fork/CoW resumes in 1.9 ms
  but a `fork()` holder keeps only the calling thread, so it cannot represent a state in which the
  race has already started. The sandbox restore writes only the pages that changed since the
  snapshot (avg 18 pages) plus register sets for every thread, in 1.8 ms, and does so at any
  decision node.
- **Runs-to-failure vs shuttle**: shuttle's random scheduler found T1 in 1 iteration and T2 in 4;
  the sandbox needed 62–155 and 20–70. Two reasons: the sandbox's preemption points are
  coverage-edge budgets (many decision nodes per critical section, each a search step), and its
  search has no *guidance* yet besides coverage novelty — shuttle's PCT is a proper
  probabilistic-concurrency-testing schedule. Porting PCT onto the decision tree is a straightforward
  follow-up; the tree makes it cheaper than in shuttle because a restore replaces re-execution.
- **Shrink** is where the sandbox is weakest: T1 shrinks to 14 decisions (6 non-default) while
  the minimal interleaving is ~4 decisions; the shrinker does not yet merge adjacent
  preemption budgets (DESIGN.md §8).

## Not in the matrix

- **AFL++ / libFuzzer / cargo-fuzz**: input-byte fuzzers. These targets take no input; the task
  is schedule/time search, which they do not do (and the sandbox does not replace them for byte
  inputs — dowsing's existing in-process coverage-guided loop is that lane). Not measured.
- **Hermit** (deterministic Linux process container with chaos scheduling, the closest design
  to this PR): see the `hermit` section of `results.txt` if present; otherwise the build did not
  complete on this host in the session.

## Reproduce

```
sandbox/build-targets.sh
cd sandbox/compare
./run.sh                          # all sections → results.txt
./run.sh sandbox snapshot         # subsets: native rr sandbox loom shuttle snapshot tsan
CRIU=/path/to/criu ./run.sh snapshot   # CRIU ≥ 4.x (Ubuntu's 3.16 segfaults on restore); needs passwordless sudo
```

The TSan row needs `cd tsan && RUSTFLAGS=-Zsanitizer=thread cargo +nightly build -Zbuild-std --target x86_64-unknown-linux-gnu --release` first.
