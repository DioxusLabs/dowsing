# coverage-bridge: out-of-process coverage + RNG bridge

`curious()` / `cautious()` run in a **supervisor** process; the harness runs in a separate,
supervised **target** process. Two channels connect them:

* **RNG** — the supervisor pre-fills the whole byte budget of a case into shared memory; the
  child consumes it through a `CaseRng<NoCoverage>` (`Case::from_raw(..).replay()`) and writes
  back what it consumed plus the draw / semantic / sequence spans. The supervisor absorbs that
  trace into its own `CaseRng`, so `fork_case()`, the corpus, mutation and every `cautious()`
  reducer see exactly what an in-process run would have recorded.
* **Coverage** — the child copies its SanitizerCoverage 8-bit counters and its comparison
  features / dictionary values into shared memory at case end (counters also from a crash signal
  handler). `ChildCoverage: CoverageCapture + ParallelCoverageCapture` turns that into
  `ExecutionFeedback`, so `curious().with_coverage(bridge)` is the only visible API change.

Per case the target is either **forked** from a persistent forkserver (default) or **exec'd**
(baseline). The design memo is `DESIGN.md`; deviations from it are listed at the end of that
file and summarized below.

## Layout

```
spikes/coverage-bridge/
  Cargo.toml                 standalone crate (empty [workspace]); deps: iterator-fuzz (../..), libc, rand
  src/lib.rs                 fd numbers, env protocol, Verdict, ChildMode
  src/shm.rs                 #[repr(C)] Header + fixed-size tables in one memfd; layout/offset tests
  src/child.rs               target runtime: serve() = map shm, forkserver loop / exec-once, run case,
                             export trace + counters + cmp features, crash handlers, _exit
  src/supervisor.rs          BridgeConfig, ChildCoverage (CoverageCapture), run(rng) -> Outcome,
                             forkserver / exec-per-case management, timeouts, respawn, stats
  src/buggy_stack.rs         examples/buggy_stack.rs logic with rng.range/rng.variant sampling
  src/bin/buggy_stack_child  target: serve() when started by a supervisor, in-process baseline otherwise
  src/bin/buggy_stack_bridge supervisor demo: curious() -> cautious() -> Case::replay()
  src/bin/echo_child         uninstrumented protocol target (pass / fail / SIGSEGV / spin / exit(7))
  src/bin/bench              protocol floor, fork cost vs RSS, phase timings
  tests/bridge.rs            protocol, trace fidelity, replay equality, exit paths, timeout survival, sancov
  scripts/measure.sh         reproduces every number below;  scripts/seeds.sh = 10-seed comparison
```

## Build (fresh clone, Linux x86_64, stable Rust 1.98)

```sh
git clone https://github.com/DioxusLabs/dowsing.git
cd dowsing
git checkout devin/spike/coverage-bridge

# base crate must stay green
cargo test
cargo clippy --all-targets

cd spikes/coverage-bridge
cargo test                                   # shm layout tests + 6 bridge tests (echo target)
cargo build --release --bins                 # supervisor demo, bench, echo_child

# instrument the target (same recipe as the root README, applied to the child binary)
cargo rustc --release --bin buggy_stack_child -- \
  -Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-level=3 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares

# the sancov test only runs when pointed at an instrumented target
COVERAGE_BRIDGE_TARGET=$PWD/target/release/buggy_stack_child cargo test --test bridge
```

## Run the demo

```sh
cd spikes/coverage-bridge

# forkserver: curious() finds the restore/orientation bug, cautious() shrinks it,
# Case::replay() reproduces the shrunk case in-process
./target/release/buggy_stack_bridge --mode fork --seed 1

# exec-per-case baseline (same protocol, one exec per case)
./target/release/buggy_stack_bridge --mode exec --seed 1 --minimize 1000

# crash path: the harness abort()s on the bug; counters come from the SIGABRT handler
BUGGY_STACK_ABORT=1 ./target/release/buggy_stack_bridge --mode fork --seed 1 --minimize 2048

# throughput of a curious() loop with every case fed back
./target/release/buggy_stack_bridge --bench 4096 [--no-cmp] [--mode exec]
./target/release/buggy_stack_child  --bench 4096 [--no-cmp] [--no-coverage]   # in-process

# protocol floor / fork cost vs target RSS
./target/release/bench --child ./target/release/echo_child --cases 3000 --rss 10,100 -- --always-pass

# everything above plus the two extra target builds it needs
cargo build --release --bin buggy_stack_child --target-dir target/plain          # uninstrumented
cargo rustc --release --bin buggy_stack_child --target-dir target/edges -- \
  -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table
./scripts/measure.sh
```

Demo output (forkserver, `--seed 1`, this machine):

```
bridge forkserver+cmp: target .../buggy_stack_child (sancov counters detected)
bridge forkserver+cmp: case 2 failed with Failed (228 bytes, 1268 features, cost 48)
bridge forkserver+cmp: discovery ran 2 cases in 2.46ms = 814 exec/s
bridge forkserver+cmp: minimization ran 4096 cases (241 reproducing) in 1.50s = 2734 exec/s
bridge forkserver+cmp: best case cost 5 ops, 32 bytes, 467 features
  per case: fill 0.1 us, launch 68.6 us, execute 285.7 us, decode 2.9 us
replay in-process: REPRODUCED with 5 ops (32 bytes)
  ops: [Push(0), Push(1), Save, Flip, Restore]
  error: final stack [1, 0], expected [0, 1]
```

## Measurements

Machine: Ubuntu, kernel 6.8 (AWS), x86_64, Rust 1.98.1, `ptrace_scope=1`,
`perf_event_paranoid=4` (so no `perf`). Single run each via `scripts/measure.sh`; run-to-run
noise is roughly ±10 % on this VM (one `bench` round of the edges build came out 2× slower than
the two others). "cmp" = target built with `-sanitizer-coverage-trace-compares` and comparison
feedback enabled.

### 1. Executions per second, `curious()` loop, 4096 cases, every case fed back to the corpus

| configuration                                            | exec/s | per case |
|----------------------------------------------------------|-------:|---------:|
| in-process `NoCoverage` (ceiling)                        | 85 619 |    12 µs |
| in-process sancov, edge counters only (no trace-compares)| 33 230 |    30 µs |
| **bridge forkserver**, edge counters only                | **3 468** |   288 µs |
| in-process sancov, cmp-instrumented, cmp feedback off    |  2 077 |   481 µs |
| **bridge forkserver**, cmp-instrumented, cmp feedback off| **1 265** |   790 µs |
| **bridge forkserver + cmp**                              |  **842** | 1 188 µs |
| bridge exec-per-case, cmp feedback off                   |    695 | 1 439 µs |
| bridge exec-per-case + cmp                               |    369 | 2 710 µs |
| in-process sancov + cmp                                  |    324 | 3 086 µs |

Forkserver vs exec-per-case: **2.3× (no cmp) / 2.3× (cmp)**. Forkserver+cmp is 2.6× *faster*
than the in-process sancov+cmp run of the same harness: the in-process supervisor also has to
sort/dedupe the child's ~1 700 cmp features into its own corpus **and** pay the trace-compares
callbacks inside the supervisor's own instrumented code; in the bridge the supervisor binary is
uninstrumented, so only the child pays for the callbacks.

Per-phase timing inside `ChildCoverage::run` (forkserver+cmp bench): fill 16.6 µs, launch
(pipe request → child forked) 84 µs, execute (fork → status byte) 787 µs, decode 8.8 µs. During
`cautious()` the fill is ~0.1 µs (mutations reuse the recorded prefix).

### 2. Where the child's time goes (`COVERAGE_BRIDGE_PROFILE=1`, one case)

| build                    | case setup | harness | counter copy (4 203 B) | decode in child | export |
|--------------------------|-----------:|--------:|-----------------------:|----------------:|-------:|
| cmp-instrumented (+cmp)  |      41 µs |  621 µs |                  6 µs |  75 µs (1 728 features) | 8 µs |
| edge counters only       |      40 µs |   25 µs |                  6 µs |   9 µs (303 features)   | 5 µs |

The harness itself is 25 µs; the extra ~600 µs is entirely the `__sanitizer_cov_trace_cmp*`
callbacks in the root crate's `sancov.rs` (`record_cmp` hashes and pushes every comparison and
its dictionary values **even when `with_cmp_feedback(false)`**; only `finish_capture` drops
them). That is a property of the base crate, not of the bridge, and the largest single
optimization available (gate `record_cmp` on `cmp_feedback`, or thin the callbacks).

### 3. Protocol floor and fork cost vs target RSS (`bench`, uninstrumented `echo_child`, cases discarded)

| target                              | mode | exec/s | fill  | launch | execute (fork→status) |
|-------------------------------------|------|-------:|------:|-------:|----------------------:|
| echo_child (~1 MiB RSS)             | fork |  4 762 | 15 µs |  61 µs |                133 µs |
| echo_child                          | exec |  1 284 | 17 µs | 261 µs |                494 µs |
| echo_child, +10 MiB touched         | fork |  2 277 | 16 µs | 159 µs |                263 µs |
| echo_child, +100 MiB touched        | fork |    565 | 16 µs | 732 µs |              1 019 µs |
| buggy_stack_child uninstrumented    | fork |  3 723 | 16 µs |  65 µs |                185 µs |
| buggy_stack_child uninstrumented    | exec |  1 256 | 17 µs | 257 µs |                512 µs |
| buggy_stack_child edges             | fork |  2 045 | 16 µs |  75 µs |                395 µs (182 µs in an earlier run) |
| buggy_stack_child edges+cmp         | fork |  1 133 | 16 µs |  91 µs |                764 µs |
| buggy_stack_child edges+cmp         | exec |    720 | 16 µs | 296 µs |              1 054 µs |

Fork cost grows ~linearly with dirty RSS (page-table copy + COW faults): +10 MiB ≈ +100 µs,
+100 MiB ≈ +670 µs, matching the memo's `forkbench` estimate.

### 4. Cases-to-bug and shrink result, 10 seeds, in-process `SancovCoverage` vs bridge forkserver

```
seed  in-process cases->bug  bridge cases->bug   in-proc shrink  bridge shrink
1     2                      2                   5 ops 32 B      5 ops 32 B
2     12                     12                  5 ops 32 B      5 ops 32 B
3     12                     5                   5 ops 32 B      5 ops 32 B
4     3                      3                   5 ops 32 B      5 ops 32 B
5     7                      9                   5 ops 32 B      5 ops 32 B
6     6                      4                   5 ops 32 B      5 ops 32 B
7     4                      4                   5 ops 32 B      5 ops 32 B
8     5                      5                   5 ops 32 B      5 ops 32 B
9     8                      8                   5 ops 32 B      5 ops 32 B
10    14                     16                  5 ops 32 B      5 ops 32 B
```

Shrink results are identical for every seed (5 ops = `[Push, Push, Save, Flip, Restore]`,
32 bytes). Cases-to-bug matches for 7/10 seeds; the others differ by a few cases because the
coverage feature *sets* differ (the in-process binary also instruments the supervisor-side
code the bridge does not), which changes the corpus energy after the first cases.

### 5. Crash and timeout paths

* `BUGGY_STACK_ABORT=1` demo: `Crashed(6)` detected on case 2 with 239 features recovered by the
  SIGABRT handler; `cautious()` shrinks the crash to a 6-op sequence that `Case::replay()`
  reproduces (601/2048 variants reproduce, 874 exec/s). Because a crashed child never exports its
  trace, the crash case is the whole 4096-byte budget without spans, so byte-level shrinking of a
  crash cannot trim the tail (see "what does not work").
* Re-raising the signal after export handed every crash to the core-dump pipe (`apport`), ~40 ms
  of `execute` time per crashing case. The handler now `_exit(128+sig)`s after writing the
  header; the supervisor reads the signal from the header. Crashing cases now take ~0.3–0.4 ms
  (the 2048-case shrink above runs in 2.3 s).
* `tests/bridge.rs::scripted_cases_report_every_exit_path` drives the echo target through
  pass / fail / SIGSEGV / infinite loop / `exit(7)` in both modes: `Passed`, `Failed`,
  `Crashed(11)`, `TimedOut` (poll + SIGKILL, 2 s default), `Exited(7)`.
* `forkserver_survives_after_timeout_and_keeps_serving`: after a SIGKILLed case the same
  forkserver keeps serving (no respawn), verified by 20 further cases.

## What works

* Standalone crate; base crate `cargo test` (54 tests) and `cargo clippy --all-targets` stay
  green (the two clippy warnings it prints are pre-existing, in code this branch does not touch).
* `memfd` shared region with a `#[repr(C)]` header and fixed-capacity tables (input 64 KiB,
  8192 spans, 1024 sequences / 8192 items, 16384 features, 256 dictionary values, 1 MiB counters);
  the child sets overflow flags instead of writing past a cap.
* Forkserver with control/status pipes on fixed fd numbers (197/198/199), `PR_SET_PDEATHSIG` on
  both the forkserver and each case child, poll-based timeout + SIGKILL, respawn on a broken
  forkserver, exec-per-case over the same protocol.
* RNG mirror: `CaseRng::fill_budget` → child replays via `Case::from_raw(..).replay()` → raw
  trace back → `CaseRng::absorb_trace`. `child_trace_matches_in_process_trace` asserts the
  `RawCase` (prefix, draw/semantic/sequence spans) is identical to an in-process run;
  `absorbed_trace_replays_identically` asserts `Case::replay()` of the absorbed case reproduces
  the same verdict and byte count. Budget exhaustion (child ran past `input_len`) is detected and
  the case is re-run with a doubled budget up to the table cap.
* Coverage: counters copied at case end and from SIGSEGV/SIGBUS/SIGABRT/SIGFPE/SIGILL/SIGTRAP
  handlers on an alternate stack. On the normal path the child wraps the case in the base
  crate's own `SancovCoverage` (so counter reset, `feature_id`s, cmp features and dictionary
  values are exactly what an in-process run produces) and writes the decoded feature list plus
  the raw counters into the shm tables; on a crash the supervisor decodes the raw counters with
  `sancov::decode_counters`.
  `ChildCoverage` is `Clone` + `ParallelCoverageCapture`: clones share a pool and each in-flight
  case leases its own forkserver + memfd (not benchmarked in parallel).
* Demo: `curious()` finds the bug in 2–16 cases, `cautious()` shrinks to 5 ops / 32 bytes,
  `Case::replay()` reproduces in-process, in fork and exec modes.

## What does not work / limitations

* **Crash cases lose their trace.** The signal handler exports counters only (async-signal-safe
  `memcpy`), not the `CaseRng` spans, so a crash case is "the whole budget" and `cautious()`
  can only shrink it structurally via the seed's mutations, not by trimming the prefix. Fix:
  have the child publish `consumed` and the span count incrementally (a monotonically growing
  header field per draw) so the handler can leave a truncated but valid trace.
* **Timeouts export nothing** (SIGKILL); a SIGALRM-in-child or a trace-pc-guard live map would
  give partial coverage. Not implemented.
* **trace-pc-guard format not implemented.** Only inline 8-bit counters are decoded; the memo's
  second format for the parallel path is a TODO, and `ParallelCoverageCapture` has been
  exercised only through `Clone`, not under `rayon`.
* **Exec mode learns instrumentation lazily** (`instrumented()` is false until the first case);
  the forkserver reports it in the hello.
* **`absorb_trace` trusts the child.** `consumed` is clamped to the budget, but span starts /
  lengths and table counts are taken from the header as-is (a misbehaving child can make the
  supervisor panic on a slice bound); fine for a spike, needs validation before hardening.
* **Root-crate hooks are `#[doc(hidden)]`** (`iterator_fuzz::raw`): `RawCase`/`RawSpan`/
  `RawSequence`, `Case::into_raw`/`from_raw`, `CaseRng::fill_budget`/`absorb_trace`/`seed`,
  `sancov::counter_ranges`/`decode_counters`. They are the minimum needed and are listed in the
  commit `0d9cc02`.
* The forkserver image runs instrumented code (the serve loop) before forking, so counters
  inherited by each case child are non-zero; `SancovCoverage::start_capture` in the child zeroes
  them, so this did not show up in `instrumented_target_reports_features`, but the memo's
  "subtract init snapshot" fallback was not needed and is not implemented.

## Deviations from DESIGN.md

* Code lives in `spikes/coverage-bridge/` (per the prototype rules), not behind a `bridge`
  feature in `src/bridge/`; the root crate only gained the hidden raw hooks above.
* fds are passed as fixed numbers (197/198/199 via `pre_exec` `dup2`) plus `COVERAGE_BRIDGE_MODE`
  in the environment, not through `/proc/self/fd` paths.
* Crash handler `_exit`s instead of re-raising (apport cost, above).
* Case children set `PR_SET_PDEATHSIG(SIGKILL)` in addition to the forkserver: an interrupted
  benchmark left a spinning case child reparented to init.
* Verdict cost is carried as a `u64` in the header and converted to `CaseCost` via `usize`.

## Next steps

1. Gate `record_cmp` on `cmp_feedback` in the root crate (or make the callbacks cheaper): it is
   ~600 µs of the ~800 µs child time with trace-compares and the biggest win available.
2. Incremental trace publication so crashes and timeouts shrink as well as failures do.
3. trace-pc-guard live map into shm for the parallel/timeout path; measure `rayon` scaling with
   one forkserver per worker.
4. Use the reserved header words for a second input cursor (syscall-intercept spike) and make
   supervisor-answered events `variant`/`range` spans as the memo describes.
5. Snapshot-ish reuse: keep a warm forked child per corpus seed for `cautious()` where most
   variants share a long prefix.
