# Spike `coverage-bridge`: out-of-process coverage + RNG bridge

Status: design memo, no prototype yet.
Branch: `devin/spike/coverage-bridge` (from `devin/1789863721-linux-rtld-default`).
Machine used for measurements: Linux 6.8.0 (Ubuntu, AWS), x86_64, 8 vCPU, Rust 1.98.1,
`ptrace_scope=1`, `unprivileged_userfaultfd=0`, `perf_event_paranoid=4` (perf needs sudo).

## 0. TL;DR

Recommendation: an **AFL-style forkserver** in which

* the **supervisor** (the process running `curious()`/`cautious()`) owns the whole dowsing
  search state and one `CaseRng` per case, exactly as today;
* the **target binary** is the existing instrumented `buggy_stack` logic linked against a small
  child runtime (`dowsing::bridge::child`). Started once, it initializes, maps a supervisor-created
  `memfd`, and then loops: read a "run" request from a control pipe, `fork()`, and let the forked
  child execute exactly one case;
* the **RNG bridge is a mirror, not an RPC**: the supervisor writes the whole byte budget for the
  case (candidate prefix, then the deterministic tail) into the shared region; the child consumes
  it sequentially through a `CaseRng`-shaped `ChildRng` that records the same draw / semantic /
  sequence spans dowsing records in-process, and writes that trace back into the shared region.
  After the case finishes the supervisor imports the trace into its own `CaseRng`, so
  `fork_case()`, the corpus, mutation and every `cautious()` reducer pass see *exactly* what an
  in-process run would have produced;
* **coverage** is SanitizerCoverage inline 8-bit counters plus the existing comparison callbacks.
  The child copies its counter section and its comparison feature list into the shared region at
  case end (or from a crash signal handler); the supervisor decodes them into
  `ExecutionFeedback` using the same `feature_id` scheme `src/sancov.rs` uses today. A
  `ChildCoverage: CoverageCapture` backend wraps all of this so `with_coverage(...)` is the only
  API change visible to `curious()`/`cautious()`.

Why this and not the "obvious" byte-at-a-time pipe RPC: a pipe round trip costs 7.7 µs here and a
`buggy_stack` case consumes 200–300 RNG bytes, i.e. ~2 ms/case for RPC versus ~0.2 ms for a fork
of a 6 MiB child. The mirror design makes the per-case IPC cost two pipe writes and two small
memcpy's, so the forkserver's per-case floor is the fork itself (measured: 116 µs at 1 MiB RSS,
~340 µs at 10 MiB).

The dowsing search loop itself is currently the bottleneck (≈1.7–3 ms/case with comparison
feedback, 40 % of it sorting `CoverageId`s), so the bridge will *not* be the thing that limits
executions/sec in the demo. That is good news for the spike (the demo will show
forkserver ≈ in-process throughput) and a separate, unrelated optimization opportunity.

## 1. What dowsing does today (the parts the bridge must preserve)

* `curious()`/`cautious()` (`src/iter/api.rs`, `run.rs`) build a `Candidate { seed, prefix,
  zero_tail, origin }` *before* execution, wrap it in a `CaseRng` (`src/iter/rng.rs`) and hand it
  to the harness.
* `CaseRng::next_byte` replays `prefix[cursor]`, then either `0` (`zero_tail`, used by
  `cautious()` and havoc) or `SmallRng::seed_from_u64(seed)` output. Every byte is appended to
  `trace`; `RngCore` draws record `DrawSpan { start, len, kind: Word|Bytes }`; `variant()` and
  the length of `range()` record `SemanticSpan { start, len, kind: Variant|Length|Item }`;
  `range()` additionally records a `SequenceSpan { length span, item spans }`.
* `CaseRng::coverage()/coverage_with_cost()/discard()/Drop` call `finish`, which calls
  `Capture::finish_capture(token)` (or `discard_capture`) and `merge_finished_execution`, which
  updates corpus/energy/coverage with `(trace, draws, semantics, sequences, ExecutionFeedback,
  cost)`.
* `fork_case()` snapshots `(seed, trace, zero_tail, draws, semantics, sequences)` into a `Case`;
  `cautious().with_case(case)` replays it with `zero_tail = true` and runs the reducer passes in
  `src/iter/shrink.rs`, all of which operate purely on the recorded bytes and spans.
* `CoverageCapture` (`src/coverage.rs`) is `start_capture() -> Token`,
  `finish_capture(Token) -> ExecutionFeedback { features: CoverageSet, hit_count_weight,
  dictionary }`, `discard_capture(Token)`. `ParallelCoverageCapture` adds `validate_parallel`.
* `SancovCoverage` (`src/sancov.rs`) is process-local: `__sanitizer_cov_8bit_counters_init`
  registers counter ranges that live in the binary's `__sancov_cntrs` section; `finish_capture`
  reads non-zero counters into `feature_id(EDGE_NAMESPACE, (index << 8) | bucket)` and appends
  `CMP_FEATURES`/`CMP_DICTIONARY` from thread-locals. Trace-pc-guard mode records guard ids into
  thread-locals instead.

Consequence for the bridge: **the child must generate bytes and spans with byte-identical
semantics**, and the supervisor must be able to **inject a trace** into its `CaseRng`. Nothing
else in the crate needs to know a child process exists.

## 2. Measured facts (throwaway C/Rust, this machine)

All numbers are single runs on an otherwise idle 8-vCPU VM; treat them as ±20 %.

| Experiment | Result |
| --- | --- |
| `fork()`+`_exit()`+`waitpid()` with N MiB of touched anonymous RSS | 1 MiB: 104 µs (9.6 k/s); 10 MiB: 297 µs (3.4 k/s); 100 MiB: 2.3 ms (431/s); 500 MiB: 5.5 ms (183/s) |
| `vfork()`+`_exit()` | 23 µs (43 k/s) – but the child cannot run Rust code safely |
| `posix_spawn("/bin/true")`+wait (exec-per-case floor) | 323 µs (3.1 k/s); a real instrumented Rust binary will be several × this |
| Forkserver: supervisor →pipe→ forkserver →`fork()`→ case child →`waitpid`→ status →pipe→ supervisor | 1 MiB: 116 µs (8.6 k/s); 10 MiB: 341 µs; 100 MiB: 2.45 ms. Writes from the case child to an inherited `memfd` `MAP_SHARED` mapping are visible to the supervisor |
| Pipe ping-pong (4 bytes each way) | 7.7 µs per round trip (130 k/s) |
| seccomp `SECCOMP_RET_USER_NOTIF` + `SECCOMP_FILTER_FLAG_NEW_LISTENER`, unprivileged, after `PR_SET_NO_NEW_PRIVS`, listener fd passed to parent over `SCM_RIGHTS` | **works** as uid 1000; supervisor answered `getppid()` with a fake value; 7.65 µs per intercepted syscall (130 k/s) |
| `PTRACE_TRACEME` child, `PTRACE_SYSCALL` + `PTRACE_GETREGS` at each stop | **works** with `ptrace_scope=1`; 15 µs per syscall stop, i.e. 30 µs per traced syscall (entry+exit) |
| `perf record` | refused with default `perf_event_paranoid=4`; works after `sudo sysctl kernel.perf_event_paranoid=1`. rr would need the same |
| Instrumented `buggy_stack`-equivalent (`-Cpasses=sancov-module`, level 3, inline 8-bit counters, pc-table, trace-compares), `curious()` in-process | with cmp feedback: 585 exec/s over 5 k cases, 313 exec/s over 50 k cases (corpus grows); without cmp feedback: 3.3 k exec/s; `NoCoverage`: 146 k exec/s; harness alone: 451 k exec/s; 200–300 RNG bytes per case |
| perf profile of the in-process run (after raising paranoid level) | ≈40 % `core::slice::sort` on `CoverageId` (from `CoverageSet::from_unsorted` / `extend` in `finish_capture`), 6 % `refresh_corpus_energies`, ~9 % hashbrown lookups on `CoverageId`, ~4 % `push_dictionary_value` (linear dedup), ~4 % `__sanitizer_cov_trace_const_cmp8`. The target itself is negligible |
| Instrumented example: `__sancov_cntrs` section | 2 780 counters (0xadc bytes) at 0xeac50, immediately after `.data` and before `__sancov_pcs`; **shares 4 KiB pages with both** |
| Max RSS of the instrumented example | 6 MiB → expected fork cost ≈ 200 µs |

Take-aways:

1. Fork cost is dominated by page-table copy of touched RSS. Keeping the forkserver's RSS small
   (do not build the corpus in the child, do not preallocate big buffers) matters more than
   anything in the protocol.
2. One IPC round trip per RNG *draw* is ruled out (≈2 ms/case). One or two round trips per *case*
   are free relative to fork.
3. Remapping the counter section onto shared memory (AFL's trick for its own map) is unsafe for
   sancov counters as laid out by the linker: the pages also hold `.data` and the pc-table, and a
   `MAP_SHARED` mapping of those pages would leak state from one case child to the next and to the
   supervisor. Copy-out is the safe default; direct-to-shm needs trace-pc-guard or a linker script.
4. seccomp user-notif and ptrace both work unprivileged here, at ≈8 µs and ≈30 µs per intercepted
   syscall respectively. Neither is needed for *this* spike, but the forkserver must not preclude
   them (see §7).
5. The supervisor's own bookkeeping, not the target or IPC, bounds executions/sec today.

## 3. Recommended design

### 3.1 Process topology

```
supervisor (curious()/cautious(), CaseRng, corpus)      target binary
┌───────────────────────────────────────────┐        ┌─────────────────────────────────────┐
│ ChildCoverage: CoverageCapture            │ ctl ►  │ forkserver loop (dowsing::bridge::  │
│ Bridge { ctl_w, st_r, shm, child pidfd }  │ ◄ st   │   child::serve): read req, fork()   │
│                                           │        │      └─► case child: run one case,  │
│ shm (memfd, MAP_SHARED):                  │◄──────►│          export trace+coverage, exit│
│   header | input bytes | trace out | cov  │        └─────────────────────────────────────┘
└───────────────────────────────────────────┘
```

* The supervisor `posix_spawn`s the target binary once with three inherited fds: control pipe
  (read end), status pipe (write end), and the `memfd` (or passes the memfd path
  `/proc/self/fd/N` in an env var, AFL passes `__AFL_SHM_ID`). All other fds are `O_CLOEXEC`.
* `dowsing::bridge::child::serve(|rng: &mut ChildRng| -> Verdict)` is called from the target's
  `main` *after* expensive one-time setup (AFL's "deferred forkserver"). It maps the shm, installs
  crash signal handlers, then loops on the control pipe. Each request: `fork()`; the parent
  (forkserver) `waitpid`s the child with a timeout it enforces via `pidfd`/`poll` or lets the
  supervisor enforce (see 3.5), then writes a status record to the status pipe.
* The case child resets nothing (fresh copy-on-write image every time), runs the harness closure
  with a `ChildRng` over the input area, writes `(consumed, spans, verdict)` and the counter
  section into shm, and `_exit(0)`s. Crashes are caught by `SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT`
  handlers that export whatever has been recorded so far and re-raise with default disposition.
* An **exec-per-case mode** uses the same child runtime with `serve` running exactly one case and
  exiting; the supervisor spawns a fresh process per case. It exists only for the measurement the
  task asks for and as a fallback for targets that cannot be forked.

### 3.2 Shared-memory layout (one `memfd`, 1 MiB default, page-aligned regions)

```
struct Header {            // 64 bytes, written by supervisor except where noted
    magic: u32, version: u32,
    input_len: u32,        // bytes valid in `input`
    zero_tail: u8,         // if the child runs past input_len: 0 => fail InputExhausted, 1 => return 0s
    counters_len: u32,     // child, at init: length of __sancov_cntrs range(s)
    consumed: u32,         // child, per case
    verdict: u32, cost: u64,          // child, per case (Verdict::Ok/Failed(code), CaseCost)
    n_draws: u32, n_semantics: u32, n_sequences: u32, n_cmp: u32, n_dict: u32,  // child
    overflow_flags: u32,   // child: which tables hit their cap
}
input:     [u8; 64 KiB]    // MAX_PREFIX_LEN is 4096 today; budget the tail generously
draws:     [(u32 start, u32 len, u8 kind); N_DRAWS]
semantics: [(u32 start, u32 len, u8 kind); N_SEM]
sequences: [(u32 length_start, u32 length_len, u32 first_item, u32 n_items)]  + item table
cmp_features: [u64; 4096]  // same cap as MAX_CMP_FEATURES today
dictionary:   [(u8 width, [u8; 8]); 256]  // MAX_DICTIONARY_VALUES today
counters:  [u8; counters_len]  // snapshot of __sancov_cntrs, copied at case end / in the crash handler
```

Everything is plain little-endian PODs, so both sides can be `#[repr(C)]` Rust structs; no serde.
Tables are capped and the child sets `overflow_flags` instead of writing past the end; the
supervisor then treats the case as `ProtocolError` (discarded, counted in stats).

### 3.3 The RNG bridge (mirror model)

Per case, the supervisor:

1. Takes the yielded `CaseRng` and asks it for its *budget*: `prefix` followed by enough fallback
   bytes to fill `input` (or zeros when `zero_tail`). This requires a new crate-internal method
   `CaseRng::fill_budget(&mut self, out: &mut [u8]) -> usize` that runs the same `next_byte`
   logic but does **not** push to `trace`/`draws` (it is a peek). `SmallRng` is cheap; 64 KiB per
   case is ~10 µs — acceptable, but the prototype should start with a 16 KiB budget and grow only
   if `InputExhausted` shows up.
2. Writes the header + input, writes a 4-byte request to the control pipe, reads a status record
   (`pid`, `wait status`, `wall time`) from the status pipe (with `poll` timeout, see 3.5).
3. Imports the child's trace: `CaseRng::absorb_trace(RawTrace { consumed, draws, semantics,
   sequences })`, which sets `trace = input[..consumed]`, `cursor = bytes_consumed = consumed`,
   and copies the spans (clamped to `MAX_PREFIX_LEN` exactly as `record_draw`/`mark_semantic`
   clamp today). After this the supervisor's `CaseRng` is indistinguishable from one that
   executed the harness in-process.
4. Finishes the case as the harness would: `rng.coverage_with_cost(cost)` for `Ok`/`Failed`,
   `rng.discard()` for `Discard`, and a configurable policy for `Crash`/`Timeout` (default: treat
   as `Failed` with a large cost so `cautious()` keeps reproducing it; `curious()` records the
   coverage collected before the crash).

In the child, `ChildRng` implements `rand::RngCore` plus `variant()`/`range()` with the same
semantics as `CaseRng` (`variant` = `next_u32() as u16 % upper` recorded as `SemanticKind::Variant`,
`range` = `Length` span + one `Item` span per yielded element + a `SequenceSpan`). The cleanest
way to guarantee identical semantics is to make it *the same type*: `CaseRng<Capture>` already
has `local_capture: Option<Capture>` and a `shared` state that is never touched until `finish`;
the child can construct `CaseRng<NoCoverage>` from `(seed, input, zero_tail)` via the existing
(currently `#[cfg(test)]`) `Case::from_raw_parts` + `Case::replay()`, and at the end read its
`trace/draws/semantics/sequences` through a `pub(crate)`/doc-hidden accessor. Then the harness
closure signature in the child is literally `FnMut(&mut CaseRng<NoCoverage>) -> Verdict`, and the
*same* `sample()`/`check_stack()` from `examples/buggy_stack.rs` compiles unchanged in both
processes. This is the option to try first; a separate `ChildRng` type is the fallback if the
`Rc<RefCell<..>>` in `RangeIter` or the `Drop` impl get in the way.

Why not send `seed` and let the child run `SmallRng` itself? It works (same crate version on
both sides) but couples the child to `rand`'s `SmallRng` algorithm and makes "input exhausted"
impossible to detect; the prefilled buffer is simpler and gives the supervisor full control.

### 3.4 Coverage channel

Inline 8-bit counters (the serial recipe from the README) are the default:

* The child runtime's `__sanitizer_cov_8bit_counters_init(start, end)` records the range(s) (LLVM
  calls it once per module; concatenate ranges in order, exactly as `sancov.rs` does) and writes
  `counters_len` into the header at forkserver init. The supervisor validates
  `counters_len <= capacity` once.
* No reset is needed in the forkserver path: each case child starts from the forkserver's image,
  whose counters are frozen after init (the forkserver runs no instrumented code between forks;
  `serve` must be careful not to call into instrumented crates in its loop — build the runtime
  into the child as `#[inline(never)]`, or accept a constant background of a few counters and
  subtract the init snapshot). Exec-per-case gets a fresh image for free.
* At case end, `memcpy(shm.counters, cntrs_start, len)`; 2.8 KiB for `buggy_stack`, well under a
  microsecond. The crash handler does the same copy and then re-raises.
* Comparison feedback: the existing `__sanitizer_cov_trace_(const_)cmpN` callbacks are kept, but
  in the child they push into a fixed-capacity array inside shm (`cmp_features`, `dictionary`)
  instead of thread-local `Vec`s. Same `cmp_hash` and `push_dictionary_value` rules so the
  feature ids match `SancovCoverage`.
* `ChildCoverage::finish_capture` decodes: for each non-zero counter byte
  `feature_id(EDGE_NAMESPACE, (index << 8) | hit_count_bucket(v))`, `hit_count_weight += 1 +
  bucket`, then appends `cmp_features` and copies `dictionary`. This is a copy of
  `counter_coverage()` reading from shm instead of the section; refactor `sancov.rs` so both call
  one `decode_counters(&[u8]) -> ExecutionFeedback`.

Trace-pc-guard as the parallel-capable alternative: `__sanitizer_cov_trace_pc_guard(guard)`
does `shm.map[*guard as usize] += 1` (AFL++'s pc-guard mode, LibAFL's `sancov_pcguard`), so
the map lives in shm from the start and nothing needs copying, at the cost of a call per edge.
Because dowsing already supports guard mode for parallel runs, `ChildCoverage` should accept
either map format (header flag); the prototype implements counters first.

Why not the LLVM `-Cinstrument-coverage` backend (`src/llvm.rs`)? Its counters are 64-bit,
larger, spread across `__llvm_prf_cnts`, and found via `dlsym`; nothing prevents copying them
out too, but sancov gives comparison feedback and is the README's recommended path. Keep it as
a later `LlvmChildCoverage` if needed.

### 3.5 Outcomes, timeouts, crashes, deadlocks

| Child outcome | Detection | Supervisor action |
| --- | --- | --- |
| `Ok` / `Failed(code)` / `Discard` | `verdict` in header, exit status 0 | `coverage_with_cost` / `discard` |
| Crash (SIGSEGV, SIGABRT from `panic=abort` or `abort()`, …) | `WIFSIGNALED` in status record; coverage exported by handler (`counters`, cmp tables, `consumed`) | record as `Failed` with `CaseCost::new(usize::MAX/2)` (configurable); expose `Outcome::Crashed(signal)` to the harness |
| Timeout | supervisor `poll`s the status pipe with `per_case_timeout`; on expiry sends `SIGKILL` via the forkserver (`req = Kill`) or directly to the child pid (the forkserver reports the pid in the status record *before* waiting, as AFL does) | discard by default (coverage is partial), or record as `Failed` in a "hang-hunting" mode |
| `InputExhausted` | `verdict` | discard; grow budget for the next attempt of the same candidate |
| Protocol error / forkserver died | `EPIPE`/EOF on pipes, `pidfd` readable | tear down, respawn the forkserver once, then surface `Err(String)` through `finish_capture` so `curious()` stops with a message |
| Forkserver stuck | supervisor holds a `pidfd` on it and puts `PR_SET_PDEATHSIG(SIGKILL)` in the child so a dying supervisor does not leave orphans | kill + respawn |

Deadlock avoidance rules (learned the hard way even in the throwaway benchmark, which hung
because the child kept the parent's write end of the control pipe open):

* Every pipe end that a process does not use is closed immediately after `fork`/`spawn`;
  `O_CLOEXEC` on everything the supervisor creates except the three deliberately inherited fds.
* Fixed-size, single-write records only (4-byte request, 16-byte status), so there is never a
  partial read to reassemble and never a write that blocks on a full pipe.
* The supervisor never blocks without a timeout; the forkserver never blocks on anything but
  the control pipe and `waitpid`.
* Stdout/stderr of the child are redirected to a per-run log file (or `/dev/null`); a chatty
  child that fills a pipe nobody drains is the classic forkserver hang.
* The child must not `exit()` through Rust's normal teardown (which runs `atexit` and flushes
  stdio, and, worse, with `panic=unwind` can unwind into `serve`); use `libc::_exit` after export.
* One forkserver per `ChildCoverage` instance; the parallel path (`ParallelCoverageCapture`)
  clones the backend and each clone spawns its own forkserver + shm, so there is no sharing to
  synchronize.

### 3.6 Determinism and replay

* Byte stream: fully determined by `(seed, prefix, zero_tail)` on the supervisor side; the
  child never generates randomness. Replaying a `Case` in the child is the same as replaying it
  in-process, so `Case::replay()` continues to work for in-process debugging of a bug found
  out-of-process (the demo should do exactly this as a sanity check).
* Coverage: fork gives an identical initial image every case, which removes the
  order-dependent noise an in-process loop has (allocator state, lazy statics). Remaining
  nondeterminism comes from ASLR (irrelevant to counter *indices*, which are section offsets),
  time/entropy syscalls in the target (out of scope here; the `syscall-intercept` spike will
  route them through the same `CaseRng` — see §6), and threads (out of scope; the
  `deterministic-scheduling` spike).
* Environment: the supervisor sets `personality(ADDR_NO_RANDOMIZE)` for the target when asked
  (helps reproducing crash addresses), pins `RUST_BACKTRACE=0`, and clears the environment
  except for an allow-list.

## 4. How it plugs into the dowsing API

Crate changes (all additive, behind a `bridge` cargo feature, Linux-only):

1. `src/coverage.rs` — no change. `ChildCoverage` implements `CoverageCapture` with
   `Token = CaseSlot` (index of the pending case; only one is pending per backend instance) and
   `ParallelCoverageCapture` (`validate_parallel` checks that the instance is `Clone`-spawnable).
2. `src/iter/rng.rs` — add `pub(crate) fn fill_budget(&mut self, out: &mut [u8]) -> usize` and
   `pub(crate) fn absorb_trace(&mut self, trace: RawTrace)`; expose both through
   `dowsing::bridge` as `#[doc(hidden)]` helpers so the bridge can live in its own module
   without leaking `pub(super)` fields. Also `pub(crate) fn raw_trace(&self) -> RawTrace` for
   the child side.
3. `src/iter/prelude.rs` — promote `Case::from_raw_parts` from `#[cfg(test)]` to
   `pub(crate)`/feature-gated so the child can build its replay `CaseRng<NoCoverage>`.
4. `src/sancov.rs` — factor `decode_counters(&[u8]) -> ExecutionFeedback` out of
   `counter_coverage`, and make `record_cmp`'s sinks pluggable (thread-local `Vec`s today, fixed
   shm arrays in the child). The child runtime provides its own
   `__sanitizer_cov_8bit_counters_init`/`trace_pc_guard_init`, so a target must link *either*
   `SancovCoverage` *or* `bridge::child`, never both (enforce with a feature or a separate
   `dowsing-child` crate; the latter also keeps the supervisor's corpus code out of the child's
   RSS).
5. New module `src/bridge/` (see §7 for files).

Supervisor-side usage, i.e. what the demo's `main` looks like:

```rust
let bridge = ChildCoverage::spawn(ChildConfig::forkserver("target/.../buggy_stack_child"))?;
let mut found = None;
for rng in curious().with_coverage(bridge.clone()).take(DISCOVERY_CASES) {
    let outcome = bridge.run(rng)?;           // ships budget, waits, absorbs trace, finishes rng
    if let Outcome::Failed { case, .. } = outcome { found = Some(case); break; }
}
let mut best = found.unwrap();
for rng in cautious().with_coverage(bridge.clone()).with_case(best.clone()).take(MINIMIZATION_CASES) {
    match bridge.run(rng)? {
        Outcome::Failed { case, .. } => best = case,   // cautious() already prefers shorter cases
        _ => {}                                        // bridge.run() called rng.discard()
    }
}
```

`bridge.run(rng)` is the only new verb: it takes the `CaseRng` by value, does steps 1–4 of §3.3
and returns `Outcome { verdict, case: Case, coverage: CaseCoverage, wall: Duration }`. Because it
calls `coverage_with_cost`/`discard` itself, `curious()`'s corpus/energy logic and `cautious()`'s
reducer see the run as an ordinary in-process case. The harness stays free to call
`rng.fork_case()` before `run` if it wants the pre-execution candidate.

Child-side usage:

```rust
fn main() {
    // one-time setup here (deferred forkserver): parse config, warm caches, etc.
    dowsing::bridge::child::serve(|rng| {
        let ops = sample(rng);                       // unchanged from examples/buggy_stack.rs
        match check_stack(&ops) {
            Ok(()) => Verdict::Ok,
            Err(e) => Verdict::failed(1).with_cost(ops.len()),
        }
    });
}
```

`serve` never returns in forkserver mode (the forkserver `_exit`s when the control pipe hits
EOF); in exec-per-case mode it runs once and `_exit`s.

### 4.1 Which choices must be `range`/`variant` spans

`cautious()` can only reduce what it can *see* as structure. For the bridge itself:

* Everything the child draws goes through `CaseRng`, so the child harness should follow the
  README guidance: `rng.range(0..=MAX_OPS)` for the operation list (so sequence deletion /
  projection passes can drop operations), `rng.variant(N)` for the operation kind (so the
  simplify pass can lower `Restore`/`Reverse`/`Pop` to `Push`), plain `next_u32`/`fill_bytes`
  for payload values (so word/byte lowering applies). The current `sample()` in
  `examples/buggy_stack.rs` uses a raw byte for the length and a raw byte for the op kind;
  the child demo should switch to `range`/`variant` and the memo's demo should show the shrunk
  case being as small as the in-process one.
* Bridge-level decisions must **not** consume RNG bytes: budget size, timeout, whether to
  respawn, exec vs fork. If they did, they would perturb the byte stream and defeat replay.
* Looking ahead (other spikes plug in here): every *supervisor-answered* nondeterministic event
  should be a draw on the same `CaseRng` so `cautious()` shrinks it — `variant` for
  "which of the runnable threads runs next", "does this `read` return data/EOF/EAGAIN", "which
  fault to inject"; `range` for "how many bytes does this `recv` deliver", "how many ticks does
  `clock_gettime` advance", with the payload bytes as plain draws. The forkserver protocol should
  therefore reserve a second input cursor ("environment stream") in the shm header now, so the
  syscall-intercept spike can consume from the same budget without re-framing the protocol.

## 5. Alternatives considered and rejected

| Alternative | Why not (for this spike) |
| --- | --- |
| **RPC per draw** (child asks supervisor for bytes over a pipe / eventfd / futex ring) | 7.7 µs per round trip × 200–300 draws ≈ 2 ms/case, 10–20× the fork cost. Speculative prefetch would reinvent the mirror model with more moving parts. |
| **Child runs `SmallRng(seed)` itself** | Works, but couples child to `rand`'s algorithm/version, cannot detect budget exhaustion, and the supervisor would still need the consumed bytes back. Prefilled input is strictly simpler. |
| **Remap `__sancov_cntrs` pages onto shm (`mmap(MAP_FIXED|MAP_SHARED)`)** | Measured layout: the counters share pages with `.data` and `__sancov_pcs`. Sharing those pages leaks mutable globals across case children and into the supervisor. Fixable with a linker script that page-aligns the section, but copy-out costs <1 µs and needs no toolchain changes. Revisit for very large targets (MBs of counters) where the copy shows up. |
| **Trace-pc-guard writing straight into shm as the *only* mode** | Per-edge call overhead; the README's serial recipe is inline counters; dowsing's hit-count buckets come from counters. Kept as the second map format for parallel runs. |
| **AFL++ persistent mode (`__AFL_LOOP`) without fork** | Fastest, but the target must be side-effect free between iterations, which is precisely the property the wider project refuses to assume (no mocks, real files/sockets). Fork gives a clean image per case. It could be an opt-in later for pure targets. |
| **In-process fork from the supervisor** (LibAFL's `InProcessForkExecutor`: fuzzer and target in one binary, `fork()` per case) | Fork cost scales with the *supervisor's* RSS (corpus + coverage sets, tens of MiB → ms per fork, measured 2.3 ms at 100 MiB), the target's instrumentation would also instrument dowsing itself, and it blocks the sandboxing spikes, which need the target in a separate address space. |
| **`vfork`/`clone(CLONE_VM)`** | 23 µs vs 104 µs, but the child cannot run Rust code or touch memory safely; gains nothing once the fork is ~5 % of the case budget. |
| **Threads instead of processes** | No crash isolation, no address-space reset, no syscall interception boundary. |
| **ptrace-driven supervisor** (stop the child at each syscall, inject RNG via registers) | Works unprivileged (measured 30 µs/syscall), but it is the wrong tool for RNG delivery and would make the child single-stepped for no benefit here. It remains the fallback for the syscall-intercept spike where seccomp-notif cannot rewrite results in place (notif can only return `val/errno` or `ADDFD`; writing into the tracee's buffers needs `process_vm_writev` on the `pid` from the notification, which should work given the supervisor already has ptrace rights over its child — to be verified in that spike). |
| **seccomp user-notif as the RNG channel** (child calls `getrandom`, supervisor answers) | Also works unprivileged (7.65 µs/call) and is exactly what the entropy-interception spike will use, but as the primary RNG channel it is RPC-per-draw again. |
| **Snapshot/restore instead of fork** (AFL++ snapshot LKM, CRIU, userfaultfd-based) | No CRIU installed, `unprivileged_userfaultfd=0`, snapshot LKM needs a kernel module; fork *is* the snapshot for a single-threaded target and costs 100–300 µs. The snapshot/rewind spike should build on a forked child (fork-at-checkpoint tree), not replace fork. |
| **Full-VM (Nyx/kAFL, Antithesis-style hypervisor)** | Excluded by the task (no KVM). |
| **rr-style record/replay for determinism** | Needs `perf_event_paranoid ≤ 1` (default here is 4; changed only with sudo), serializes threads, and solves replay, not coverage/RNG delivery. Relevant later for the scheduling spike as prior art, not as a dependency. |
| **Serialize `Case` and shell out per case (`Command::new(target).arg(case)`)** | The exec-per-case floor is 323 µs for `/bin/true`; a Rust binary with instrumentation init is several × that, and it is *still* required as the baseline measurement, so it is implemented, just not recommended. |

## 6. Risks and unknowns

1. **`CaseRng` reuse in the child.** `RangeIter` holds `Rc<RefCell<&mut CaseRng>>` and
   `CaseRng: Drop` calls `finish`, which locks `shared`. Constructing a `CaseRng<NoCoverage>`
   in the child via `Case::replay()` gives a throwaway `Engine` whose `State` is never
   observed, so this should be fine, but the child must call `std::mem::forget` or read the trace
   before drop and must not let `finish` do meaningful work. If this gets awkward, fall back to a
   standalone `ChildRng` that duplicates ~150 lines of `rng.rs`. Mitigation: try it first in the
   prototype's step 2 and decide within an hour.
2. **Forkserver image pollution.** Any instrumented code executed by the forkserver loop between
   forks (allocator via `Vec` growth, `std::io` in the loop) bumps counters that every child then
   inherits. Mitigation: snapshot counters after init, subtract per case; keep the loop
   allocation-free (`libc::read`/`write`, fixed buffers).
3. **Panics in the child.** With the default `panic=unwind`, a panic inside the harness closure
   unwinds into `serve`; `catch_unwind` there maps it to `Verdict::Failed`. With `panic=abort`,
   `SIGABRT` is caught by the export handler. Rust's default panic hook prints to stderr — must
   be redirected. `std::process::exit` inside the target bypasses export (AFL has the same
   blind spot); document it.
4. **Comparison feedback volume.** `MAX_CMP_FEATURES = 4096` `u64`s + dictionary per case is
   ~40 KiB of shm writes per case in the worst case; still cheap, but the *supervisor-side* cost
   of sorting/deduping them dominates today (perf: ~40 % in sort). Not a bridge problem, but the
   demo's exec/s will be bounded by it; report both "bridge overhead" (wall time inside
   `bridge.run` minus supervisor bookkeeping) and end-to-end exec/s.
5. **Timeouts.** A `SIGKILL`ed child exports nothing. If hang detection matters, use
   trace-pc-guard (live map) or a `SIGALRM`-in-child export path. Prototype: supervisor-side
   timeout, discard, count.
6. **Fork cost growth.** Targets with large heaps (100 MiB → 2.3 ms/fork) lose the advantage;
   that is where snapshot-based approaches or `MADV_DONTFORK` on cold regions come in. Out of
   scope, but `bridge.run` should expose per-phase timings so it is visible.
7. **Zombie/orphan hygiene.** `PR_SET_PDEATHSIG` is per-thread-of-parent semantics (it fires
   when the *thread* that forked dies); the supervisor must spawn from a long-lived thread or use
   a `pidfd` + `poll` watchdog instead. Use both.
8. **`memfd_create` + `SCM_RIGHTS` vs env var.** Passing `/proc/self/fd/N` in the environment
   is simplest; it requires `/proc`. Fine locally; note for future sandboxing (a `pivot_root`ed
   child may not see `/proc`): pass the fd number itself, not a path.
9. **Feature id compatibility.** Counter *indices* are section offsets; if the supervisor ever
   mixes in-process and child coverage sets (it should not), ids would collide with different
   meanings. `ChildCoverage` is a distinct backend so the search state never mixes them.
10. **Unknown: true exec-per-case cost of an instrumented Rust binary.** `/bin/true` is 323 µs;
    Rust std init plus sancov init and the child runtime's `mmap` could be 0.5–2 ms. This is one
    of the numbers the prototype measures.
11. **Unknown: `sancov-module` pass + `-Cinstrument-coverage`-style counters for *only* the target
    crate.** The example currently instruments dowsing's own `iter` code too (perf shows
    `__sanitizer_cov_trace_const_cmp8` from the supervisor side). In the child binary that is
    fine (dowsing's rng code is part of the "target" and just adds a few constant edges) but the
    supervisor binary must **not** be built with the sancov pass or `SancovCoverage` linked, or it
    will record its own comparisons. Two build targets, two recipes; document them in the demo.

## 7. Prototype plan

### 7.1 Files

```
Cargo.toml                       feature `bridge` (Linux only); add the `libc` crate (currently only rand + rayon)
src/bridge/mod.rs                pub use; shared #[repr(C)] protocol structs + consts (ShmHeader, Request, Status, Verdict, RawTrace)
src/bridge/shm.rs                memfd_create/ftruncate/mmap wrapper, region offsets, bounds-checked views
src/bridge/supervisor.rs         ChildCoverage (CoverageCapture + ParallelCoverageCapture), Bridge::spawn/run/kill, timeouts, respawn
src/bridge/child.rs              serve(): shm attach, sancov init hooks (8-bit counters + trace-pc-guard + cmp sinks), fork loop, export, crash handlers, _exit
src/bridge/decode.rs             decode_counters/decode_guards/decode_cmp -> ExecutionFeedback (shared with sancov.rs)
src/iter/rng.rs                  + fill_budget, absorb_trace, raw_trace (pub(crate), re-exported doc-hidden)
src/iter/prelude.rs              Case::from_raw_parts un-gated (pub(crate))
src/sancov.rs                    counter_coverage -> bridge::decode::decode_counters
examples/buggy_stack_child.rs    target: serve(|rng| ...) using sample()/check_stack() moved into examples/buggy_stack_common.rs (or duplicated, if example modules are awkward)
examples/buggy_stack_bridge.rs   supervisor demo: spawns the child binary in forkserver or exec mode, runs curious() then cautious(), prints stats + exec/s
spikes/coverage-bridge/DESIGN.md this memo
spikes/coverage-bridge/RESULTS.md measurements (added by the prototype)
tests/bridge.rs                  integration test gated on cfg(target_os = "linux") + feature; builds the child via the sancov recipe in a build step or skips if not instrumented
```

### 7.2 Steps (each independently checkable; ≈ one session total)

1. **Protocol + shm** (`mod.rs`, `shm.rs`): `#[repr(C)]` structs, `memfd` region, unit tests
   for offsets/caps. Half an hour.
2. **Child RNG** (`child.rs` part 1): build `CaseRng<NoCoverage>` from `(seed, input,
   zero_tail)` via `Case::from_raw_parts().replay()`, run a closure, extract `RawTrace`. Unit
   test: in one process, run `sample()` through a `CaseRng` from `curious()` and through the
   child path with the same budget; assert identical `Case`s. This test decides risk #1.
3. **Supervisor RNG** (`rng.rs` + `supervisor.rs` part 1): `fill_budget` / `absorb_trace`; unit
   test: absorb a trace and check `fork_case()` equals the in-process `Case`.
4. **Forkserver loop** (`child.rs` part 2, `supervisor.rs` part 2): spawn, handshake (child
   writes `counters_len` + `magic`), request/status records, `poll` timeout, `SIGKILL`, respawn.
   Test with an uninstrumented dummy child (`examples/bridge_echo_child.rs`) that just consumes N
   bytes and returns a verdict; assert exec/s > 3 k at 1–6 MiB RSS.
5. **Coverage export + decode** (`child.rs` part 3, `decode.rs`): sancov init hooks, cmp sinks
   in shm, `memcpy` at export, crash handlers; refactor `sancov.rs` to share `decode_counters`.
   Test: instrumented `buggy_stack_child`, run one case in-process with `SancovCoverage` and via
   the bridge with the same `Case`; assert `ExecutionFeedback.features` are equal (they should
   be, modulo forkserver-image pollution — risk #2; the test tells us).
6. **`ChildCoverage: CoverageCapture`** and `bridge.run()`: wire `finish_capture` to decode the
   pending slot; `discard_capture` to nothing. `ParallelCoverageCapture` via `Clone`-spawns.
7. **Demo** (`buggy_stack_bridge.rs`): forkserver mode → `curious()` finds the restore-orientation
   bug, `cautious()` shrinks it, print the shrunk ops and `Case::replay()` it in-process to
   confirm. Then `--mode exec` for the baseline.
8. **Measure and write `RESULTS.md`**.

### 7.3 Demo target

`examples/buggy_stack.rs` logic (model `VecDeque` + spill vs. `Actual` with the deliberate
`Restore`-does-not-restore-`reversed` bug), moved to a shared module and built twice:

* `buggy_stack_child` — instrumented with the README's serial sancov recipe, links
  `dowsing::bridge::child`, no `SancovCoverage`.
* `buggy_stack_bridge` — **not** instrumented, links `dowsing` with `feature = "bridge"`, runs
  `curious()`/`cautious()` with `ChildCoverage`.

`sample()` is upgraded to `rng.range(0..=MAX_OPS)` + `rng.variant(4)` so the shrink result is
comparable to the README's structured example.

### 7.4 Measurements (all in `RESULTS.md`, same machine class, 3 runs each)

1. exec/s, forkserver vs exec-per-case vs in-process `SancovCoverage`, for `curious()` over
   8 192 cases with and without cmp feedback. Also `NoCoverage` in-process as the ceiling.
2. Per-phase breakdown inside `bridge.run` (fill budget, pipe wait, absorb, decode) from
   `Instant` timers, and forkserver-only round trip with a no-op case (the protocol floor).
3. Fork cost vs child RSS by having the child touch 1/10/100 MiB at init (confirms the
   `forkbench` curve in the real binary).
4. Time-to-bug and cases-to-bug for `curious()` (seeded, 10 seeds) in-process vs bridge; they
   should be statistically indistinguishable, which is the correctness signal that the RNG mirror
   is faithful.
5. Shrink quality: `cautious()` from the found case, 4 096 cases, final `prefix.len()` and ops
   count in-process vs bridge (should be identical for identical seeds).
6. Crash path: a variant of the child that `abort()`s on the bug; confirm the crash is recorded
   with coverage and shrinks.
7. Timeout path: a variant that loops forever on a specific op sequence; confirm detection,
   `SIGKILL`, respawn-free continuation, and exec/s impact.

## 8. Prior art consulted (what was taken from each)

* **AFL / AFL++ forkserver**: control/status pipes on fixed fds, shm map via environment,
  deferred init (`__AFL_INIT`), persistent loop (`__AFL_LOOP`), reporting the child pid before
  waiting so the fuzzer can kill on timeout, and its pc-guard instrumentation writing into the shm
  map. Taken: the whole process topology and the timeout protocol. Not taken: persistent mode as
  default, its own compiler pass (we use upstream sancov).
* **LibAFL**: `ForkserverExecutor` (AFL-compatible), `InProcessForkExecutor` (fork from the
  fuzzer process), `libafl_targets` `sancov_8bit`/`sancov_pcguard`/cmplog runtimes, observers
  backed by `ShMem`. Taken: keeping the coverage observer as a plain shared byte map decoded by
  the fuzzer; the distinction between fork-from-fuzzer and separate-forkserver, and why the latter
  fits a sandboxing roadmap.
* **rr**: ptrace + seccomp-bpf to avoid stopping on untraced syscalls, in-process "syscallbuf"
  to batch syscall recording, retired-branch perf counters for replay scheduling, one runnable
  thread at a time. Taken: the reminder that ptrace per syscall is ~30 µs and that perf counters
  are gated by `perf_event_paranoid` here. Deferred to the scheduling/snapshot spikes.
* **gVisor systrap**: as I understand it, seccomp `SIGSYS` traps in a stub process plus a
  shared-memory message region to the sentry, replacing the older ptrace platform for speed. Taken: seccomp-notif/`SIGSYS`-style
  interception is viable unprivileged (measured 7.65 µs per intercepted syscall) and cheap enough
  for the syscall-intercept spike; the forkserver design leaves the child's seccomp filter and a
  notif fd slot to be added without changing the protocol.
* **Nyx / kAFL**: hypervisor snapshot fuzzing with an agent protocol; excluded by the no-KVM
  constraint, but their "agent reports crash/timeout/coverage via shared pages" protocol is the
  same shape as the shm header here.
* **Shuttle / Loom**: deterministic scheduling of Rust concurrency via shimmed primitives and a
  scheduler driven by a random/exhaustive choice sequence. Taken: scheduling decisions must be
  choices drawn from the same byte stream so shrinking applies (§4.1).
* **Antithesis**: whole-system deterministic hypervisor with snapshot/branch exploration;
  motivational only, excluded by scope.
* **Hypothesis / proptest shrinking**: Hypothesis's choice-sequence ("conjecture") model, where
  every decision is a draw from a byte stream and shrinking operates on that stream with
  structure hints, is exactly dowsing's model; the memo's insistence that the child's byte
  consumption order and spans be identical to in-process is what keeps that property. proptest's
  value-tree shrinking does not apply directly.

## 9. Throwaway experiment inventory (not committed)

* `forkbench.c` — fork/vfork/spawn/pipe/forkserver timings at a given touched RSS, plus
  inherited-`memfd` visibility check (`~/spike-exp/forkbench.c` on the measurement box).
* `notif.c` — unprivileged seccomp user-notif round trip and throughput.
* `ptr.c` — `PTRACE_TRACEME` + `PTRACE_SYSCALL` stop cost.
* `examples/tmp_throughput.rs` (deleted) — in-process `curious()` throughput with/without cmp
  feedback, `NoCoverage`, and raw harness; used with `perf record` after
  `sudo sysctl kernel.perf_event_paranoid=1`.
* `readelf -SW` on the instrumented example for the `__sancov_cntrs` layout.

## 10. What the prototype changed (post-implementation notes)

Written after building the prototype in `spikes/coverage-bridge/`; see its `README.md` for the
measurements. Where the built thing differs from §3–§7, this section is authoritative.

* **Location.** Everything lives in the standalone `spikes/coverage-bridge` crate (prototype
  rules) instead of `src/bridge/` behind a `bridge` feature. The root crate only gained hidden
  hooks: `Case::into_raw`/`from_raw` + `RawCase`/`RawSpan`/`RawSequence`,
  `CaseRng::fill_budget`/`absorb_trace`, and `sancov::{counter_ranges, decode_counters}`
  (re-exported as `iterator_fuzz::raw`).
* **Crash handler exits instead of re-raising.** §3.4 planned "export counters, then re-raise so
  the exit status carries the signal". Re-raising hands the child to the kernel core-dump pipe
  (`apport` on Ubuntu, `core_pattern=|/usr/share/apport/apport ...`), which cost ~40 ms per crashing
  case. The handler now writes the signal number into the header and `_exit(128 + sig)`s; the
  supervisor takes `Status::Crashed` from the header. Crashing cases now cost ~0.3–0.4 ms (a
  2048-case `cautious()` run on an aborting harness takes 2.3 s). The information lost is only a core file, which the
  supervisor never wanted.
* **Child decodes its own features.** §3.4 had the child export raw counters and cmp features
  separately and the supervisor decode both. The child instead wraps the case in the base crate's
  `SancovCoverage` (reset at `start_capture`, `finish_capture` at case end) and exports the
  decoded `ExecutionFeedback` (features + dictionary) *and* the raw counter bytes. Reusing
  `SancovCoverage` in the child guarantees feature-id equality with in-process runs for free
  (risk 9 in §6) and left the "subtract init snapshot" fallback for forkserver-image pollution
  (risk 2) unnecessary: the reset at case start discards whatever the serve loop bumped. Raw
  counters are still exported so crash cases (where `finish_capture` never runs) get edge
  coverage via `decode_counters` in the supervisor.
* **The cmp callbacks dominate, not the bridge.** With `-sanitizer-coverage-trace-compares` the
  harness takes ~620 µs in the child versus ~25 µs with edge counters only, because
  `sancov::record_cmp` hashes and records every comparison while a capture is active regardless
  of `with_cmp_feedback`. §2.4's "supervisor bookkeeping is the bottleneck" holds for the
  in-process run (324 exec/s); for the bridge the supervisor is uninstrumented, so the forkserver
  reaches 842 exec/s with cmp feedback and 3 468 exec/s with edge counters only (protocol floor
  for this target: 3 723 exec/s uninstrumented, 4 762 for the tiny echo target).
* **fd passing.** Fixed fd numbers 197/198/199 (`dup2` in `pre_exec`) plus `COVERAGE_BRIDGE_MODE`
  in the environment; no `/proc/self/fd` paths (risk 8).
* **PDEATHSIG on case children too.** Each forked case child sets `PR_SET_PDEATHSIG(SIGKILL)` and
  checks `getppid() == 1`, after an interrupted benchmark left a spinning case reparented to init.
* **Budget exhaustion is a retry, not a failure.** If the child runs past `input_len` the
  supervisor doubles the budget (up to the input table cap) and re-runs the case from the same
  `CaseRng`; `fill_budget` is deterministic so the retry consumes the same prefix.
* **Not built:** trace-pc-guard as second format, SIGALRM-in-child coverage for timeouts,
  incremental trace publication for crash shrinking, pidfd watchdog (poll on the status pipe +
  PDEATHSIG was enough), `rayon` parallel measurement. All listed as next steps in the README.
