# Spike `shrink-quality`: why `cautious()` stalls on `buggy_stack`, and how to fix it

Status: design memo, followed by the prototype on this branch. Branch `devin/spike/shrink-quality`,
based on `devin/1789863721-linux-rtld-default` (`84b80ef`). Sections 1–6 are the original memo;
§7 records where the prototype deviated from it and why. Final numbers are in `RESULTS.md`, build
and run commands in `README.md`.

## TL;DR

`examples/buggy_stack.rs` reports a 20–55 op "minimized" failure (up to 264 RNG bytes) for a
bug whose smallest reproducer is 5 ops. Measured on this machine (10 seeds, 4096-case
minimization budget, ASLR disabled for reproducibility), the stall has **three independent
root causes**, in order of impact:

1. **Reducer pass order + restart policy starve the deletion passes.** `REDUCER_PASSES`
   runs `DrawLength` (set *every* draw to each of ~27 small targets, 3 widths) before
   `TailTrim`/`DrawDelete`. On a ~62-draw prefix that is thousands of candidates, and every
   improvement — including cosmetic ones that only lower `features`/`nonzero_bytes` —
   resets `pass_index` to 0. Trace of seed 4: **4096/4096 executions were `DrawLength`
   candidates**; not a single deletion was ever tried. The only ops removed were the tail,
   one op per ~21 candidates, via the `word - 1` target on the length draw.
2. **Byte-granular length adjustment on draw-granular deletions.** `DeleteRange { adjust_first:
   true }` subtracts the deleted *byte count* from the first word. When the first draw is a
   length (`u8 % 80`) and each item is one 4-byte draw, deleting one draw subtracts 4 from a
   length that should drop by 1, so the surviving ops are re-interpreted and the failure
   disappears. The reducer has no structure telling it "one op = 1 draw, or 2 for `Push`".
3. **The example does not use the API it is demonstrating.** `sample()` uses
   `rng.random::<u8>() % 80` / `% 7` / `% 16` instead of `range`/`variant`, so no sequence or
   variant spans are recorded and the semantic passes (`SequenceDelete`, `SemanticSimplify`,
   …) generate zero candidates. It also uses `coverage()` (neutral cost) so `MinPathScore`
   orders on `features` before `bytes` — which prefers a 6-op case with 682 features over a
   5-op case with 722 features (seen on 9/10 seeds in the structured-without-cost run).

Secondary findings: the cautious havoc fallback contributes nothing here (deterministic passes
alone reach the same result); value-hashed `cmp` features include pointer comparisons and make
results ASLR-dependent (identical seed gives 5 vs 6 ops across runs) — disable ASLR when
measuring and fix in a follow-up; `DictionaryRepair` and `WordLower` burn budget without ever
improving.

**Recommendation:** fix both sides. (a) In the example: `range(0..80)` + `variant(7)` +
`variant(16)` + `coverage_with_cost(ops.len())`. (b) In `src/iter/shrink.rs`: deletion passes
before value-lowering, draw-granular `adjust_first`, and do not restart from pass 0 on cosmetic
improvements. Each side alone already reaches ≤ 6 ops on 10/10 seeds; together they reach
exactly 5 ops on 10/10 seeds by iteration 22–137 (well under 4096), and the library-side fixes
also rescue unstructured users of `cautious()`.

## 1. Baseline and evidence

Environment (verified): Linux 6.8.0-1061-aws x86_64, 8 vCPU Xeon 8559C, 32 GiB RAM, Rust
1.98.1, `kernel.yama.ptrace_scope=1`, `vm.unprivileged_userfaultfd=0`,
`kernel.perf_event_paranoid=4`, no `criu`. Instrumented with the README sancov recipe
(`-Cpasses=sancov-module`, level 3, inline 8-bit counters, pc-table, trace-compares).

Throwaway harness (`examples/shrink_exp.rs` in a scratch copy of the repo, not committed):
same `Op`/`BuggyStack`/`check_stack` as `buggy_stack.rs`, same 8192/4096 budgets, with env
toggles `STRUCTURED`, `COST`, `HAVOC`, `SEMANTIC`, `CMP`, `SEED`. It records the ops/features/
bytes of the best case, the number of failing vs discarded minimization cases, and the
iteration at which ≤ 8 ops was first reached. Runs used `setarch x86_64 -R` (see §1.3).
A `DOWSING_TRACE` env hook was added to the scratch copy's `rng.rs` to print, per candidate,
the reducer pass that produced it and whether it improved / preserved / was discarded.

### 1.1 Results (ops of best case per seed 0..9; `≤8` = seeds meeting the success bar)

| variant | lib changes | example changes | ops per seed | ≤8 |
|---|---|---|---|---|
| **baseline** | none | none | 19 26 8 8 41 37 35 21 20 17 | 2/10 |
| baseline, cmp feedback off | none | `with_cmp_feedback(false)` | 35 51 10 54 18 32 38 53 54 11 | 0/10 |
| cost only | none | `coverage_with_cost(ops.len())` | 18 26 5 13 42 34 33 52 12 15 | 1/10 |
| structured only | none | `range`/`variant` | 6 5 5 5 6 6 6 6 6 6 | 10/10 |
| structured + cost | none | both | 5 5 5 5 5 5 5 5 5 5 | 10/10 |
| structured + cost, havoc off | none | both, `with_havoc(false)` | 5 5 5 5 5 5 5 5 5 5 | 10/10 (reducer exhausted at ~1900–2200 cases) |
| draw-granular adjust | A | none | 7 11 5 6 41 37 12 7 6 7 | 7/10 |
| A + deletion passes first | A, B | none | 11 8 7 13 7 6 7 12 7 6 | 7/10 |
| A + B + window/2 adjust | A, B, C | none | 5 5 5 6 6 6 6 6 6 5 | 10/10 |
| A + B + C + cost | A, B, C | cost | 5 5 5 5 5 5 5 5 5 5 | 10/10 |
| A + B + C + structured + cost | A, B, C | both | 5 5 5 5 5 5 5 5 5 5 | 10/10 |

Library changes tried in the scratch copy: **A** — `DeleteRange::adjust_first: usize`, and
`DrawDelete` emits both "subtract number of draws deleted" and "subtract bytes deleted"
variants; **B** — `TailTrim` and `DrawDelete` moved ahead of `DrawLength` in `REDUCER_PASSES`;
**C** — windowed `DrawDelete` also emits `adjust_first = window / 2` (covers "one `Push` = 2
draws"). A+B+C break one unit test (`cautious_draw_spans_prioritize_length_like_first_draw`,
which asserts `DrawLength` on the first draw runs first); §4 handles that.

Iteration at which ≤ 8 ops was first reached (blank = never within 4096):

```
baseline                 -    -  785 1288    -    -    -    -    -    -
A                     1952    -  653 1288    -    - 3401 1639 1096    -   (seed 0..9)
A+B                      -  473 3552    -  471  381  579    - 2598  169
A+B+C                  338  251  564  287  424  232  288  565  427  117
structured + cost       80   69   34  106  137  127   61   80   48   22
```

The structured example converges 3–10x faster than the best library-only variant because
`SequenceDelete` deletes whole items (including the 2-draw `Push`) with the length span fixed
up exactly, instead of guessing the adjustment.

### 1.2 What the traces show

* Baseline seed 4 (`DOWSING_TRACE`): 4096 executions, origins = `DrawLength` 4095 +
  `SeededCase` 1; 77 improvements, 2375 preserved, 1643 discarded. Ops went 52 → 45 in the
  first 170 candidates (tail truncation via the length word), then 45 stayed for the remaining
  ~3900 candidates while `features` crept 947 → 831: every improvement was cosmetic (lower
  `cmp` value features from zeroing `Push` payload words) and each one restarted the pass
  loop at `SequenceDelete`… → `DrawLength` again.
* With A+B (deletions first), seed 0 spent 3346 of 4096 executions on `DrawDelete` candidates
  that all *broke* the failure (0 "preserved" outcomes): the remaining 11-op case was six
  `Push(v)` ops before `Save`; deleting one draw turns a payload into an opcode, deleting two
  with `adjust_first = 2` drops the essential last op. Only the `window / 2` adjustment (C)
  can express "delete 2 draws, length −1". This is exactly the information `range()` item
  spans carry for free.
* Once the deterministic passes are no longer starved (A+B+C build, seed 2, 4096 executions):
  `DrawDelete` 946 (12 improvements), `DictionaryRepair` 775 (0), `TailTrim` 308 (10),
  `DrawLength` 122 (8), `WordLower` 97 (0), `WeightedBlockDelete` 27 (0), `BlockZero` 5 (0),
  then `CautiousHavoc` 1812 (0 improvements, 841 preserved) after the passes exhausted at
  ~2280 candidates. Havoc and `DictionaryRepair` are pure budget consumers on this target.

### 1.3 Nondeterminism

Identical seeds gave different results across runs (`ops=5` vs `ops=6` on seed 3; different
failing/discarded counts). Under `setarch x86_64 -R` (ASLR off) results are bit-identical
across reruns and across unrelated harness changes. Cause: `record_cmp` hashes only
`(width, left, right)`; `__sanitizer_cov_trace_cmp8` fires on pointer comparisons inside
`Vec`/`VecDeque`/iterator code, so the feature set depends on heap/stack addresses. This
also inflates `features` with noise the reducer then "improves". Not the root cause of the
stall, but it makes the demo flaky and must be controlled during measurement.

## 2. Recommended approach

### 2.1 Example side (`examples/buggy_stack.rs`) — the demo must use structured spans

```rust
fn sample<C: CoverageCapture>(rng: &mut CaseRng<C>) -> Vec<Op> {
    rng.range(0..MAX_OPS)                 // Length span: shrinkable sequence length
        .map(|mut item| match item.variant(7) {   // Variant span: opcode
            0 => Op::Push(item.variant(16) as i32), // Variant span: payload
            1 => Op::Pop,
            2 => Op::Flip,
            3 => Op::Spill,
            4 => Op::Flush,
            5 => Op::Save,
            _ => Op::Restore,
        })
        .collect()
}
```

* `range(0..80)` records a `Length` span plus one `Item` span per op (variable width — a
  `Push` item covers two draws). `SequenceDelete`/`SequenceProject` can then delete whole ops
  and rewrite the length exactly; `SemanticLength` lowers the length directly.
* `variant(7)` for the opcode and `variant(16)` for the payload record `Variant` spans so
  `SemanticSimplify` lowers them toward 0 without disturbing neighbours. The `Op` numbering
  should be chosen so that "simpler" is lower: keep `Push`=0 … `Restore`=6 (the reproducer
  needs `Save`/`Flip`/`Restore`; nothing to gain by reordering, but the minimum still lands
  on `Push(0)`/`Push(1)` payloads only with a cost — see 1.1 "structured only").
* Minimization loop: `variant.coverage_with_cost(ops.len())` for failing cases (cost = domain
  size, which becomes the primary `MinPathScore` key), `variant.discard()` for non-failing.
  Also compare `best` by `(coverage, ops.len())` so the printed result is the smallest-cost
  case, and print `ops.len()`.
* The discovery loop can stay `curious()` + `coverage()`; discovery is not the problem
  (bug found within the first 0–64 curious cases on all 10 seeds, initial case 42–79 ops).

Which choices should be spans: **every** choice the harness makes — the length (`range`),
the per-op discriminant (`variant`), and the `Push` payload (`variant`). Anything drawn with
raw `random::<u8>() % n` is invisible to the semantic passes and is only reachable by the
byte-level passes, which cannot know the encoding.

### 2.2 Library side (`src/iter/shrink.rs`, `src/iter/prelude.rs`) — make byte-level shrinking
robust for unstructured users, and stop starving deletion

1. **Deletion before lowering.** New `REDUCER_PASSES` order:
   `SequenceDelete, SemanticLength, SemanticDelete, LengthProbe(new), TailTrim, DrawDelete,
   WeightedBlockDelete, SequenceProject, SequenceReplace, SemanticSimplify, DrawLength,
   BlockZero, WordLower, ByteLower, RepeatedValue, DictionaryRepair`.
   `LengthProbe` is `DrawLength` restricted to the first draw (≤ 27 candidates) so the
   existing "try small lengths first" behaviour and its unit test survive; the full
   `DrawLength` moves after the deletion passes. This is the delta-debugging / afl-tmin order
   (block removal first, byte normalisation last) and matches Hypothesis' shortlex
   `sort_key` (choice-sequence *length* first, choice indices second — i.e. size dominates
   value). Hypothesis' documented pass invariants also apply directly to `CautiousReducer`:
   whether a pass makes progress must be deterministic, passes must not iterate to a
   fixpoint themselves, and passes must be robust to the shrink target changing under them.
2. **Draw-granular `adjust_first`.** `ReductionOp::DeleteRange { adjust_first: usize }`
   (amount to subtract; 0 = none). `DrawDelete` emits, per deletion, adjustments of
   {draws deleted, `window / 2`, bytes deleted}, de-duplicated; `TailTrim`/`WeightedBlockDelete`
   keep bytes deleted (and add `bytes / 4` for 4-byte-aligned prefixes, cheap to try).
   `ReductionId` already carries `(start, len, target)`; add the adjustment so `tried_prefixes`
   fingerprinting still dedups correctly (it hashes the materialised prefix, so this is
   automatic).
3. **Restart policy.** In `CautiousReducer`, distinguish *structural* improvements (lower
   `case_cost` or `bytes`) from *cosmetic* ones (only `features`/`hit_count_weight`/
   `nonzero_bytes` changed). On a cosmetic improvement keep `pass_index`/`cursor` and only
   refresh `best_*` (Hypothesis' passes are written to be robust to the target changing
   under them; the same holds here because a cosmetic improvement never changes the draw
   layout). On a structural improvement restart from pass 0 as today. This needs the
   improvement kind to be threaded from `run.rs` (where `MinPathScore` is compared) into
   `reset_cautious_reducer_to_best` — a `reset_kind` parameter, no public API change.
4. **Pass budgets.** Cap `DrawLength` per invocation to `pass_candidate_limit / 4` candidates
   sorted by pressure, and move `DictionaryRepair` to a small fixed cap (e.g. 128) — it never
   improved in any trace. These are tuning-only changes to `CautiousOptions` defaults or
   internal constants; document in the PR if a default changes.
5. **(Follow-up, not needed for the success bar) deterministic `cmp` features.** Options in
   order of preference: (i) drop `cmp8` records where either operand looks like a
   user-space address (`>= 1 << 32` on x86_64 with the default 47-bit VA) — cheap, removes
   the ASLR dependence measured in §1.3, keeps value dictionary useful; (ii) libFuzzer-style
   site-keyed features (`PC` of the compare, obtained via a `#[unsafe(naked)]` trampoline
   reading the return address — stable since Rust 1.88) combined with a Hamming-distance
   bucket instead of raw values. (i) is the prototype; (ii) is a separate spike.

Public API: none of 1–4 change signatures or documented semantics. `CautiousOptions` gains
nothing new unless we decide to expose the `DrawLength`/`DictionaryRepair` caps.

## 3. Alternatives considered and rejected

* **Fix only the example.** Reaches the success bar (10/10 at 5 ops), but leaves
  `cautious()` unable to shrink any harness that uses raw `Rng` draws — which is the whole
  point of the crate's "works with any `Rng` user" pitch. The pass-order/starvation bug is a
  real library defect independent of the demo. Rejected as *sole* fix; kept as part of the
  fix.
* **Fix only the library.** A+B+C reach 5–6 ops on 10/10 seeds but need 117–565 candidates
  vs 22–137 for the structured example, and the 6-op results are an artefact of `features`
  ranking above `bytes` (cost fixes that). It also cannot generalise to items whose draw
  count varies more than 1–2 (the `window / 2` heuristic is a guess). Rejected as sole fix.
* **Reorder `MinPathScore` to `bytes` before `features`.** Would make the unstructured
  example converge to 5 ops without `coverage_with_cost`, but it changes public ranking
  semantics (`CaseCoverage::cmp` is documented as cost, features, hit-count, bytes) and the
  README explicitly steers users to `coverage_with_cost` for domain size. The feature-first
  ordering is defensible (fewer executed edges is a proxy for "less happening"); the demo
  simply needs to supply the cost. Rejected.
* **Disable havoc or semantic reductions.** Measured: havoc off changes nothing except that
  the reducer exhausts at ~1900–2200 cases (the deterministic passes already find the
  minimum; with havoc on, the ~1800 havoc candidates after exhaustion never improved);
  semantic off obviously hurts the structured example. Neither is a root cause. Rejected.
* **Disable `cmp` feedback.** Makes the unstructured baseline *worse* (0/10) because value
  features are the only signal that shrinks when payload words are zeroed. Rejected;
  address-filtering (2.2.5) is the right fix.
* **Replace the pass pipeline with Hypothesis' full shrinker (choice-tree, `find_integer`
  adaptive deletion, shortlex on choice indices).** Attractive long-term (dowsing already has
  the IR: draws + spans), but a rewrite is out of scope for a spike whose bar is met by
  ordering/adjustment fixes. Adopt its *invariants* now (passes are deterministic in whether
  they make progress; passes do not iterate to a fixpoint themselves; deletion before
  lowering) and revisit a shortlex-on-spans score later.
* **Process-level snapshot/fork tricks to speed up minimization** (AFL++/libAFL forkserver,
  Nyx-style snapshots): irrelevant to this spike. The 4096-case budget is ~4–5 s wall in a
  debug build; the stall is algorithmic, not throughput. Measured `fork()`+`exit`+`wait` on
  this box for reference: 99 µs at 1 MiB RSS, 164 µs at 4 MiB, 452 µs at 16 MiB, 1.6 ms at
  64 MiB, 3.5 ms at 256 MiB, 10.6 ms at 1 GiB (page-table copy dominates; touching 4 MiB
  of CoW pages in the child adds ~3 ms at 256 MiB). This bounds any future fork-per-case
  design at roughly 300–6000 cases/s depending on harness RSS — fine for `cautious()`, too
  slow to replace in-process `curious()`.

## 4. Risks and unknowns

* **Existing test asserts the current pass order.** `cautious_draw_spans_prioritize_length_like_first_draw`
  expects the first four candidates after the seed to set the first draw to 0,1,2,3. The
  `LengthProbe` pass in 2.2.1 preserves this; if it proves not worth keeping, the test must be
  changed and that must be called out in the PR (it encodes behaviour that is part of the
  stall).
* **Cosmetic-improvement restart policy.** Not measured yet; the A+B+C numbers were obtained
  with the *current* restart-from-0 policy. Risk: skipping the restart could miss deletions
  that only become possible after a lowering. Mitigation: still restart after a structural
  improvement; measure with/without on the 10-seed matrix.
* **Adjustment heuristics may misfire on other encodings** (e.g. a `u16` length, or lengths
  drawn after other data). They only add candidates, so the failure mode is budget, not
  wrong answers; caps in 2.2.4 bound it. Unstructured shrinking will remain heuristic — the
  memo's position is that `range`/`variant` is the supported path and the docs should say so
  more loudly.
* **Address-filtering of `cmp8` operands** is a heuristic; values ≥ 2^32 that are genuine
  data (hashes, u64 ids) would lose value feedback. Acceptable for the default; expose via
  `SancovCoverage` toggle if anyone complains.
* **Feature-count noise from inline 8-bit counters.** Hit-count buckets shift when deleting
  ops, so `features` is not monotone in "simplicity"; with cost as the primary key this is
  harmless for the demo, but it is why cost-less unstructured runs stall at 6 rather than 5.
* **Measurement variance.** Everything above is 10 seeds on one machine, debug build. The
  prototype must re-run with ASLR on (to show the address filter works) and in `--release`.
* Not risks for this spike, but recorded for the wider sandbox vision (all measured here,
  unprivileged, UID 1000): seccomp user-notification works (`SECCOMP_FILTER_FLAG_NEW_LISTENER`
  + `SECCOMP_RET_USER_NOTIF`, parent answered a trapped `getpid` in **7.8 µs per round trip**;
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE` and `SECCOMP_IOCTL_NOTIF_ADDFD` present in the 6.8
  headers); a parent can `PTRACE_TRACEME`-trace its child under `ptrace_scope=1`
  (`PTRACE_SYSCALL` stop + `GETREGS` = **8.0 µs per stop**, i.e. ~16 µs per intercepted
  syscall vs 7.8 µs for user-notif); `PTRACE_SYSEMU` and `PTRACE_GET_SYSCALL_INFO` are
  available; `unprivileged_userfaultfd=0` rules out userfaultfd-based dirty-page snapshots
  without `CAP_SYS_PTRACE`; `perf_event_paranoid=4` rules out perf-counter-based scheduling
  points (rr's approach) for an unprivileged supervisor on this box; no CRIU. gVisor's
  systrap (seccomp `SECCOMP_RET_TRAP` + `SIGSYS` handler) replaced its ptrace platform in 2023
  for exactly the per-syscall overhead reason measured above.

## 5. Prototype plan

Target: `examples/buggy_stack.rs` built with the README sancov recipe. Success bar: best
case ≤ 8 ops on seeds 0–9 within `MINIMIZATION_CASES = 4096`; `cargo test` and
`cargo clippy --all-targets` green; before/after table in the PR.

Files:

* `examples/buggy_stack.rs` — structured `sample()`, `coverage_with_cost(ops.len())`, print
  `ops.len()`, accept a seed via `with_seed`/env so the 10-seed matrix is scriptable
  (`DOWSING_SEED`), and print the iteration at which the best case was found.
* `src/iter/prelude.rs` — `DeleteRange::adjust_first: usize`; `ReducerPass::LengthProbe`;
  a `ResetKind { Structural, Cosmetic }` (crate-private).
* `src/iter/shrink.rs` — new `REDUCER_PASSES` order; `length_probe_specs`;
  `draw_delete_specs` adjustment variants; `materialize_reduction` uses the numeric adjust;
  `CautiousReducer::reset` takes `ResetKind` and keeps `pass_index`/`cursor` on `Cosmetic`;
  per-pass caps for `DrawLength` and `DictionaryRepair`.
* `src/iter/run.rs` — compute `ResetKind` where the new best is accepted (compare
  `case_cost`/`bytes` of old vs new `MinPathScore`) and pass it through
  `next_cautious_reduction`/`reset_cautious_reducer_to_best`.
* `src/sancov.rs` — `record_cmp`: skip feature (keep dictionary) for `width == 8` when either
  operand `>= 1 << 32`. Behind the existing `cmp_feedback` flag; document.
* `src/tests.rs` — keep `cautious_draw_spans_prioritize_length_like_first_draw` passing via
  `LengthProbe`; add: (a) a `ScriptedCapture` test that a 3-draw prefix `[len=3, a, b, c]`
  where only `c` matters shrinks to `[len=1, c]` via `DrawDelete` with draw-granular adjust;
  (b) a test that a cosmetic improvement does not reset `pass_index`; (c) a `sancov` unit test
  that `record_cmp(8, 0x7f..., 0x7f...)` records no feature.
* `README.md` — one paragraph under the cautious section: "draw every harness choice through
  `range`/`variant`; raw `Rng` draws are shrunk heuristically".
* `spikes/shrink-quality/RESULTS.md` — the before/after matrix.

Steps (each step re-runs the 10-seed matrix; ~1 min per configuration on 8 cores):

1. Land the example changes alone; record the "structured + cost" row (expected 5/5/…,
   iteration ≤ 137). This is the demo-facing fix and should be its own commit.
2. Land A+B+C (+ `LengthProbe`) with the *old* example kept in a scratch build to record the
   "library-only" row (expected 5–6 ops, 10/10). Verify `cargo test` (incl. the pass-order
   test) and clippy.
3. Add the `ResetKind` restart policy; measure with the unstructured scratch example
   (expect fewer candidates to ≤ 8; keep only if it does not regress the structured row).
4. Add per-pass caps; re-measure; keep if neutral-or-better.
5. Add the `cmp8` address filter; rerun the matrix **with ASLR on** twice and diff — expect
   identical results across runs.
6. Write `RESULTS.md`: baseline row (from this memo), each step's row, candidates-to-≤8,
   wall time, and the root-cause attribution (§ TL;DR).

Measurements per run: best ops, RNG bytes, `feature_count`, `hit_count_weight`, failing vs
discarded counts, iteration of first ≤ 8 ops and of the final best, wall time; per-pass
candidate/improve/preserve/discard counts from a crate-private trace hook (the `DOWSING_TRACE`
env hook used here, or a `SearchStats` extension if we want it permanently — the latter is a
public API addition and should be flagged).

## 6. How it plugs into the dowsing API

* `CaseRng::range(0..n)` → `SequenceSpan` + `Length` span + per-item `Item` spans; the item
  iterator's `ChildRng` is where `variant()` must be called so `Variant` spans nest inside
  the item. `cautious()` consumes these in `SequenceDelete`/`SequenceProject`/
  `SequenceReplace`/`SemanticLength`/`SemanticDelete`/`SemanticSimplify`.
* `CaseRng::coverage_with_cost(cost)` → `CaseCost` becomes the first key of `MinPathScore`
  and `CaseCoverage::cmp`; use the domain-level size (`ops.len()`), not bytes.
* `CaseRng::discard()` → `record_cautious_discard`, which raises `range_pressure` on the
  touched bytes so later passes deprioritise them. Keep calling it for every non-failing
  variant; the failing/discarded ratio also feeds the cautious energy scheduler.
* `CoverageCapture` is unchanged. `SancovCoverage` gains the address filter behind
  `with_cmp_feedback`; `NoCoverage` users are unaffected (and the structured + cost example
  reaches 5 ops even with zero coverage features — measured by accident when an
  uninstrumented build slipped into the matrix — so the spans + cost are doing the work).
* `curious()` is untouched. `fork_case()` on the failing curious RNG carries the prefix and
  all spans into `cautious().with_case(case)`, so the structured spans recorded during
  discovery are what the reducer shrinks.

## 7. What the prototype changed relative to this memo

Commits: `039e8c9` (bench harness), `73d20dc` (example), `170ade2` (library), plus docs.

* **Root-cause ranking was wrong in §TL;DR.** The memo put pass order + restart policy first and
  byte-granular `adjust_first` second. The ablation (RESULTS.md) shows the opposite: with the old
  pass order and always-reset, switching `adjust_first` to draw granularity alone takes
  unstructured+cost from 1/10 to 8/10 seeds; the reorder alone (bytes-only adjust) moves 1/10 →
  2/10. Reordering and the restart rule matter for *how fast* the reducer converges (max
  `last_improvement_at` 4092 → 2106 → 1460 executions), not for whether it does.
* **§1.1 "structured only" row.** The memo measured 6/5/5/5/6/6/6/6/6/6 for structured sampling
  with `coverage()`. The committed harness measures 5 on all 10 seeds on the *base* library too.
  The memo's scratch harness (uncommitted) is not reproducible, so the committed harness is the
  reference. The ordering issue the memo described (a fewer-features case outranking a smaller
  one) is real and is exactly what keeps seed 7 at 52 ops in the unstructured+`coverage()` row —
  see RESULTS.md.
* **`ResetKind` enum not added.** Same behaviour, simpler plumbing: `rng.rs` computes
  `is_structural_improvement(previous_best, candidate)` (cost or byte length changed) and calls
  either `reset_cautious_reducer_to_best` or the new `retarget_cautious_reducer_to_best`, which
  swaps in the new best prefix/spans but keeps `pass_index`/`cursor`. No change to `run.rs`.
* **`DeleteRange.adjust_first` alternatives** are emitted by `DrawDelete` and `TailTrim` (1 draw,
  draws in window, window/2, deleted bytes, deduplicated). `WeightedBlockDelete` keeps the byte
  count because its windows are not draw-aligned. The numeric adjustment is folded into
  `ReductionId::target` so alternatives with different amounts are distinct candidates.
* **Per-pass caps (step 4) were not needed.** Once deletion runs first, the shipped example and the
  unstructured+cost row converge by execution ≤ 1460 of 4096; capping `DrawLength`/
  `DictionaryRepair` would only save wall time after convergence.
* **cmp8 pointer filter (step 5) not implemented.** With the new reducer, ASLR-on matrices were
  identical to ASLR-off matrices on every seed and configuration tried, and three consecutive
  ASLR-on runs of seed 3 (the memo's flaky seed) produced identical feature/weight/improvement
  counts. There was no observable nondeterminism left to fix, so the change to `record_cmp` was
  deferred to keep root-crate edits minimal.
* **Tests.** Instead of a `ScriptedCapture` end-to-end shrink test, seven unit tests in
  `src/iter/shrink.rs` pin the new pass order, `LengthProbe` first-draw-only behaviour (targets
  `[0,1,2,3]`), the draw-granular alternatives and their dedup, numeric `adjust_first`
  materialisation, the structural/cosmetic classifier, and that `retarget` keeps the cursor while
  `reset` restarts it. The existing `cautious_draw_spans_prioritize_length_like_first_draw` test
  passes unchanged.
* **Root `README.md`** gained two short paragraphs (why `coverage_with_cost`, prefer
  `range`/`variant` over raw `% n` draws) rather than a new section.
