# Spike `shrink-quality`

Why `cautious()` reported a ~51-op "minimized" failure for `examples/buggy_stack.rs` when a 5-op
reproducer exists, and the fix. Design memo: [`DESIGN.md`](DESIGN.md). Measured numbers:
[`RESULTS.md`](RESULTS.md).

## Outcome

The sancov-instrumented `examples/buggy_stack` now minimizes to exactly **5 ops on all 10 seeds
(0..9)** within the existing 4096-case budget, ASLR on or off. `cargo test` (61 tests) and
`cargo clippy --all-targets` pass on the root crate.

| configuration (bench harness)                | before (ops, seeds 0..9)     | after                  |
|----------------------------------------------|------------------------------|------------------------|
| original example: unstructured, `coverage()` | 11 51 7 36 38 37 37 54 22 18 | 5 5 5 5 5 5 5 52 5 5   |
| unstructured, `coverage_with_cost(ops.len())`| 11 47 7 37 41 37 36 31 21 18 | 5 5 5 5 5 5 5 5 5 5    |
| structured (`range`/`variant`), `coverage()` | 5 5 5 5 5 5 5 5 5 5          | 5 5 5 5 5 5 5 5 5 5    |
| structured + cost (**the shipped example**)  | 5 5 5 5 5 5 5 5 5 5          | 5 5 5 5 5 5 5 5 5 5    |

"before" = library at `73d20dc` (pre-fix reducer), "after" = this branch.

## Root cause

Two independent problems, both fixed:

1. **The example did not use the API it demonstrates.** `sample()` drew `rng.random::<u8>() % 80`,
   `% 7`, `% 16`. Each draw consumed 4 RNG bytes and recorded no span, so the semantic passes
   (`SequenceDelete`, `SemanticLength`, `SemanticDelete`, `SemanticSimplify`) had nothing to work
   on, and it finished with `coverage()` so `MinPathScore` ranked by feature count before size.
   Rewriting `sample()` with `rng.range(0..80)` + `item.variant(7)` + `item.variant(16)` alone
   reaches 5 ops on 10/10 seeds; adding `coverage_with_cost(ops.len())` makes op count the primary
   key so coverage noise cannot outrank a smaller case.

2. **The byte-level reducer could not delete draws from an unstructured prefix.** Three
   interacting defects in `src/iter/shrink.rs`, confirmed by ablation (RESULTS.md):
   * `DeleteRange { adjust_first: bool }` subtracted the deleted *byte count* from the first
     length-like draw. Deleting one 4-byte op draw lowered the length by 4 instead of 1, so the
     surviving ops were re-interpreted and the failure vanished. This was the dominant defect:
     fixing it alone (old pass order) takes unstructured+cost from 1/10 to 8/10.
   * `DrawLength` (every draw x ~27 targets x 3 widths) ran before every deletion pass, so on a
     60-draw prefix thousands of value-lowering candidates were tried before a single deletion.
   * Every improvement, including cosmetic ones that only changed `feature_count`/`hit_weight`,
     restarted the pass schedule from pass 0, re-running `DrawLength` again.

   Havoc, the energy scheduler, semantic reductions on/off and cmp feedback were measured and are
   not the cause (`HAVOC=0` / `SEMANTIC=0` rows in RESULTS.md are unchanged).

## Root-crate edits (`src/`)

Listed explicitly as required; no public API signatures changed.

* `src/iter/prelude.rs`
  * `ReducerPass::LengthProbe` added.
  * `ReductionOp::DeleteRange.adjust_first: bool` -> `usize` (0 = no adjustment); the value is
    folded into the `ReductionId` target so alternatives dedupe correctly.
* `src/iter/shrink.rs`
  * `REDUCER_PASSES` reordered: `SequenceDelete, SemanticLength, SemanticDelete, LengthProbe,
    TailTrim, DrawDelete, WeightedBlockDelete, SequenceProject, SequenceReplace, SemanticSimplify,
    DrawLength, BlockZero, WordLower, ByteLower, RepeatedValue, DictionaryRepair`. This is a
    behavioural change in candidate order for all `cautious()` users (documented in DESIGN.md §7).
  * `LengthProbe`: first-draw-only small-value probe (targets 0,1,2,3,...) so the existing
    `cautious_draw_spans_prioritize_length_like_first_draw` test still observes `[0,1,2,3]`.
  * `DrawDelete` and `TailTrim` emit draw-granular `adjust_first` alternatives (1 draw, draws in
    window, half window, deleted bytes; deduplicated) via `push_delete_range`.
    `WeightedBlockDelete` keeps the byte-count adjustment (it has no draw boundaries).
  * `retarget_cautious_reducer_to_best` (keeps `pass_index`/`cursor`) and
    `is_structural_improvement` (cost or bytes changed) added; 7 unit tests added.
* `src/iter/rng.rs`: on an accepted cautious improvement, `reset_cautious_reducer_to_best` is
  used only when `is_structural_improvement`, otherwise `retarget_cautious_reducer_to_best`.
* `examples/buggy_stack.rs`: structured `sample()`, `coverage_with_cost(ops.len())`, `discard()`
  on non-failing variants, `DOWSING_SEED` env var, prints `ops.len()`.
* `README.md` (root): two short paragraphs on why `coverage_with_cost` and `range`/`variant`
  matter for shrinking.

Not done from the memo: the `record_cmp` cmp8 pointer filter (`src/sancov.rs`) and per-pass caps.
With the new reducer, ASLR-on runs were deterministic across repeats on every seed we tried, so the
filter had no observable problem to fix; per-pass caps were unnecessary once deletion ran first.

## Contents of this crate

* `src/main.rs` — `shrink-bench`: the `buggy_stack` discovery + minimization loop with env knobs
  `SEED`, `STRUCTURED`, `COST`, `HAVOC`, `SEMANTIC`, `DISCOVERY_CASES`, `MINIMIZATION_CASES`,
  `VERBOSE`. Prints one line per run with discovery iteration, final ops/bytes/features/weight,
  executed/accepted/failing counts, improvement count, execution index of the last improvement,
  and timings.
* `src/stack.rs` — copy of the buggy stack target (`Op`, model, `check_stack`) so the harness
  does not depend on the example.
* `run_matrix.sh` — builds `shrink-bench` with the sancov recipe and runs seeds 0..9 under
  `setarch x86_64 -R` (ASLR off; `ASLR=1` to keep it on), printing a per-seed line and a
  `SUMMARY ops: ... success(<=8 ops): N/10` line. Forwards all env knobs.
* `RESULTS.md` — full before/after and ablation tables.
* `DESIGN.md` — original design memo plus §7 "What the prototype changed".

The crate has an empty `[workspace]` table, depends on `iterator-fuzz = { path = "../.." }`, and
only adds `rand` (already a root dependency). The root `Cargo.toml` is untouched.

## Build and run (fresh clone, Linux x86_64, stable Rust)

```sh
git clone https://github.com/DioxusLabs/dowsing.git
cd dowsing
git checkout devin/spike/shrink-quality

# 1. Root crate must stay green.
cargo test
cargo clippy --all-targets

# 2. The demo: sancov-instrumented buggy_stack, 10 seeds. Expect "found stack bug with 5 ops" each time.
cargo rustc --release --example buggy_stack -- -Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-level=3 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares
for s in 0 1 2 3 4 5 6 7 8 9; do DOWSING_SEED=$s ./target/release/examples/buggy_stack | head -1; done

# 3. The bench matrix (builds spikes/shrink-quality/target/release/shrink-bench with the same flags).
cd spikes/shrink-quality
./run_matrix.sh after                                   # structured + cost (the shipped example)
STRUCTURED=0 COST=1 SKIP_BUILD=1 ./run_matrix.sh unstructured-cost
STRUCTURED=0 COST=0 SKIP_BUILD=1 ./run_matrix.sh unstructured-nocost   # expect seed 7 = 52 ops
ASLR=1 STRUCTURED=0 COST=1 SKIP_BUILD=1 ./run_matrix.sh aslr-on

# 4. Reproduce the "before" rows: check out the pre-fix library with the same harness.
cd ../..
git worktree add /tmp/dowsing-base 73d20dc
cd /tmp/dowsing-base/spikes/shrink-quality
STRUCTURED=0 COST=0 ./run_matrix.sh before              # expect 11 51 7 36 38 37 37 54 22 18
```

Each `run_matrix.sh` invocation takes about 3-15 s for 10 seeds (release build, one core).
`setarch` is in `util-linux`; if absent the script runs without it (results may then differ by a
feature or two but the op counts above were identical with ASLR on).

## What works / what does not

Works:
* 5-op reproducer on 10/10 seeds for the shipped example (structured + cost), ASLR on and off.
* 5-op reproducer on 10/10 seeds for *unstructured* sampling when the harness supplies
  `coverage_with_cost(ops.len())`.
* All existing tests plus 7 new reducer tests; clippy clean apart from 2 pre-existing warnings.

Does not (by design, documented rather than fixed):
* Unstructured sampling **with plain `coverage()`** still stalls on seed 7 (52 ops). The case fails
  early, so it executes less code and has fewer features than any smaller case that fails late;
  with `coverage()` fewer features wins. Escaping this would require ranking bytes/cost before
  features in `MinPathScore`, which changes semantics for coverage-only users, so the fix is the
  documented one: pass a domain cost.
* The cmp8 pointer-operand filter from the memo was not implemented (no flakiness observed to fix).

## Next steps

1. Decide whether `MinPathScore` should fall back to `bytes` before `feature_count` when
   `case_cost` is neutral (would fix the seed-7 no-cost stall; behavioural change for everyone).
2. Add a per-pass candidate/improvement counter to `SearchStats` (public API addition) so users
   can see budget starvation like the original `DrawLength` problem without a trace hook.
3. Cap `DictionaryRepair`/`WordLower` per pass or drop them from the deterministic schedule on
   prefixes with spans; the memo's per-pass trace saw no improvements from them on this target.
4. Run the reorder against the other examples/tests with larger prefixes to confirm the
   ~4x candidate growth from draw-granular alternatives stays under the candidate cap.
5. Implement the `record_cmp` width-8 address filter behind `with_cmp_feedback` if ASLR-dependent
   results reappear on other targets.
