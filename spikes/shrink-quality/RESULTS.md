# Measured results

All numbers below were produced on this branch with `run_matrix.sh` (sancov recipe from the root
README, `--release`, 8192 discovery / 4096 minimization cases, seeds 0..9). Unless noted, ASLR was
disabled with `setarch x86_64 -R` so runs are byte-for-byte repeatable. Host: Linux 6.8.0-1061-aws
x86_64, 8 vCPU, Rust 1.98.1.

Each cell is the op count of the best failing case after the 4096-case cautious budget. The bug's
smallest reproducer is 5 ops (`Push, Push, Save, Flip, Restore`). The success bar is `<= 8`.

## Before / after (bench harness `shrink-bench`)

`STRUCTURED=0` is the original example's sampling (`rng.random::<u8>() % 80`, `% 7`, `% 16`);
`STRUCTURED=1` is `rng.range(0..80)` + `item.variant(7)` + `item.variant(16)`. `COST=1` finishes
failing cases with `coverage_with_cost(ops.len())`, `COST=0` with `coverage()`.

| library                | sampling     | cost | ops per seed 0..9                | <=8   |
|------------------------|--------------|------|----------------------------------|-------|
| base (`73d20dc`)       | unstructured | no   | 11 51 7 36 38 37 37 54 22 18     | 1/10  |
| base                   | unstructured | yes  | 11 47 7 37 41 37 36 31 21 18     | 1/10  |
| base                   | structured   | no   | 5 5 5 5 5 5 5 5 5 5              | 10/10 |
| base                   | structured   | yes  | 5 5 5 5 5 5 5 5 5 5              | 10/10 |
| this branch (`170ade2`)| unstructured | no   | 5 5 5 5 5 5 5 **52** 5 5         | 9/10  |
| this branch            | unstructured | yes  | 5 5 5 5 5 5 5 5 5 5              | 10/10 |
| this branch            | structured   | no   | 5 5 5 5 5 5 5 5 5 5              | 10/10 |
| this branch            | structured   | yes  | 5 5 5 5 5 5 5 5 5 5              | 10/10 |

"base" rows were measured at commit `73d20dc` (bench harness present, library untouched). The
`73d20dc` unstructured/no-cost row is the situation the task describes (seed 1 = 51 ops).

## The shipped demo (`examples/buggy_stack.rs`, structured + cost, ASLR **on**)

```
seed=0 539ms: found stack bug with 5 ops, 380 features and 32 bytes: [Push(0), Push(1), Save, Flip, Restore]
seed=1 516ms: found stack bug with 5 ops, 380 features and 32 bytes: [Push(0), Push(1), Save, Flip, Restore]
seed=2 807ms: found stack bug with 5 ops, 380 features and 32 bytes: [Push(5), Push(10), Save, Flip, Restore]
seed=3 674ms: found stack bug with 5 ops, 380 features and 32 bytes: [Push(0), Push(1), Save, Flip, Restore]
seed=4 562ms: found stack bug with 5 ops, 380 features and 32 bytes: [Push(0), Push(6), Save, Flip, Restore]
seed=5 572ms: found stack bug with 5 ops, 380 features and 32 bytes: [Push(2), Push(3), Save, Flip, Restore]
seed=6 539ms: found stack bug with 5 ops, 380 features and 32 bytes: [Push(5), Push(7), Save, Flip, Restore]
seed=7 447ms: found stack bug with 5 ops, 380 features and 32 bytes: [Push(9), Push(15), Save, Flip, Restore]
seed=8 464ms: found stack bug with 5 ops, 380 features and 32 bytes: [Push(0), Push(3), Save, Flip, Restore]
seed=9 858ms: found stack bug with 5 ops, 380 features and 32 bytes: [Push(1), Push(5), Save, Flip, Restore]
```

(wall time includes the 8192-case discovery phase; the 32 bytes are 1 length draw + 5 opcode
draws + 2 payload draws, 4 bytes each.)

## Ablation of the library changes (unstructured sampling, ASLR off)

The three library changes were toggled independently (temporary env knobs, removed before commit).
`old order` is the pre-branch `REDUCER_PASSES`; `bytes-only` is the old `adjust_first: bool`
behaviour (subtract deleted *bytes* from the first byte); `always reset` restarts the pass
schedule on every improvement.

| pass order | DeleteRange adjust | restart policy     | cost | ops per seed 0..9             | <=8   |
|------------|--------------------|--------------------|------|-------------------------------|-------|
| old        | bytes-only         | always reset       | no   | 11 51 8 36 38 37 37 54 21 18  | 1/10  |
| old        | bytes-only         | always reset       | yes  | 11 46 8 37 41 37 36 31 21 18  | 1/10  |
| new        | bytes-only         | always reset       | no   | 8 51 26 17 32 36 14 31 11 18  | 1/10  |
| new        | bytes-only         | always reset       | yes  | 6 7 26 16 35 18 30 31 11 18   | 2/10  |
| new        | bytes-only         | structural only    | no   | 8 51 26 17 32 36 14 31 11 18  | 1/10  |
| new        | bytes-only         | structural only    | yes  | 8 6 26 15 35 17 29 30 11 17   | 2/10  |
| old        | draw-granular      | always reset       | no   | 5 33 5 23 5 29 37 54 5 5      | 5/10  |
| old        | draw-granular      | always reset       | yes  | 5 7 5 8 5 29 5 45 5 5         | 8/10  |
| old        | draw-granular      | structural only    | no   | 5 11 5 5 5 5 5 5 5 5          | 9/10  |
| old        | draw-granular      | structural only    | yes  | 5 5 5 5 5 5 5 5 5 5           | 10/10 |
| new        | draw-granular      | always reset       | no   | 5 5 5 5 5 5 5 52 5 5          | 9/10  |
| new        | draw-granular      | always reset       | yes  | 5 5 5 5 5 5 5 5 5 5           | 10/10 |
| **new**    | **draw-granular**  | **structural only**| no   | 5 5 5 5 5 5 5 52 5 5          | 9/10  |
| **new**    | **draw-granular**  | **structural only**| yes  | 5 5 5 5 5 5 5 5 5 5           | 10/10 |

(The first two rows are the emulated base; they differ from the true `73d20dc` measurement at
seeds 2 and 8 by one op; the emulation is not byte-identical to the old code, e.g. the
`ReductionId` of a `DeleteRange` now encodes the numeric adjustment, which changes dedup order.)

Executions until the last improvement, unstructured + cost (budget 4096). For rows that reach 5
ops on every seed this is the convergence point; for the first two rows it is where the reducer
stalled or where the budget ran out:

| configuration                          | seed 0..9                                                  | max  |
|----------------------------------------|------------------------------------------------------------|------|
| base (`73d20dc`)                       | 256 3264 1321 3092 2703 3759 2576 3819 2073 806            | 3819 |
| old order + draw-granular (always reset)| 614 4092 1325 4019 3710 4053 3836 3970 2003 1515          | 4092 |
| new order + draw-granular (always reset)| 365 1561 1178 1237 2106 1676 791 1460 1661 630            | 2106 |
| new order + draw-granular + restart    | 365 1113 1178 1237 1298 868 791 1460 1015 630              | 1460 |

Reading: draw-granular `adjust_first` is the change that makes unstructured deletion work at all;
the pass reorder roughly halves the executions needed; the restart policy shaves another ~30% off
the worst seed. Each is neutral for the structured example, which was already at 5/5 on the base
library.

## Other knobs

| run                                        | ops per seed 0..9      | <=8   |
|--------------------------------------------|------------------------|-------|
| structured + cost, `HAVOC=0`               | 5 5 5 5 5 5 5 5 5 5    | 10/10 |
| structured + cost, `SEMANTIC=0`            | 5 5 5 5 5 5 5 5 5 5    | 10/10 |
| unstructured + cost, `HAVOC=0`             | 5 5 5 5 5 5 5 5 5 5    | 10/10 |
| unstructured + cost, ASLR on (2 runs)      | 5 5 5 5 5 5 5 5 5 5    | 10/10 |
| unstructured + no cost, ASLR on (2 runs)   | 5 5 5 5 5 5 5 52 5 5   | 9/10  |
| structured + cost, ASLR on (2 runs)        | 5 5 5 5 5 5 5 5 5 5    | 10/10 |

Seed 3, unstructured + cost, ASLR on, three consecutive runs: identical
`features=287 weight=314 accepted=60 improvements=45 last_improvement_at=1237` each time. With
this branch's reducer we could not reproduce the ASLR-dependent flakiness the design memo saw,
so the proposed `record_cmp` pointer filter was not implemented (see DESIGN.md §7).

## Seed 7, unstructured, no cost: why it stays at 52 ops

`VERBOSE=1 SEED=7 STRUCTURED=0 COST=0` shows that after execution 80 the reducer produces many
failing candidates with fewer ops and bytes but *more* features:

```
[   80] ops=52 bytes=252 features=804 weight=721   <- best
[  125] kept failing but not better: ops=44 bytes=228 features=890 weight=716
[  152] kept failing but not better: ops=44 bytes=220 features=853 weight=708
...
single-op deletions of the final case that still fail: 47/52
```

The 52-op case fails *early* (an op returns the wrong value mid-sequence), so `check_stack`
returns before running the remaining ops and the run touches fewer edges/comparisons. Deleting an
op before that point makes the early mismatch disappear; the case still fails at the final stack
comparison, but now every op executes and the feature count rises. With `coverage()` the score is
`(features, hit_weight, bytes, ...)`, so a "fewer features" 52-op case is a local minimum that
byte-level deletion cannot escape. `coverage_with_cost(ops.len())` puts op count first and the
same seed reaches 5 ops; the structured example never enters this trap because `SequenceDelete`
removes items in bulk before the early-failure case is reached. This is the documented reason to
call `coverage_with_cost` from a harness rather than a library bug we can fix without changing
`MinPathScore` semantics.

## Test suite

```
cargo test                  -> 61 passed (54 existing + 7 new in src/iter/shrink.rs)
cargo clippy --all-targets  -> 0 errors; 2 pre-existing warnings (manual_isolate_lowest_one in
                               src/iter/prelude.rs, while_let_on_iterator in src/tests.rs)
```
