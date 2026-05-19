# dowsing

Coverage-guided randomness for Rust tests.

`dowsing` gives a test harness an iterator of RNGs. Each RNG records the bytes it consumes and the
coverage it reaches. Successful paths feed the next round of exploration; failing paths can be
forked, replayed, and minimized.

The public API starts with one optimizer configured by a goal:

- `optimize(goals::MaximizeCoverage)` searches for new coverage.
- `optimize(goals::MinimizeCoverage)` starts from an interesting case and tries to make it smaller.

The older `curious()` and `cautious()` constructors remain as deprecated compatibility wrappers.

## Quick Start

The examples below use `NoCoverage` so they can run as plain doctests. In an instrumented harness,
omit `.with_coverage(NoCoverage)` to use the default SanitizerCoverage feedback.

```rust
use dowsing::{NoCoverage, goals, optimize};
use rand::Rng;

fn sample(mut rng: impl Rng) -> u8 {
    rng.random()
}

fn check(sample: u8) -> Result<(), String> {
    if sample == 13 {
        Err("unlucky".to_string())
    } else {
        Ok(())
    }
}

for mut rng in optimize(goals::MaximizeCoverage)
    .with_coverage(NoCoverage)
    .take(128)
{
    let input = sample(&mut rng);

    if check(input).is_err() {
        let case = rng.fork_case();
        let _ = rng.coverage().expect("finish discovery coverage");

        let mut variants = optimize(goals::MinimizeCoverage)
            .with_coverage(NoCoverage)
            .with_case(case);
        let mut best = None;

        for mut variant in variants.by_ref().take(128) {
            let input = sample(&mut variant);

            if check(input).is_err() {
                let coverage = variant.coverage().expect("finish minimization coverage");
                if best.as_ref().is_none_or(|best_coverage| coverage < *best_coverage) {
                    best = Some(coverage);
                }
            } else {
                variant.discard();
            }
        }
    }
}
```

## How It Works

`optimize(goal)` drives a set of candidate sources toward the chosen goal. The coverage goal keeps
executions that find useful coverage, stores the consumed RNG trace, and later mutates accepted
trace bytes to explore nearby inputs. Trace storage and replay are implemented in the
workspace `dowsing-rng` crate; `dowsing::Case` is a reexport of that trace type for the
coverage-guided API.

The minimization goal starts from one or more forked cases. It does not generate unrelated fresh roots.
Non-discarded variants are treated as still valid, so call `discard()` for cases that do not
reproduce the behavior your harness is trying to keep.

The minimizer ranks valid variants by:

1. Lower domain-specific `CaseCost`, when reported.
2. Fewer coverage features.
3. Lower hit-count weight.
4. Fewer consumed RNG bytes.

This usually means the minimization goal keeps simplifying the failing path while still spending
energy on candidates that remove hard-to-remove code.

## Mutation Sets

Optimizers can replace their candidate sources with built-ins or custom sources:

```rust
# use dowsing::{goals, mutations, optimize};
let search = optimize(goals::MaximizeCoverage).with_mutations([
    mutations::coverage_havoc(),
]);
```

Custom sources implement `CandidateSource` and return `MutationCandidate::from_case(...)`.
Built-in sources include coverage havoc, minimizing havoc, and semantic reductions over ranges,
scalar draws, and byte spans.

## Domain Costs

Failing variants can report a harness-level cost:

```rust
# use dowsing::{NoCoverage, goals, optimize};
# use rand::Rng;
# fn sample(mut rng: impl Rng) -> Vec<u8> {
#     vec![rng.random()]
# }
# let mut rng = optimize(goals::MaximizeCoverage).with_coverage(NoCoverage).next().expect("seed case");
# let _ = sample(&mut rng);
# let case = rng.fork_case();
# let _ = rng.coverage().expect("finish seed coverage");
# let mut variants = optimize(goals::MinimizeCoverage).with_coverage(NoCoverage).with_case(case);
# let mut variant = variants.next().expect("variant");
# let input = sample(&mut variant);
let coverage = variant
    .coverage_with_cost(input.len())
    .expect("finish minimization coverage");
# assert_eq!(coverage.case_cost(), input.len().into());
```

Use `coverage_with_cost` for stable value-level preferences such as operation count, input length,
or AST node count. Use `discard()` for variants that do not reproduce the target behavior at all.

## Range Generation

Generators can use typed structure builders around the bytes they draw from a `CaseRng`:

```rust
use rand::Rng;

fn sample_items<C: dowsing::coverage::CoverageCapture>(
    rng: &mut dowsing::CaseRng<C>,
) -> Vec<u8> {
    rng.range(0..64)
        .map(|mut item| item.random())
        .collect()
}
```

`range` draws a length in the requested bounds and maps each element through another `CaseRng`
node. Range items share the same tracked byte stream as the parent while recording item spans, so
generation can use `random`, `random_range`, nested `range` calls, and other `rand::Rng` methods.

The minimization goal uses range structure to try length and item reductions before falling back to
generic byte shrinking. Larger harnesses can tune the reducer budget with
`tuning::CautiousOptions::new().with_reducer_budget(...)` and `.with_options(...)`.

## Parallel Search

The iterators can feed Rayon directly:

```rust
use dowsing::{NoCoverage, goals, optimize};
use rand::Rng;
use rayon::prelude::*;

# fn sample(mut rng: impl Rng) -> u8 {
#     rng.random()
# }
# fn check(sample: u8) -> Result<(), String> {
#     if sample == 13 {
#         Err("unlucky".to_string())
#     } else {
#         Ok(())
#     }
# }
let found = optimize(goals::MaximizeCoverage)
    .with_coverage(NoCoverage)
    .take(128)
    .into_par_iter()
    .find_map_any(|mut rng| {
        let input = sample(&mut rng);
        check(input).err().map(|error| {
            let case = rng.fork_case();
            let _ = rng.coverage();
            (case, error)
        })
    });
```

Parallel coverage requires trace-pc-guard feedback. Inline counters are process-global and are only
supported by serial search.

## Coverage

By default, feedback comes from LLVM SanitizerCoverage: inline 8-bit edge counters plus comparison
callbacks. Build the demo harness with instrumentation:

```sh
cargo rustc --example buggy_stack -- -Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-level=3 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares
./target/debug/examples/buggy_stack
```

For a parallel timing breakdown:

```sh
cargo rustc --release --example buggy_stack_bench -- -Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-level=3 \
  -Cllvm-args=-sanitizer-coverage-trace-pc-guard \
  -Cllvm-args=-sanitizer-coverage-trace-compares
ITERATOR_FUZZ_BENCH=1 ./target/release/examples/buggy_stack_bench
```

Custom feedback is available by implementing `coverage::CoverageCapture` and passing it to
`.with_coverage(...)`.
