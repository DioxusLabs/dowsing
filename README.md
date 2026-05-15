# iterator-fuzz

Minimal coverage-guided randomness.

The API has two entry points:

```rust
use iterator_fuzz::{curious, shy};
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

for mut rng in curious().take(128) {
    let input = sample(&mut rng);
    if check(input).is_err() {
        let case = rng.fork_case();
        let _coverage = rng.coverage().expect("finish discovery coverage");
        let mut shy = shy().seed_case(case);
        let mut best = None;

        for mut variant in shy.by_ref().take(128) {
            let input = sample(&mut variant);
            if check(input).is_err() {
                let coverage = variant.coverage().expect("finish minimization coverage");
                if best.as_ref().is_none_or(|best_coverage| coverage < *best_coverage) {
                    best = Some(coverage);
                }
            } else {
                // Exclude this path; it does not reproduce what the harness wants.
                variant.discard();
            }
        }
    }
}
```

`curious()` maximizes coverage between creation and drop of each yielded RNG. When an execution is
accepted, it stores the consumed RNG byte prefix and later mutates accepted prefixes to explore
nearby inputs.

The iterator can also feed Rayon directly:

```rust
use rayon::prelude::*;

let found = curious()
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

`shy()` starts from forked cases. It does not generate unrelated fresh roots. It generates byte
variants with stacked havoc mutations: deletion, truncation, zeroing, interesting values, bit and
arithmetic flips, random byte edits, and cmp/dictionary replacement or insertion. Passing variants
should be consumed with `discard()`, which keeps them out of the minimization corpus. Every
non-discarded variant is retained as a failing variant. Parent selection is not the coverage-rarity
entropy used by `curious()`; it is the inverse signal for minimization. `shy()` records the coverage
features from the initial failing path, then gives more energy to valid failing candidates that
remove features that most other valid candidates still execute. The public coverage score orders
shorter consumed RNG paths before lower feature counts, so the minimizer prefers smaller failing
inputs while still sampling candidates that discovered hard-to-remove code.

By default, feedback comes from LLVM SanitizerCoverage: inline 8-bit edge counters plus comparison
callbacks. Build the clean demo with instrumentation:

```sh
cargo rustc --example buggy_stack -- -Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-level=3 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares
./target/debug/examples/buggy_stack
```

The benchmark uses native Rayon iteration over `curious().take(n)`. Parallel coverage requires
trace-pc-guard feedback; inline counters are process-global and are only supported by the serial
loop.

For timing breakdowns, use the parallel benchmark variant:

```sh
cargo rustc --release --example buggy_stack_bench -- -Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-level=3 \
  -Cllvm-args=-sanitizer-coverage-trace-pc-guard \
  -Cllvm-args=-sanitizer-coverage-trace-compares
DEMONIC_BENCH=1 ./target/release/examples/buggy_stack_bench
```

Custom coverage is available by implementing `CoverageCapture` and passing it to `.coverage(...)`.
