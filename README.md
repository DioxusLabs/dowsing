# iterator-fuzz

Small Rust helper for deterministic state-machine fuzzing.

It is for tests shaped like:

1. Define a printable mutation enum.
2. Implement `rand::distr::Distribution<Op>` so `rand` can sample mutations.
3. Replay a mutation list from a clean model/system and check invariants after each step.
4. If a sequence fails, reduce it with a cost model to produce a smaller, cheaper repro.

`Fuzzer::sequences` yields one lazy `GeneratedCase` per seed (just `seed` + `steps` + a clone of
your distribution — no `Vec<Op>` allocated up front). `.check` / `.failures` / `.minimize` are the
three optional pipeline stages. Passing cases stream ops through your step function without
allocating; only failing cases materialize a `Vec<Op>` (so reduction has a slice to shrink).

The pipeline is a plain `Iterator`, so `.take(N)`, `.inspect(..)`, `try_for_each`, etc. compose
with it.

```rust
use iterator_fuzz::{CaseIteratorExt, Fuzzer, Step};
use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};

#[derive(Debug, Clone, Copy)]
enum Op {
    Read(usize),
    Reset(usize),
    PointTo(usize),
    Write(usize),
    Peek,
}

impl Distribution<Op> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Op {
        match rng.random_range(0..5) {
            0 => Op::Read(rng.random_range(0..4)),
            1 => Op::Reset(rng.random_range(0..4)),
            2 => Op::PointTo(rng.random_range(0..4)),
            3 => Op::Write(rng.random_range(0..4)),
            _ => Op::Peek,
        }
    }
}

struct State { model: Model, actual: System }
impl State { fn new() -> Self { Self { model: Model::new(), actual: System::new() } } }

fn apply_and_check(state: &mut State, step: Step<'_, Op>) -> Result<(), String> {
    state.model.apply(*step.op);
    state.actual.apply(*step.op);
    if state.model.dirty_counts() != state.actual.dirty_counts() {
        return Err(format!("step {}, op {:?}: dirty mismatch", step.index, step.op));
    }
    Ok(())
}

fn cost(op: &Op) -> u64 {
    match op {
        Op::Peek => 10,
        Op::Reset(_) => 3,
        Op::Read(_) | Op::PointTo(_) | Op::Write(_) => 1,
    }
}

if let Some(failure) = Fuzzer::sequences(StandardUniform)
    .base_seed(0x51a9_0000)
    .seeds(256)
    .steps(512)
    .failures(State::new, apply_and_check)
    .minimize(cost)
    .next()
{
    panic!(
        "seed {} failed: {}\nminimized to {} ops: {:?}\nminimized failure: {}",
        failure.seed,
        failure.error,
        failure.minimized_ops.len(),
        failure.minimized_ops,
        failure.minimized_error,
    );
}
```

## Pipeline stages

```
Sequences<GeneratedCase>
  └─ .check(init, step)   ─► Check<CheckedCase>       every replay outcome, pass or fail
      └─ .failures()      ─► Failures<FailedCase>     drop passes; keep failures only
          └─ .minimize(cost) ─► Minimize<MinimizedFailure>
```

`.failures(init, step)` is a shortcut for `.check(init, step).failures()`. The closures pass once
and thread through subsequent stages.

A few shapes you can write directly:

```rust
// All failures, no minimization:
for failed in sequences.failures(State::new, apply_and_check) {
    eprintln!("seed {}: {}", failed.seed, failed.error);
}

// Stop after 3 minimized failures:
let bugs: Vec<_> = sequences
    .failures(State::new, apply_and_check)
    .minimize(cost)
    .take(3)
    .collect();

// Pass-rate audit (use check, not failures):
let (pass, fail) = sequences
    .check(State::new, apply_and_check)
    .fold((0u64, 0u64), |(p, f), c| if c.is_failure() { (p, f + 1) } else { (p + 1, f) });

// Replay a single case lazily (no Vec allocation):
case.replay(State::new, apply_and_check)?;
```

If you want full manual control, `GeneratedCase::replay` (lazy), `replay_ops` (slice-based, for
custom reducers), and `reduce_with_cost` are all public — the combinators are just a thin layer on
top of them.

The reducer only removes operations. It preserves order and accepts a candidate when it still fails
and improves `(total_cost, length)`.

`minimize_with_transforms` and `reduce_preserving_with_transforms` accept a `SequenceMutator`
callback. The mutator emits valid rewritten operation sequences for your domain; the library
decides whether each candidate keeps the failure, keeps required coverage, or adds new coverage.

## Coverage-guided exploration

Enable `llvm-coverage` and build the harness with LLVM source coverage instrumentation. The
coverage-guided adapter is still an iterator: it yields accepted cases that fail or add real source
coverage.

```rust
use iterator_fuzz::{CaseIteratorExt, Fuzzer, llvm_coverage::LlvmCoverage, replay_ops};

let mut coverage = LlvmCoverage::new(
    std::env::current_exe()?,
    [std::path::PathBuf::from("src")],
    "target/iterator-fuzz-cov/my-harness",
)?;

let corpus: Vec<_> = Fuzzer::sequences(StandardUniform)
    .base_seed(0)
    .seeds(128)
    .steps(256)
    .coverage_guided(move |ops| {
        coverage
            .evaluate(|| replay_ops(ops, State::new, apply_and_check))
            .expect("failed to collect LLVM coverage")
    })
    .mutate(mutate_ops)
    .shrink(simplify_ops)
    .rounds(6)
    .mutations_per_entry(64)
    .take(128)
    .collect();
```

Run the harness with instrumentation:

```sh
rustup component add llvm-tools-preview
RUSTFLAGS="-Cinstrument-coverage" cargo run --features llvm-coverage --example my_harness
```

`LlvmCoverage` resets counters before each candidate, writes a per-case `.profraw`, exports source
regions with `llvm-cov`, and feeds those region IDs to `coverage_guided`.

## Parallel fuzzing (rayon)

Enable the optional `rayon` feature to fan out seeds across cores:

```toml
[dependencies]
iterator-fuzz = { version = "0.1", features = ["rayon"] }
```

`SequencesBuilder::par()` produces a rayon `IndexedParallelIterator`, and the
`parallel::ParCaseIteratorExt` trait provides parallel `failures` and `minimized_failures`
stages. Closures must be `Fn + Send + Sync` (not `FnMut`), since each thread invokes them; each
worker builds its own `State` via `init`.

```rust
use iterator_fuzz::{Fuzzer, parallel::ParCaseIteratorExt};
use rayon::iter::ParallelIterator;

let bug = Fuzzer::sequences(StandardUniform)
    .base_seed(0).seeds(10_000).steps(64)
    .par()
    .minimized_failures(State::new, apply_and_check, cost)
    .find_any(|_| true);          // first failure any thread sees
```

Order is not preserved; reproduce by seed. Reduction stays per-case — scaling comes from spreading
distinct failing seeds across cores, not from parallelizing inside a single reduction.
