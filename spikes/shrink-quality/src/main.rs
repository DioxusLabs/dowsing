//! Shrink-quality bench harness for dowsing's `buggy_stack` demo.
//!
//! Runs the same discovery + minimization loop as `examples/buggy_stack.rs`, but with knobs so the
//! example-side and library-side fixes can be measured independently across seeds. Every knob is
//! an environment variable so the binary can be built once with SanitizerCoverage flags and driven
//! from a shell loop (see `run_matrix.sh`).
//!
//! Knobs (all optional):
//! - `SEED` (u64, default 0): base seed passed to `curious().with_seed` / `cautious().with_seed`.
//! - `STRUCTURED` (0/1, default 1): use `range`/`variant` spans instead of raw `random::<u8>() %`.
//! - `COST` (0/1, default 1): finish failing variants with `coverage_with_cost(ops.len())`.
//! - `HAVOC` (0/1, default 1): `CautiousOptions::with_havoc`.
//! - `SEMANTIC` (0/1, default 1): `CautiousOptions::with_semantic_reductions`.
//! - `DISCOVERY_CASES` (default 8192), `MINIMIZATION_CASES` (default 4096): budgets.
//! - `VERBOSE` (0/1, default 0): print every accepted improvement during minimization.

mod stack;

use iterator_fuzz::coverage::CoverageCapture;
use iterator_fuzz::tuning::CautiousOptions;
use iterator_fuzz::{CaseCoverage, CaseRng, cautious, curious};
use rand::Rng;
use stack::{Op, check_stack};
use std::time::Instant;

const MAX_OPS: usize = 80;

#[derive(Debug, Clone, Copy)]
struct Config {
    seed: u64,
    structured: bool,
    cost: bool,
    havoc: bool,
    semantic: bool,
    discovery_cases: usize,
    minimization_cases: usize,
    verbose: bool,
}

fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => !matches!(value.trim(), "0" | "false" | "no" | ""),
        Err(_) => default,
    }
}

fn env_num<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(default)
}

impl Config {
    fn from_env() -> Self {
        Self {
            seed: env_num("SEED", 0),
            structured: env_flag("STRUCTURED", true),
            cost: env_flag("COST", true),
            havoc: env_flag("HAVOC", true),
            semantic: env_flag("SEMANTIC", true),
            discovery_cases: env_num("DISCOVERY_CASES", 8_192),
            minimization_cases: env_num("MINIMIZATION_CASES", 4_096),
            verbose: env_flag("VERBOSE", false),
        }
    }
}

fn op_from_variant(code: usize, payload: impl FnOnce() -> i32) -> Op {
    match code {
        0 => Op::Push(payload()),
        1 => Op::Pop,
        2 => Op::Flip,
        3 => Op::Spill,
        4 => Op::Flush,
        5 => Op::Save,
        _ => Op::Restore,
    }
}

/// Unstructured sampling, byte-for-byte what the original demo did: the reducer sees only raw
/// draws and has to guess where the sequence boundaries are.
fn sample_unstructured<C: CoverageCapture>(rng: &mut CaseRng<C>) -> Vec<Op> {
    let len = usize::from(rng.random::<u8>() % MAX_OPS as u8);
    (0..len)
        .map(|_| {
            let code = usize::from(rng.random::<u8>() % 7);
            op_from_variant(code, || i32::from(rng.random::<u8>() % 16))
        })
        .collect()
}

/// Structured sampling: `range` records the length + per-item spans, `variant` records the
/// discriminants, so the semantic reducer passes can delete/simplify whole ops.
fn sample_structured<C: CoverageCapture>(rng: &mut CaseRng<C>) -> Vec<Op> {
    rng.range(0..MAX_OPS)
        .map(|mut item| {
            let code = item.variant(7);
            op_from_variant(code, || item.variant(16) as i32)
        })
        .collect()
}

fn sample<C: CoverageCapture>(rng: &mut CaseRng<C>, structured: bool) -> Vec<Op> {
    if structured {
        sample_structured(rng)
    } else {
        sample_unstructured(rng)
    }
}

struct Outcome {
    discovery_iter: usize,
    discovery_ops: usize,
    discovery_bytes: usize,
    best: CaseCoverage,
    ops: Vec<Op>,
    executed: u64,
    accepted: u64,
    failing: u64,
    improvements: u64,
    last_improvement_at: u64,
    minimize_ms: u128,
}

fn run(config: Config) -> Option<Outcome> {
    let mut curious = curious().with_seed(config.seed);
    for (index, mut rng) in curious.by_ref().take(config.discovery_cases).enumerate() {
        let ops = sample(&mut rng, config.structured);
        if check_stack(&ops).is_err() {
            let case = rng.fork_case();
            let discovery = rng.coverage().expect("finish discovery coverage");
            let discovery_ops = ops.len();
            let discovery_bytes = discovery.bytes_consumed();
            let minimize_started = Instant::now();

            let options = CautiousOptions::new()
                .with_havoc(config.havoc)
                .with_semantic_reductions(config.semantic);
            let mut cautious = cautious()
                .with_options(options)
                .with_seed(config.seed)
                .with_case(case);
            let mut best: Option<(CaseCoverage, Vec<Op>)> = None;
            let mut failing = 0;
            let mut improvements = 0;
            let mut last_improvement_at = 0;
            let mut executed = 0;
            for mut variant in cautious.by_ref().take(config.minimization_cases) {
                executed += 1;
                let ops = sample(&mut variant, config.structured);
                if check_stack(&ops).is_err() {
                    failing += 1;
                    let coverage = if config.cost {
                        variant.coverage_with_cost(ops.len())
                    } else {
                        variant.coverage()
                    }
                    .expect("finish minimization coverage");
                    if best
                        .as_ref()
                        .is_none_or(|(best_coverage, _)| coverage < *best_coverage)
                    {
                        improvements += 1;
                        last_improvement_at = executed;
                        if config.verbose {
                            eprintln!(
                                "  [{executed:>5}] ops={} bytes={} features={} weight={} {:?}",
                                ops.len(),
                                coverage.bytes_consumed(),
                                coverage.feature_count(),
                                coverage.hit_count_weight(),
                                ops
                            );
                        }
                        best = Some((coverage, ops));
                    }
                } else {
                    variant.discard();
                }
            }

            let stats = cautious.stats();
            let (best, ops) = best?;
            return Some(Outcome {
                discovery_iter: index,
                discovery_ops,
                discovery_bytes,
                best,
                ops,
                executed: stats.executed(),
                accepted: stats.accepted(),
                failing,
                improvements,
                last_improvement_at,
                minimize_ms: minimize_started.elapsed().as_millis(),
            });
        }
    }
    None
}

fn main() {
    let config = Config::from_env();
    let started = Instant::now();
    match run(config) {
        Some(outcome) => {
            println!(
                "seed={} structured={} cost={} havoc={} semantic={} discovery_iter={} \
                 discovery_ops={} discovery_bytes={} ops={} bytes={} features={} weight={} \
                 executed={} accepted={} failing={} improvements={} last_improvement_at={} \
                 minimize_ms={} total_ms={} ops_list={:?}",
                config.seed,
                u8::from(config.structured),
                u8::from(config.cost),
                u8::from(config.havoc),
                u8::from(config.semantic),
                outcome.discovery_iter,
                outcome.discovery_ops,
                outcome.discovery_bytes,
                outcome.ops.len(),
                outcome.best.bytes_consumed(),
                outcome.best.feature_count(),
                outcome.best.hit_count_weight(),
                outcome.executed,
                outcome.accepted,
                outcome.failing,
                outcome.improvements,
                outcome.last_improvement_at,
                outcome.minimize_ms,
                started.elapsed().as_millis(),
                outcome.ops,
            );
        }
        None => {
            println!(
                "seed={} structured={} cost={} havoc={} semantic={} NOT_FOUND total_ms={}",
                config.seed,
                u8::from(config.structured),
                u8::from(config.cost),
                u8::from(config.havoc),
                u8::from(config.semantic),
                started.elapsed().as_millis()
            );
            std::process::exit(2);
        }
    }
}
