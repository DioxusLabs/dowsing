//! Benchmarked version of the buggy stack example.
//!
//! Run with LLVM SanitizerCoverage instrumentation:
//!
//! `cargo rustc --release --example buggy_stack_bench -- -Cpasses=sancov-module \
//! -Cllvm-args=-sanitizer-coverage-level=3 \
//! -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
//! -Cllvm-args=-sanitizer-coverage-pc-table \
//! -Cllvm-args=-sanitizer-coverage-trace-compares`
//!
//! `DEMONIC_BENCH=1 ./target/release/examples/buggy_stack_bench`

use iterator_fuzz::{curious, shy};
use rand::Rng;
use rayon::prelude::*;
use std::{
    collections::VecDeque,
    env,
    time::{Duration, Instant},
};

const DISCOVERY_CASES: usize = 8_192;
const MINIMIZATION_CASES: usize = 8_192;

#[derive(Debug, Default)]
struct BenchStats {
    minimization_cases: usize,
    improved_cases: usize,
    non_improving_failures: usize,
    passing_cases: usize,
    candidate_generation: Duration,
    check: Duration,
    sample: Duration,
    coverage: Duration,
    discard: Duration,
    improved_total: Duration,
    non_improving_failure_total: Duration,
    passing_total: Duration,
}

impl BenchStats {
    fn print(&self) {
        let total =
            self.candidate_generation + self.sample + self.check + self.coverage + self.discard;
        let wrong = self.non_improving_failure_total + self.passing_total;
        println!(
            "minimization benchmark over {} variants:",
            self.minimization_cases
        );
        print_duration("candidate generation", self.candidate_generation, total);
        print_duration("sample bytes -> ops", self.sample, total);
        print_duration("check", self.check, total);
        print_duration("coverage", self.coverage, total);
        print_duration("discard", self.discard, total);
        print_duration("wrong-direction variants", wrong, total);
        print_duration("improving variants", self.improved_total, total);
        println!(
            "outcomes: {} improved, {} failing non-improving, {} passing",
            self.improved_cases, self.non_improving_failures, self.passing_cases
        );
    }
}

fn print_duration(label: &str, duration: Duration, total: Duration) {
    let percent = if total.is_zero() {
        0.0
    } else {
        duration.as_secs_f64() * 100.0 / total.as_secs_f64()
    };
    println!(
        "  {label}: {:.3}ms ({percent:.1}%)",
        duration.as_secs_f64() * 1_000.0
    );
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn bench_enabled() -> bool {
    env::var_os("DEMONIC_BENCH").is_some()
}

fn trace_best_enabled() -> bool {
    env::var_os("DEMONIC_TRACE_BEST").is_some()
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Push(i32),
    Pop,
    Flip,
    Spill,
    Flush,
    Save,
    Restore,
}

fn sample(rng: &mut impl Rng) -> Vec<Op> {
    let len = usize::from(rng.random::<u8>() % 80);

    (0..len)
        .map(|_| match rng.random::<u8>() % 7 {
            0 => Op::Push(i32::from(rng.random::<u8>() % 16)),
            1 => Op::Pop,
            2 => Op::Flip,
            3 => Op::Spill,
            4 => Op::Flush,
            5 => Op::Save,
            _ => Op::Restore,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Model {
    stack: Vec<i32>,
    spill: Vec<i32>,
    saved: Option<(Vec<i32>, Vec<i32>)>,
}

impl Model {
    fn apply(&mut self, op: Op) -> Option<i32> {
        match op {
            Op::Push(value) => self.stack.push(value),
            Op::Pop => return self.stack.pop(),
            Op::Flip => self.stack.reverse(),
            Op::Spill => {
                if let Some(value) = self.stack.pop() {
                    self.spill.push(value);
                }
            }
            Op::Flush => self.stack.extend(self.spill.drain(..).rev()),
            Op::Save => self.saved = Some((self.stack.clone(), self.spill.clone())),
            Op::Restore => {
                if let Some((stack, spill)) = &self.saved {
                    self.stack.clone_from(stack);
                    self.spill.clone_from(spill);
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
struct Actual {
    deque: VecDeque<i32>,
    spill: Vec<i32>,
    reversed: bool,
    saved: Option<(VecDeque<i32>, Vec<i32>, bool)>,
}

impl Actual {
    fn logical_stack(&self) -> Vec<i32> {
        if self.reversed {
            self.deque.iter().rev().copied().collect()
        } else {
            self.deque.iter().copied().collect()
        }
    }

    fn apply(&mut self, op: Op) -> Option<i32> {
        match op {
            Op::Push(value) if self.reversed => self.deque.push_front(value),
            Op::Push(value) => self.deque.push_back(value),
            Op::Pop if self.reversed => return self.deque.pop_front(),
            Op::Pop => return self.deque.pop_back(),
            Op::Flip => self.reversed = !self.reversed,
            Op::Spill => {
                if let Some(value) = self.apply(Op::Pop) {
                    self.spill.push(value);
                }
            }
            Op::Flush => {
                while let Some(value) = self.spill.pop() {
                    self.apply(Op::Push(value));
                }
            }
            Op::Save => self.saved = Some((self.deque.clone(), self.spill.clone(), self.reversed)),
            Op::Restore => {
                if let Some((deque, spill, _reversed)) = &self.saved {
                    self.deque.clone_from(deque);
                    self.spill.clone_from(spill);
                    // BUG: restore forgets to restore orientation.
                }
            }
        }
        None
    }
}

fn check_stack(ops: &[Op]) -> Result<(), String> {
    let mut model = Model {
        stack: Vec::new(),
        spill: Vec::new(),
        saved: None,
    };
    let mut actual = Actual {
        deque: VecDeque::new(),
        spill: Vec::new(),
        reversed: false,
        saved: None,
    };

    for (index, op) in ops.iter().copied().enumerate() {
        let expected = model.apply(op);
        let actual_value = actual.apply(op);
        if actual_value != expected {
            return Err(format!(
                "op {index} returned {actual_value:?}, expected {expected:?}: {ops:?}"
            ));
        }
    }

    let actual_stack = actual.logical_stack();
    if actual_stack != model.stack {
        return Err(format!(
            "final stack {actual_stack:?}, expected {:?}: {ops:?}",
            model.stack
        ));
    }

    if actual.spill != model.spill {
        return Err(format!(
            "spill {:?}, expected {:?}: {ops:?}",
            actual.spill, model.spill
        ));
    }

    Ok(())
}

fn main() {
    let discovery_cases = env_usize("DEMONIC_DISCOVERY_CASES", DISCOVERY_CASES);
    let minimization_cases = env_usize("DEMONIC_MINIMIZATION_CASES", MINIMIZATION_CASES);
    let base_seed = env_u64("DEMONIC_BASE_SEED", 0);
    let bench = bench_enabled();
    let trace_best = trace_best_enabled();

    let found = curious()
        .seed(base_seed)
        .take(discovery_cases)
        .into_par_iter()
        .find_map_any(|rng| run_discovery_case(rng, minimization_cases, trace_best));

    if let Some(found) = found {
        if bench {
            println!("found failure from discovery seed {}", found.discovery_seed);
            found.bench_stats.print();
        }
        println!(
            "found stack bug with {} features and {} bytes: {:?}\nerror: {}",
            found.coverage.feature_count, found.coverage.bytes_consumed, found.ops, found.failure
        );
    }
}

#[derive(Debug)]
struct FoundBug {
    discovery_seed: u64,
    bench_stats: BenchStats,
    coverage: iterator_fuzz::DemonicCoverage,
    ops: Vec<Op>,
    failure: String,
}

fn run_discovery_case(
    mut rng: iterator_fuzz::DemonicRng,
    minimization_cases: usize,
    trace_best: bool,
) -> Option<FoundBug> {
    let discovery_seed = rng.seed();
    // Maximize code coverage between when rng is created and dropped in the body of the loop, to increase the chance of hitting the bug.
    let ops = sample(&mut rng);
    if let Err(_err) = check_stack(&ops) {
        let case = rng.fork_case();
        let _coverage = rng.coverage().expect("finish discovery coverage");
        // Minimize the code executed by the discovery loop, to increase the chance of hitting the bug in the minimization loop.
        let mut shy = shy().seed_case(case);
        let mut best = None;
        let mut bench_stats = BenchStats::default();
        for _ in 0..minimization_cases {
            let case_start = Instant::now();
            let candidate_start = Instant::now();
            let Some(mut variant) = shy.next() else {
                break;
            };
            bench_stats.candidate_generation += candidate_start.elapsed();
            bench_stats.minimization_cases += 1;

            let sample_start = Instant::now();
            let ops = sample(&mut variant);
            bench_stats.sample += sample_start.elapsed();

            let check_start = Instant::now();
            let result = check_stack(&ops);
            bench_stats.check += check_start.elapsed();

            if let Err(error) = result {
                let coverage_start = Instant::now();
                let coverage = variant.coverage().expect("finish minimization coverage");
                bench_stats.coverage += coverage_start.elapsed();

                let improved = best
                    .as_ref()
                    .is_none_or(|(best_coverage, _, _)| coverage < *best_coverage);
                if improved {
                    if trace_best {
                        println!(
                            "seed {} new best: {} features and {} bytes",
                            discovery_seed, coverage.feature_count, coverage.bytes_consumed
                        );
                    }
                    best = Some((coverage, ops, error));
                    bench_stats.improved_cases += 1;
                    bench_stats.improved_total += case_start.elapsed();
                } else {
                    bench_stats.non_improving_failures += 1;
                    bench_stats.non_improving_failure_total += case_start.elapsed();
                }
            } else {
                // exclude this from the minimization search space, since it doesn't trigger the bug.
                let discard_start = Instant::now();
                variant.discard();
                bench_stats.discard += discard_start.elapsed();
                bench_stats.passing_cases += 1;
                bench_stats.passing_total += case_start.elapsed();
            }
        }
        if let Some((coverage, ops, failure)) = best {
            return Some(FoundBug {
                discovery_seed,
                bench_stats,
                coverage,
                ops,
                failure,
            });
        }
    }
    None
}
