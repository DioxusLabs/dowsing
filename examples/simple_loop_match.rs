//! `curious()` explores code. `cautious()` keeps one behavior while avoiding code.
//!
//! Run with SanitizerCoverage instrumentation:
//!
//! `cargo rustc --example simple_loop_match -- -Cpasses=sancov-module \
//! -Cllvm-args=-sanitizer-coverage-level=3 \
//! -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
//! -Cllvm-args=-sanitizer-coverage-pc-table`
//!
//! `./target/debug/examples/simple_loop_match`

use dowsing::{Case, CaseCoverage, CaseRng, cautious, coverage::CoverageCapture, curious};
use rand::Rng;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Arm {
    Add,
    Double,
    Clear,
}

fn sample<C: CoverageCapture>(rng: &mut CaseRng<C>) -> Vec<Arm> {
    rng.range(0..8)
        .map(|mut item| match item.random_range(0..3) {
            0 => Arm::Add,
            1 => Arm::Double,
            _ => Arm::Clear,
        })
        .collect()
}

fn run(steps: &[Arm]) -> BTreeSet<Arm> {
    let mut seen = BTreeSet::new();
    let mut value = 1;

    for step in steps {
        match step {
            Arm::Add => {
                seen.insert(Arm::Add);
                value += 1;
            }
            Arm::Double => {
                seen.insert(Arm::Double);
                value *= 2;
            }
            Arm::Clear => {
                seen.insert(Arm::Clear);
                value = 1;
            }
        }
    }

    if value == 0 {
        unreachable!();
    }

    seen
}

fn main() {
    let Some(case) = find_interesting_path() else {
        return;
    };

    show_cautious_avoidance(case);
}

fn find_interesting_path() -> Option<Case> {
    let mut search = curious().with_seed(1);

    for _ in 0..512 {
        let Some(mut rng) = search.next() else {
            break;
        };
        let steps = sample(&mut rng);
        let arms = run(&steps);
        let case = rng.fork_case();
        let coverage = rng.coverage().expect("finish curious coverage");

        if arms.len() == 3 {
            println!(
                "curious explored {arms:?}: {steps:?} ({} coverage features)",
                coverage.feature_count()
            );
            return Some(case);
        }
    }

    None
}

fn show_cautious_avoidance(case: Case) {
    let mut search = cautious().with_case(case);
    let mut best: Option<(CaseCoverage, Vec<Arm>, BTreeSet<Arm>)> = None;

    println!("cautious, preserving Double:");
    for mut rng in search.by_ref().take(512) {
        let steps = sample(&mut rng);
        let arms = run(&steps);

        if arms.contains(&Arm::Double) {
            let coverage = rng.coverage().expect("finish cautious coverage");
            if best
                .as_ref()
                .is_none_or(|(best_coverage, _, _)| coverage < *best_coverage)
            {
                println!(
                    "  kept {arms:?}: {steps:?} ({} coverage features)",
                    coverage.feature_count()
                );
                best = Some((coverage, steps, arms));
            }
        } else {
            rng.discard();
        }
    }
}
