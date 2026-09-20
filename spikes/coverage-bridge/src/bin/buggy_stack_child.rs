//! Target binary: the buggy stack harness, served to a supervisor.
//!
//! Started by `buggy_stack_bridge` it runs `coverage_bridge::child::serve`. Started by hand it
//! runs the same harness in-process with `SancovCoverage`, which is the apples-to-apples
//! in-process baseline (same instrumented code, same structured sampling).
//!
//! Instrument with:
//!   cargo rustc --release --bin buggy_stack_child -- -Cpasses=sancov-module \
//!     -Cllvm-args=-sanitizer-coverage-level=3 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
//!     -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares

#[path = "../buggy_stack.rs"]
mod buggy_stack;

use buggy_stack::{check_stack, run_case, sample};
use coverage_bridge::ChildMode;
use iterator_fuzz::{
    Case, CaseRng, NoCoverage, backends::SancovCoverage, cautious, coverage::CoverageCapture,
    curious,
};
use std::time::Instant;

fn main() {
    if ChildMode::from_env().is_some() {
        // BUGGY_STACK_ABORT=1 turns the logical failure into a SIGABRT so the crash path
        // (signal handler exporting counters) can be exercised end to end.
        let abort_on_bug = std::env::var_os("BUGGY_STACK_ABORT").is_some();
        coverage_bridge::child::serve(move |rng: &mut CaseRng<NoCoverage>| {
            let verdict = run_case(rng).0;
            if abort_on_bug && verdict.failed {
                std::process::abort();
            }
            verdict
        });
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut discovery = 8_192usize;
    let mut minimization = 4_096usize;
    let mut cmp = true;
    let mut no_coverage = false;
    let mut bench: Option<usize> = None;
    let mut seed: Option<u64> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--seed" => seed = Some(iter.next().and_then(|v| v.parse().ok()).expect("--seed N")),
            "--discovery" => {
                discovery = iter
                    .next()
                    .and_then(|v| v.parse().ok())
                    .expect("--discovery N")
            }
            "--minimize" => {
                minimization = iter
                    .next()
                    .and_then(|v| v.parse().ok())
                    .expect("--minimize N")
            }
            "--no-cmp" => cmp = false,
            "--no-coverage" => no_coverage = true,
            "--bench" => bench = Some(iter.next().and_then(|v| v.parse().ok()).expect("--bench N")),
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
    }

    if no_coverage {
        run(
            NoCoverage,
            "NoCoverage",
            discovery,
            minimization,
            bench,
            seed,
        );
    } else {
        run(
            SancovCoverage::new().with_cmp_feedback(cmp),
            if cmp { "sancov+cmp" } else { "sancov" },
            discovery,
            minimization,
            bench,
            seed,
        );
    }
}

fn run<Capture: CoverageCapture + Clone>(
    capture: Capture,
    label: &str,
    discovery: usize,
    minimization: usize,
    bench: Option<usize>,
    seed: Option<u64>,
) {
    let search = |capture: Capture| {
        let search = curious().with_coverage(capture);
        match seed {
            Some(seed) => search.with_seed(seed),
            None => search,
        }
    };
    if let Some(cases) = bench {
        let start = Instant::now();
        let mut failures = 0u64;
        for mut rng in search(capture).take(cases) {
            let (verdict, _) = run_case(&mut rng);
            failures += u64::from(verdict.failed);
            let _ = rng.coverage_with_cost(verdict.cost as usize);
        }
        let elapsed = start.elapsed();
        println!(
            "in-process {label}: {cases} cases in {:.3}s = {:.0} exec/s ({failures} failing)",
            elapsed.as_secs_f64(),
            cases as f64 / elapsed.as_secs_f64()
        );
        return;
    }

    let start = Instant::now();
    let mut found: Option<(Case, usize)> = None;
    for (index, mut rng) in search(capture.clone()).take(discovery).enumerate() {
        let ops = sample(&mut rng);
        if check_stack(&ops).is_err() {
            let case = rng.fork_case();
            let _ = rng.coverage_with_cost(ops.len());
            found = Some((case, index + 1));
            break;
        }
        let _ = rng.coverage_with_cost(ops.len());
    }
    let discovery_time = start.elapsed();
    let Some((case, cases_to_bug)) = found else {
        println!("in-process {label}: no failure in {discovery} cases ({discovery_time:.2?})");
        std::process::exit(1);
    };
    println!(
        "in-process {label}: found bug after {cases_to_bug} cases in {discovery_time:.2?} ({:.0} exec/s)",
        cases_to_bug as f64 / discovery_time.as_secs_f64()
    );

    let start = Instant::now();
    let mut best = None;
    let mut cautious = cautious().with_coverage(capture).with_case(case);
    let mut executed = 0usize;
    for mut variant in cautious.by_ref().take(minimization) {
        executed += 1;
        let ops = sample(&mut variant);
        if let Err(error) = check_stack(&ops) {
            let case = variant.fork_case();
            let coverage = variant.coverage_with_cost(ops.len()).expect("coverage");
            if best
                .as_ref()
                .is_none_or(|(best_coverage, _, _, _)| coverage < *best_coverage)
            {
                best = Some((coverage, ops, error, case));
            }
        } else {
            variant.discard();
        }
    }
    let minimize_time = start.elapsed();
    let (coverage, ops, error, _case) = best.expect("minimization keeps the seed case");
    println!(
        "in-process {label}: minimized to {} ops / {} bytes in {executed} cases ({minimize_time:.2?}, {:.0} exec/s)",
        ops.len(),
        coverage.bytes_consumed(),
        executed as f64 / minimize_time.as_secs_f64()
    );
    println!("  ops: {ops:?}\n  error: {error}");
}
