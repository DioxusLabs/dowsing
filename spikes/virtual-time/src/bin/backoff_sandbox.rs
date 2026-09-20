//! End-to-end demo harness: `curious()` drives the sandboxed backoff target until it fails, the
//! failing case is minimised with `cautious()` (cost = jumps*1000 + non_natural*10000 +
//! virtual seconds; non-reproducing variants are `discard()`ed), then the minimised case is
//! replayed to check the event log hash is identical.
//!
//! `backoff_sandbox [--target PATH] [--no-coverage] [--runs N] [--shrink N] [--replays N]
//!                  [--max-jumps N] [--show-target] [-- target args]`

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use iterator_fuzz::{Case, NoCoverage, cautious, coverage::CoverageCapture, curious};
use virtual_time::{Outcome, RunReport, Sandbox, SandboxCoverage};

struct Options {
    target: PathBuf,
    target_args: Vec<String>,
    coverage: bool,
    runs: usize,
    shrink: usize,
    replays: usize,
    max_jumps: usize,
    quiet_target: bool,
}

fn parse() -> Options {
    let mut o = Options {
        target: PathBuf::from("target/debug/backoff_target"),
        target_args: Vec::new(),
        coverage: true,
        runs: 2000,
        shrink: 300,
        replays: 100,
        max_jumps: 8,
        quiet_target: true,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                i += 1;
                o.target = PathBuf::from(&args[i]);
            }
            "--no-coverage" => o.coverage = false,
            "--runs" => {
                i += 1;
                o.runs = args[i].parse().expect("--runs N");
            }
            "--shrink" => {
                i += 1;
                o.shrink = args[i].parse().expect("--shrink N");
            }
            "--replays" => {
                i += 1;
                o.replays = args[i].parse().expect("--replays N");
            }
            "--max-jumps" => {
                i += 1;
                o.max_jumps = args[i].parse().expect("--max-jumps N");
            }
            "--show-target" => o.quiet_target = false,
            "--" => {
                o.target_args = args[i + 1..].to_vec();
                break;
            }
            other => panic!("unknown flag {other}"),
        }
        i += 1;
    }
    o
}

fn describe(report: &RunReport) -> String {
    format!(
        "{:?} virtual={:.3}s wall={:.2}ms stops={} jumps={} non_natural={} rng_bytes={}",
        report.outcome,
        report.virtual_elapsed.as_secs_f64(),
        report.wall.as_secs_f64() * 1e3,
        report.stats.stops,
        report.decisions.jumps_used,
        report.decisions.non_natural_jumps,
        report.decisions.random_bytes,
    )
}

fn discover<C: CoverageCapture>(
    sandbox: &Sandbox,
    search: impl Iterator<Item = iterator_fuzz::CaseRng<C>>,
    runs: usize,
) -> Option<(Case, RunReport, usize, Duration, usize)> {
    let started = Instant::now();
    for (n, mut rng) in search.take(runs).enumerate() {
        let report = sandbox.run(&mut rng);
        let failed = report.outcome.is_failure();
        let case = failed.then(|| rng.fork_case());
        let cov = rng
            .coverage_with_cost(report.cost())
            .expect("discovery coverage");
        if let Some(case) = case {
            return Some((case, report, n + 1, started.elapsed(), cov.feature_count()));
        }
    }
    None
}

fn main() {
    let o = parse();
    let coverage = SandboxCoverage::new();
    let mut sandbox = Sandbox::new(&o.target)
        .quiet(o.quiet_target)
        .max_jumps(o.max_jumps)
        .wall_limit(Duration::from_secs(10))
        .with_coverage_slot(coverage.slot());
    for a in &o.target_args {
        sandbox = sandbox.arg(a);
    }

    eprintln!(
        "== discovery: {} (coverage {}), up to {} runs, max_jumps {}",
        o.target.display(),
        if o.coverage { "sancov" } else { "none" },
        o.runs,
        o.max_jumps
    );
    let found = if o.coverage {
        discover(&sandbox, curious().with_coverage(coverage.clone()), o.runs)
    } else {
        discover(&sandbox, curious().with_coverage(NoCoverage), o.runs)
    };
    let Some((case, first, runs, wall, features)) = found else {
        eprintln!("no failure in {} runs", o.runs);
        std::process::exit(1);
    };
    eprintln!(
        "found failure after {runs} runs in {:.1}ms wall ({features} coverage features, {} counter bytes): {}",
        wall.as_secs_f64() * 1e3,
        first.coverage_bytes,
        describe(&first)
    );
    if first.outcome == Outcome::Hang {
        eprintln!("(hang: the wall watchdog fired; see README on unsupervised blocking)");
    }

    eprintln!("== minimisation: {} cautious variants", o.shrink);
    let started = Instant::now();
    let mut best: Option<(iterator_fuzz::CaseCoverage, Case, RunReport)> = None;
    let mut reproduced = 0_usize;
    let mut tried = 0_usize;
    let mut cautious = cautious()
        .with_coverage(coverage.clone())
        .with_case(case.clone());
    for mut variant in cautious.by_ref().take(o.shrink) {
        tried += 1;
        let report = sandbox.run(&mut variant);
        if report.outcome == first.outcome {
            reproduced += 1;
            let candidate = variant.fork_case();
            let cov = variant
                .coverage_with_cost(report.cost())
                .expect("minimisation coverage");
            if best.as_ref().is_none_or(|(b, _, _)| cov < *b) {
                best = Some((cov, candidate, report));
            }
        } else {
            variant.discard();
        }
    }
    let (best_cov, best_case, best_report) = best.unwrap_or_else(|| {
        let cov = iterator_fuzz::CaseCoverage::new(0, 0, 0);
        (cov, case.clone(), first.clone())
    });
    eprintln!(
        "minimised in {:.1}ms: {tried} variants, {reproduced} reproduced; best rng bytes {} cost {:?}: {}",
        started.elapsed().as_secs_f64() * 1e3,
        best_cov.bytes_consumed(),
        best_cov.case_cost(),
        describe(&best_report)
    );

    eprintln!("== replay: {} times", o.replays);
    let mut identical = 0;
    let mut same_outcome = 0;
    let replay_sandbox = sandbox.clone().quiet(true);
    let started = Instant::now();
    for _ in 0..o.replays {
        let mut rng = best_case.clone().replay();
        let again = replay_sandbox.run(&mut rng);
        rng.discard();
        if again.outcome == best_report.outcome
            && again.virtual_elapsed.as_millis() == best_report.virtual_elapsed.as_millis()
        {
            same_outcome += 1;
        }
        if again.event_hash == best_report.event_hash && again.outcome == best_report.outcome {
            identical += 1;
        }
    }
    eprintln!(
        "replays identical (event log hash): {identical}/{}; same outcome + virtual time: {same_outcome}/{} ({:.2}ms each)",
        o.replays,
        o.replays,
        started.elapsed().as_secs_f64() * 1e3 / o.replays.max(1) as f64
    );

    eprintln!("== final failing run with target output:");
    let mut rng = best_case.replay();
    let shown = sandbox.clone().quiet(false).keep_events(true).run(&mut rng);
    rng.discard();
    for e in shown
        .events
        .iter()
        .filter(|e| e.contains("jump") && !e.contains("kind=0"))
    {
        eprintln!("  {e}");
    }
    eprintln!("{}", describe(&shown));
    std::process::exit(if identical == o.replays { 0 } else { 2 });
}
