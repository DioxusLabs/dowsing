//! Fuzz the unmodified `demo_target` inside the seccomp-unotify sandbox: `curious()` finds the
//! injected bug through fuzzer-supplied file contents, environment, and entropy; `cautious()`
//! minimizes the failing case and the harness prints the resulting config file.
//!
//! Build with SanitizerCoverage (see README.md) and run
//! `target/debug/examples/sandboxed_config [--raw] [--no-dict] [--seed N] [--cases N]`.
//!
//! * default: `app.conf` comes from a structured line generator (`Content::Generate`).
//! * `--raw`: `app.conf` is a flat `Content::Random` byte string; the comparison dictionary
//!   (`trace-compares`) has to discover `mode`, `strict`, `retries` on its own.
//! * `--no-dict`: disable the comparison dictionary (measures how much it helps).

#[path = "demo_target/mod.rs"]
mod demo_target;
#[path = "demo_target/harness.rs"]
mod harness;

use std::path::{Path, PathBuf};
use std::time::Instant;

use fs_env_intercept::Sandbox;
use harness::{is_bug, run_target, spec};
use iterator_fuzz::backends::SancovCoverage;
use iterator_fuzz::{Case, CaseCoverage, cautious, curious};

/// A failing case plus what the sandbox served it: (case, error, materialized files, entropy).
type Found = (Case, String, Vec<(PathBuf, Vec<u8>)>, Vec<u8>);
/// Best minimized case so far: (coverage, app.conf bytes, applied env, entropy).
type Best = (CaseCoverage, Vec<u8>, Vec<(String, Option<String>)>, Vec<u8>);

const DISCOVERY_CASES: usize = 200_000;
const MINIMIZATION_CASES: usize = 3_000;

struct Args {
    raw: bool,
    dict: bool,
    seed: u64,
    cases: usize,
}

fn parse_args() -> Args {
    let mut args = Args {
        raw: false,
        dict: true,
        seed: 1,
        cases: DISCOVERY_CASES,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--raw" => args.raw = true,
            "--no-dict" => args.dict = false,
            "--seed" => args.seed = iter.next().expect("--seed N").parse().expect("seed"),
            "--cases" => args.cases = iter.next().expect("--cases N").parse().expect("cases"),
            other => panic!("unknown argument {other:?}"),
        }
    }
    args
}

fn main() {
    let args = parse_args();
    // Panics inside the target are the bug we are hunting; keep them quiet.
    std::panic::set_hook(Box::new(|_| {}));

    let mut sandbox = Sandbox::install().expect("install sandbox (needs Linux seccomp unotify)");
    let spec = spec(args.raw);
    let coverage = || SancovCoverage::new().with_cmp_feedback(args.dict);

    let started = Instant::now();
    let mut found: Option<Found> = None;
    let mut executed = 0usize;
    let mut discarded = 0usize;
    let mut search = curious().with_coverage(coverage()).with_seed(args.seed);
    while executed < args.cases {
        let Some(rng) = search.next() else { break };
        let (rng, report, result) = sandbox.run_case(rng, &spec, run_target);
        executed += 1;
        if is_bug(&result) {
            let case = rng.fork_case();
            rng.coverage_with_cost(report.cost()).expect("coverage");
            found = Some((case, result.unwrap_err(), report.files, report.entropy));
            break;
        }
        if report.should_discard() {
            discarded += 1;
            rng.discard();
        } else {
            rng.coverage_with_cost(report.cost()).expect("coverage");
        }
        if executed.is_multiple_of(1000) {
            let stats = search.stats();
            eprintln!(
                "  {executed} cases, {} in corpus, {} coverage ids, {:.0} cases/s",
                stats.accepted(),
                stats.coverage_ids(),
                executed as f64 / started.elapsed().as_secs_f64()
            );
        }
    }
    let discovery = started.elapsed();
    let Some((case, error, files, entropy)) = found else {
        println!(
            "no bug found in {executed} cases ({discarded} discarded) in {:.2?} ({:.0} cases/s)",
            discovery,
            executed as f64 / discovery.as_secs_f64()
        );
        std::process::exit(2);
    };
    println!(
        "found bug after {executed} cases ({discarded} discarded) in {:.2?} ({:.0} cases/s): {error}",
        discovery,
        executed as f64 / discovery.as_secs_f64()
    );
    for (path, bytes) in files.iter().filter(|(p, _)| !p.starts_with("/proc")) {
        println!("  {}: {:?}", path.display(), String::from_utf8_lossy(bytes));
    }
    println!("  entropy served: {entropy:?}");

    // Replay determinism: the same case must reproduce the same failure and the same files.
    for _ in 0..3 {
        let (_, report, result) = sandbox.run_case(case.clone().replay(), &spec, run_target);
        assert!(is_bug(&result), "replay reproduces the bug: {result:?}");
        assert_eq!(report.files, files, "replay materializes identical files");
        assert_eq!(report.entropy, entropy, "replay serves identical entropy");
    }
    println!("replayed 3x: identical failure, files and entropy");

    let started = Instant::now();
    let mut best: Option<Best> = None;
    let mut minimization_cases = 0usize;
    let mut retries = 0u64;
    for rng in cautious()
        .with_coverage(coverage())
        .with_case(case)
        .take(MINIMIZATION_CASES)
    {
        let (rng, report, result) = sandbox.run_case(rng, &spec, run_target);
        minimization_cases += 1;
        retries += report.send_retries;
        if is_bug(&result) && !report.should_discard() {
            let coverage = rng.coverage_with_cost(report.cost()).expect("coverage");
            let conf = report
                .files
                .iter()
                .find(|(p, _)| p.ends_with("app.conf"))
                .map(|(_, b)| b.clone())
                .unwrap_or_default();
            if best.as_ref().is_none_or(|(c, ..)| coverage < *c) {
                best = Some((coverage, conf, report.applied_env.clone(), report.entropy.clone()));
            }
        } else {
            rng.discard();
        }
    }
    let minimization = started.elapsed();
    let (coverage, conf, env, entropy) = best.expect("minimization keeps a failing case");
    println!(
        "minimized in {minimization_cases} cases / {:.2?}: app.conf = {:?} ({} bytes), env = {:?}, entropy = {:?}, cost = {}, features = {}, consumed = {} bytes, SEND retries = {retries}",
        minimization,
        String::from_utf8_lossy(&conf),
        conf.len(),
        env,
        entropy,
        coverage.case_cost().get(),
        coverage.feature_count(),
        coverage.bytes_consumed(),
    );
    let repro = Path::new("target/dowsing-repro");
    std::fs::create_dir_all(repro).ok();
    std::fs::write(repro.join("app.conf"), &conf).ok();
    println!("wrote {}", repro.join("app.conf").display());
}
