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

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Instant;

use fs_env_intercept::draw::pick;
use fs_env_intercept::{Content, Draw, Sandbox, Spec};
use iterator_fuzz::backends::SancovCoverage;
use iterator_fuzz::{Case, cautious, curious};

const DISCOVERY_CASES: usize = 200_000;
const MINIMIZATION_CASES: usize = 3_000;

/// `key=value` lines as a `sequence` so `cautious()` can delete whole lines; every value is a
/// `variant` (index 0 = simplest) so the minimized file reads naturally.
fn structured_config(draw: &mut dyn Draw) -> Vec<u8> {
    let mut out = Vec::new();
    draw.sequence(0..=4, &mut |_, draw| {
        let (_, key) = pick(draw, &["mode", "retries", "name", "seed", "# note", "bogus"]);
        match *key {
            "mode" => {
                let (_, value) = pick(draw, &["lenient", "strict", "fast", ""]);
                out.extend_from_slice(format!("mode={value}\n").as_bytes());
            }
            "retries" => {
                let value = draw.variant(300);
                out.extend_from_slice(format!("retries={value}\n").as_bytes());
            }
            "name" => {
                let value = draw.bytes(0..=6);
                out.extend_from_slice(b"name=");
                out.extend(value.iter().map(|b| b'a' + b % 26));
                out.push(b'\n');
            }
            "seed" => {
                let value = draw.variant(1 << 16);
                out.extend_from_slice(format!("seed={value}\n").as_bytes());
            }
            "# note" => out.extend_from_slice(b"# note\n"),
            _ => out.extend_from_slice(&draw.bytes(0..=8)),
        }
    });
    out
}

fn spec(raw: bool) -> Arc<Spec> {
    let content = if raw {
        Content::Random { max_len: 48 }
    } else {
        Content::Generate(Arc::new(structured_config))
    };
    Arc::new(
        Spec::new()
            .file("/etc/app/app.conf", content)
            .file("/var/lib/app/state.db", Content::Random { max_len: 16 })
            .dir("/var/lib/app", 2)
            .env("APP_MODE", vec![Some("lenient"), Some("strict"), None]),
    )
}

/// Run the target once and classify the outcome. The bug is a panic inside the target.
fn run_target() -> Result<demo_target::Summary, String> {
    match catch_unwind(AssertUnwindSafe(demo_target::run)) {
        Ok(result) => result,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "panic".to_string());
            Err(format!("PANIC: {msg}"))
        }
    }
}

fn is_bug(result: &Result<demo_target::Summary, String>) -> bool {
    matches!(result, Err(msg) if msg.starts_with("PANIC:"))
}

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
    let mut found: Option<(Case, String, Vec<(std::path::PathBuf, Vec<u8>)>, Vec<u8>)> = None;
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
        if executed % 1000 == 0 {
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
    let mut best: Option<(iterator_fuzz::CaseCoverage, Vec<u8>, Vec<(String, Option<String>)>, Vec<u8>)> =
        None;
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
    let repro = std::path::Path::new("target/dowsing-repro");
    std::fs::create_dir_all(repro).ok();
    std::fs::write(repro.join("app.conf"), &conf).ok();
    println!("wrote {}", repro.join("app.conf").display());
}
