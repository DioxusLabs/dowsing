//! Snapshot-rewind demo and measurement driver.
//!
//! ```text
//! snapshot_demo demo     --rss-mb 100 --n 32        # setup once, N random continuations
//! snapshot_demo latency  --rss-mb 100 --n 200       # continuation round trip vs RSS
//! snapshot_demo curious  --rss-mb 10  --cases 400   # coverage-guided search with/without
//! snapshot_demo cautious --rss-mb 10                # minimise a failing case with/without
//! ```
//! Build the sancov-instrumented binary for `curious`/`cautious` (see README).

#[path = "common/kv.rs"]
mod kv;

use iterator_fuzz::{
    CaseRng, NoCoverage, cautious,
    coverage::CoverageCapture,
    curious,
    snapshot_hooks::{StreamSpec, case_from_stream, case_stream},
};
use kv::{KvConfig, run_case};
use snapshot_rewind::{Outcome, SnapshotPolicy, Snapshotted, Verdict, describe_us};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Args {
    mode: String,
    rss_mb: usize,
    n: usize,
    cases: usize,
    ops: usize,
    seed: u64,
    op_work_kb: usize,
    passes: usize,
    no_snapshots: bool,
    no_baseline: bool,
    verbose: bool,
    hints_only: bool,
}

fn parse() -> Args {
    let mut args = Args {
        mode: "demo".into(),
        rss_mb: 10,
        n: 16,
        cases: 200,
        ops: 64,
        seed: 1,
        op_work_kb: 0,
        passes: 1,
        no_snapshots: false,
        no_baseline: false,
        verbose: false,
        hints_only: false,
    };
    let mut it = std::env::args().skip(1);
    if let Some(mode) = it.next() {
        args.mode = mode;
    }
    while let Some(flag) = it.next() {
        let mut value = || it.next().expect("flag needs a value");
        match flag.as_str() {
            "--rss-mb" => args.rss_mb = value().parse().unwrap(),
            "--n" => args.n = value().parse().unwrap(),
            "--cases" => args.cases = value().parse().unwrap(),
            "--ops" => args.ops = value().parse().unwrap(),
            "--seed" => args.seed = value().parse().unwrap(),
            "--op-work-kb" => args.op_work_kb = value().parse().unwrap(),
            "--passes" => args.passes = value().parse().unwrap(),
            "--no-snapshots" => args.no_snapshots = true,
            "--no-baseline" => args.no_baseline = true,
            "--hints-only" => args.hints_only = true,
            "-v" | "--verbose" => args.verbose = true,
            other => panic!("unknown flag {other}"),
        }
    }
    args
}

fn config(args: &Args) -> KvConfig {
    KvConfig {
        arena_mb: args.rss_mb,
        passes: args.passes,
        max_ops: args.ops,
        op_work_kb: args.op_work_kb,
    }
}

fn policy(args: &Args) -> SnapshotPolicy {
    if args.hints_only {
        SnapshotPolicy::hints_only()
    } else {
        SnapshotPolicy::default()
    }
}

/// Cases that share the 4 setup bytes (`variant(3)` flavor draw) and diverge after.
fn shared_prefix_cases(seed: u64, n: usize) -> Vec<iterator_fuzz::Case> {
    (0..n)
        .map(|i| {
            case_from_stream(StreamSpec {
                seed: seed.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64),
                prefix: vec![0, 0, 0, 0],
                zero_tail: false,
            })
        })
        .collect()
}

fn verdict_name(outcome: &Outcome) -> &'static str {
    match outcome.verdict {
        Some(Verdict::Keep) => "keep",
        Some(Verdict::Discard) => "discard",
        Some(Verdict::Fail) => "FAIL",
        Some(Verdict::Panicked) => "PANIC",
        None => "CRASH",
    }
}

fn run_supervised(
    args: &Args,
    label: &str,
    policy: SnapshotPolicy,
    total: usize,
) -> (Duration, snapshot_rewind::SnapshotStats) {
    let config = config(args);
    let cases = shared_prefix_cases(args.seed, total);
    let iter = curious()
        .with_coverage(NoCoverage)
        .with_cases(cases)
        .take(total);
    let mut snap = Snapshotted::new(iter, policy);
    let started = Instant::now();
    let mut i = 0;
    snap.run(
        |rng| run_case(rng, &config).0,
        |outcome| {
            if args.verbose {
                println!(
                    "  [{label}] #{i:<3} {:>7} resumed_from={:<12} wall={:>9.3} ms body={:>9.3} ms holders+{}",
                    verdict_name(outcome),
                    outcome
                        .resumed_from
                        .map(|(id, cursor)| format!("H{id}@{cursor}"))
                        .unwrap_or_else(|| "fresh".into()),
                    outcome.wall.as_secs_f64() * 1e3,
                    outcome.body.as_secs_f64() * 1e3,
                    outcome.holders_created,
                );
            }
            i += 1;
            true
        },
    );
    let elapsed = started.elapsed();
    let stats = snap.stats().clone();
    snap.finish();
    (elapsed, stats)
}

fn run_inproc(args: &Args, total: usize) -> (Duration, usize) {
    let config = config(args);
    let cases = shared_prefix_cases(args.seed, total);
    let iter = curious()
        .with_coverage(NoCoverage)
        .with_cases(cases)
        .take(total);
    let started = Instant::now();
    let mut fails = 0;
    for mut rng in iter {
        let (verdict, _) = run_case(&mut rng, &config);
        if verdict == Verdict::Fail {
            fails += 1;
        }
        let _ = rng.coverage();
    }
    (started.elapsed(), fails)
}

fn setup_cost(args: &Args) -> Duration {
    let config = config(args);
    let started = Instant::now();
    let store = kv::Store::setup(&config, 0);
    std::hint::black_box(store.arena_len());
    started.elapsed()
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn demo(args: &Args) {
    let total = args.n + 1;
    let setup = setup_cost(args);
    println!(
        "== demo: arena {} MB, setup {:.2} ms in-process, 1 warm-up + {} continuations, {} ops each ==",
        args.rss_mb,
        ms(setup),
        args.n,
        args.ops
    );
    let (snap_wall, stats) = run_supervised(args, "snap", policy(args), total);
    println!("{}", stats.summary());
    println!(
        "snapshots      : {:>9.2} ms total, {:>8.3} ms/candidate ({} fresh, {} continuations)",
        ms(snap_wall),
        ms(snap_wall) / total as f64,
        stats.fresh_runs,
        stats.continuations
    );
    if !args.no_baseline {
        let (fs_wall, fs_stats) =
            run_supervised(args, "forkserver", SnapshotPolicy::disabled(), total);
        println!(
            "forkserver only: {:>9.2} ms total, {:>8.3} ms/candidate ({} fresh)",
            ms(fs_wall),
            ms(fs_wall) / total as f64,
            fs_stats.fresh_runs
        );
        let (ip_wall, _) = run_inproc(args, total);
        println!(
            "in-process     : {:>9.2} ms total, {:>8.3} ms/candidate",
            ms(ip_wall),
            ms(ip_wall) / total as f64
        );
        let cont = describe_us(&stats.continuation_wall_us);
        println!("continuation wall: {cont}");
        println!(
            "speedup vs in-process: {:.2}x, vs forkserver-without-snapshots: {:.2}x",
            ip_wall.as_secs_f64() / snap_wall.as_secs_f64(),
            fs_wall.as_secs_f64() / snap_wall.as_secs_f64()
        );
    }
}

fn latency(args: &Args) {
    let args = Args {
        ops: 0,
        ..args.clone()
    };
    let total = args.n + 1;
    println!(
        "== latency: arena {} MB, {} empty continuations (Spawn -> fork -> resume -> Finished -> exit -> reap) ==",
        args.rss_mb, args.n
    );
    let (wall, stats) = run_supervised(&args, "latency", policy(&args), total);
    println!("{}", stats.summary());
    println!(
        "total {:.2} ms; continuation wall {}; runner-side body {}",
        ms(wall),
        describe_us(&stats.continuation_wall_us),
        "(see body column with -v)"
    );
}

fn run_search<C: CoverageCapture + 'static>(
    args: &Args,
    label: &str,
    iter: impl Iterator<Item = CaseRng<C>>,
    policy: SnapshotPolicy,
    map_verdict: fn(Verdict) -> Verdict,
) -> (Duration, snapshot_rewind::SnapshotStats, usize, Option<iterator_fuzz::Case>, u64) {
    let config = config(args);
    let mut snap = Snapshotted::new(iter, policy);
    let started = Instant::now();
    let mut features = BTreeSet::new();
    let mut fails = 0u64;
    let mut first_fail = None;
    let mut count = 0usize;
    let verbose = args.verbose;
    snap.run(
        |rng| map_verdict(run_case(rng, &config).0),
        |outcome| {
            count += 1;
            features.extend(outcome.features.iter().copied());
            if outcome.verdict == Some(Verdict::Fail) {
                fails += 1;
                if first_fail.is_none() {
                    first_fail = outcome.case.clone();
                    println!(
                        "  [{label}] first failing case after {count} candidates, {:.1} ms",
                        ms(started.elapsed())
                    );
                }
            }
            if verbose && count % 50 == 0 {
                println!(
                    "  [{label}] {count} candidates, {} features, {:.1} ms",
                    features.len(),
                    ms(started.elapsed())
                );
            }
            true
        },
    );
    let elapsed = started.elapsed();
    let stats = snap.stats().clone();
    snap.finish();
    (elapsed, stats, features.len(), first_fail, fails)
}

fn curious_mode(args: &Args) {
    println!(
        "== curious: arena {} MB, {} candidates (0 features below means the binary is not sancov-instrumented; then the corpus never grows and curious only yields fresh roots) ==",
        args.rss_mb, args.cases
    );
    let configs: Vec<(&str, SnapshotPolicy)> = if args.no_snapshots {
        vec![("no-snapshots", SnapshotPolicy::disabled())]
    } else {
        vec![
            ("snapshots", policy(args)),
            ("no-snapshots", SnapshotPolicy::disabled()),
        ]
    };
    for (label, policy) in configs {
        let iter = curious().with_seed(args.seed).take(args.cases);
        let (wall, stats, features, _first_fail, fails) =
            run_search(args, label, iter, policy, |verdict| verdict);
        println!(
            "{label:>13}: {:>9.1} ms, {features} features, {fails} failing candidates, {} fresh / {} continuations, {} holders created, skipped prefix {:.1} ms",
            ms(wall),
            stats.fresh_runs,
            stats.continuations,
            stats.holders_created,
            stats.skipped_us as f64 / 1e3
        );
        if args.verbose {
            println!("{}", stats.summary());
        }
    }
}

fn cautious_mode(args: &Args) {
    println!(
        "== cautious: arena {} MB, find a failing case then minimise it ==",
        args.rss_mb
    );
    // Find a failing case in-process first (cheap for the search; setup runs each time).
    let config = config(args);
    let mut failing = None;
    let mut tried = 0;
    for mut rng in curious().with_seed(args.seed).take(args.cases.max(2000)) {
        tried += 1;
        let (verdict, ops) = run_case(&mut rng, &config);
        if verdict == Verdict::Fail {
            println!(
                "found failing case after {tried} candidates: {} ops: {}",
                ops.len(),
                kv::describe_ops(&ops)
            );
            failing = Some(rng.fork_case());
            rng.discard();
            break;
        }
        let _ = rng.coverage();
    }
    let Some(failing) = failing else {
        println!("no failing case found in {tried} candidates; try another --seed");
        return;
    };
    let spec = case_stream(&failing);
    println!(
        "failing stream: seed {} prefix {} bytes",
        spec.seed,
        spec.prefix.len()
    );
    let configs: Vec<(&str, SnapshotPolicy)> = if args.no_snapshots {
        vec![("no-snapshots", SnapshotPolicy::disabled())]
    } else {
        vec![
            ("snapshots", policy(args)),
            ("no-snapshots", SnapshotPolicy::disabled()),
        ]
    };
    for (label, policy) in configs {
        let iter = cautious().with_case(failing.clone()).take(args.cases);
        let (wall, stats, _features, _first_fail, fails) =
            run_search(args, label, iter, policy, |verdict| match verdict {
                Verdict::Keep => Verdict::Discard,
                other => other,
            });
        println!(
            "{label:>13}: {:>9.1} ms for {} candidates ({fails} still failing), {} fresh / {} continuations, {} holders, skipped prefix {:.1} ms",
            ms(wall),
            stats.candidates,
            stats.fresh_runs,
            stats.continuations,
            stats.holders_created,
            stats.skipped_us as f64 / 1e3
        );
        if args.verbose {
            println!("{}", stats.summary());
        }
    }
    // Show the minimal case dowsing ends up with (in-process, so we can print ops).
    let mut last_ops = None;
    for mut rng in cautious().with_case(failing.clone()).take(args.cases) {
        let (verdict, ops) = run_case(&mut rng, &config);
        if verdict == Verdict::Fail {
            last_ops = Some(ops);
            let _ = rng.coverage();
        } else {
            rng.discard();
        }
    }
    if let Some(ops) = last_ops {
        println!("smallest failing sequence seen: {}", kv::describe_ops(&ops));
    }
}

fn main() {
    let args = parse();
    match args.mode.as_str() {
        "demo" => demo(&args),
        "latency" => latency(&args),
        "curious" => curious_mode(&args),
        "cautious" => cautious_mode(&args),
        other => panic!("unknown mode {other}; expected demo|latency|curious|cautious"),
    }
}
