//! Supervisor demo: `curious()` finds the buggy-stack restore bug in a child process,
//! `cautious()` shrinks it, and `Case::replay()` confirms the shrunk case in-process.
//!
//!   buggy_stack_bridge [--mode fork|exec] [--child PATH] [--no-cmp] [--quiet]
//!                      [--discovery N] [--minimize N] [--seed N] [--bench N]

#[path = "../buggy_stack.rs"]
mod buggy_stack;

use buggy_stack::{check_stack, run_case};
use coverage_bridge::supervisor::{BridgeConfig, ChildCoverage, Mode, Status};
use iterator_fuzz::{Case, cautious, curious};
use std::{path::PathBuf, time::Instant};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut mode = Mode::Fork;
    let mut child: Option<PathBuf> = None;
    let mut cmp = true;
    let mut quiet = false;
    let mut discovery = 8_192usize;
    let mut minimization = 4_096usize;
    let mut bench: Option<usize> = None;
    let mut seed: Option<u64> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--seed" => seed = Some(iter.next().and_then(|v| v.parse().ok()).expect("--seed N")),
            "--mode" => {
                mode = match iter.next().map(String::as_str) {
                    Some("fork") => Mode::Fork,
                    Some("exec") => Mode::Exec,
                    other => panic!("--mode fork|exec, got {other:?}"),
                }
            }
            "--child" => child = Some(PathBuf::from(iter.next().expect("--child PATH"))),
            "--no-cmp" => cmp = false,
            "--quiet" => quiet = true,
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
            "--bench" => bench = Some(iter.next().and_then(|v| v.parse().ok()).expect("--bench N")),
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
    }
    let child = child.unwrap_or_else(|| {
        std::env::current_exe()
            .expect("current exe")
            .with_file_name("buggy_stack_child")
    });

    let config = BridgeConfig::new(&child, mode)
        .with_cmp_feedback(cmp)
        .quiet(quiet);
    let bridge = ChildCoverage::spawn(config).unwrap_or_else(|err| {
        eprintln!("cannot start target {}: {err}", child.display());
        std::process::exit(1);
    });
    let label = format!(
        "{}{}",
        match mode {
            Mode::Fork => "forkserver",
            Mode::Exec => "exec-per-case",
        },
        if cmp { "+cmp" } else { "" }
    );
    println!(
        "bridge {label}: target {} ({})",
        child.display(),
        if bridge.instrumented() {
            "sancov counters detected"
        } else {
            "instrumentation unknown until first case"
        }
    );

    if let Some(cases) = bench {
        // Same loop as `buggy_stack_child --bench`: curious() with every case fed back.
        let start = Instant::now();
        let mut failures = 0u64;
        let mut search = curious().with_coverage(bridge.clone());
        if let Some(seed) = seed {
            search = search.with_seed(seed);
        }
        for rng in search.take(cases) {
            let outcome = bridge.run(rng).expect("bridge run");
            failures += u64::from(outcome.status.is_failure());
            outcome.coverage().expect("coverage");
        }
        let elapsed = start.elapsed();
        println!(
            "bridge {label}: {cases} cases in {:.3}s = {:.0} exec/s ({failures} failing)",
            elapsed.as_secs_f64(),
            cases as f64 / elapsed.as_secs_f64()
        );
        print_phases(&bridge.stats());
        return;
    }

    // Discovery.
    let start = Instant::now();
    let mut found: Option<Case> = None;
    let mut executed = 0usize;
    let mut search = curious().with_coverage(bridge.clone());
    if let Some(seed) = seed {
        search = search.with_seed(seed);
    }
    for rng in search.take(discovery) {
        executed += 1;
        let outcome = bridge.run(rng).expect("bridge run");
        if let Status::Broken(reason) = &outcome.status {
            eprintln!("case {executed}: broken child: {reason}");
        }
        if outcome.status.is_failure() {
            println!(
                "bridge {label}: case {executed} failed with {:?} ({} bytes, {} features, cost {})",
                outcome.status, outcome.consumed, outcome.feature_count, outcome.cost
            );
            found = Some(outcome.case.clone());
            outcome.coverage().expect("discovery coverage");
            break;
        }
        outcome.coverage().expect("discovery coverage");
    }
    let discovery_time = start.elapsed();
    let stats = bridge.stats();
    println!(
        "bridge {label}: discovery ran {executed} cases in {discovery_time:.2?} = {:.0} exec/s",
        executed as f64 / discovery_time.as_secs_f64()
    );
    print_phases(&stats);
    let Some(case) = found else {
        println!("bridge {label}: no failure found in {discovery} cases");
        std::process::exit(1);
    };
    if !bridge.instrumented() {
        println!(
            "bridge {label}: WARNING target reported no coverage; build it with the sancov flags"
        );
    }

    // Minimization.
    let before = bridge.stats();
    let start = Instant::now();
    let mut best: Option<(iterator_fuzz::CaseCoverage, Case)> = None;
    let mut executed = 0usize;
    let mut reproduced = 0usize;
    let mut cautious = cautious().with_coverage(bridge.clone()).with_case(case);
    for variant in cautious.by_ref().take(minimization) {
        executed += 1;
        let outcome = bridge.run(variant).expect("bridge run");
        if outcome.status.is_failure() {
            reproduced += 1;
            let case = outcome.case.clone();
            let coverage = outcome.coverage().expect("minimization coverage");
            if best
                .as_ref()
                .is_none_or(|(best_coverage, _)| coverage < *best_coverage)
            {
                best = Some((coverage, case));
            }
        } else {
            outcome.discard();
        }
    }
    let minimize_time = start.elapsed();
    let after = bridge.stats();
    let (coverage, best_case) = best.expect("the seed case reproduces");
    println!(
        "bridge {label}: minimization ran {executed} cases ({reproduced} reproducing) in {minimize_time:.2?} = {:.0} exec/s",
        executed as f64 / minimize_time.as_secs_f64()
    );
    println!(
        "bridge {label}: best case cost {} ops, {} bytes, {} features",
        coverage.case_cost().get(),
        coverage.bytes_consumed(),
        coverage.feature_count()
    );
    print_phases(&delta(&before, &after));

    // In-process confirmation.
    let mut rng = best_case.replay();
    let (verdict, ops) = run_case(&mut rng);
    let error = check_stack(&ops).err();
    rng.discard();
    println!(
        "replay in-process: {} with {} ops ({} bytes)\n  ops: {ops:?}\n  error: {}",
        if verdict.failed {
            "REPRODUCED"
        } else {
            "did NOT reproduce"
        },
        ops.len(),
        coverage.bytes_consumed(),
        error.unwrap_or_default()
    );
    if !verdict.failed {
        std::process::exit(1);
    }
}

fn print_phases(stats: &coverage_bridge::supervisor::BridgeStats) {
    if stats.runs == 0 {
        return;
    }
    let per = |d: std::time::Duration| d.as_secs_f64() * 1e6 / stats.runs as f64;
    println!(
        "  per case: fill {:.1} us, launch {:.1} us, execute {:.1} us, decode {:.1} us (runs {}, retries {}, respawns {}, crashes {}, timeouts {})",
        per(stats.fill),
        per(stats.launch),
        per(stats.execute),
        per(stats.decode),
        stats.runs,
        stats.retries,
        stats.respawns,
        stats.crashes,
        stats.timeouts
    );
}

fn delta(
    before: &coverage_bridge::supervisor::BridgeStats,
    after: &coverage_bridge::supervisor::BridgeStats,
) -> coverage_bridge::supervisor::BridgeStats {
    coverage_bridge::supervisor::BridgeStats {
        runs: after.runs - before.runs,
        failures: after.failures - before.failures,
        crashes: after.crashes - before.crashes,
        timeouts: after.timeouts - before.timeouts,
        retries: after.retries - before.retries,
        respawns: after.respawns - before.respawns,
        fill: after.fill - before.fill,
        launch: after.launch - before.launch,
        execute: after.execute - before.execute,
        decode: after.decode - before.decode,
    }
}
