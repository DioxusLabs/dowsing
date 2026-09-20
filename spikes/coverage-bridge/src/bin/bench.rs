//! Micro-benchmarks for the bridge itself, independent of dowsing's search bookkeeping.
//!
//!   bench --child PATH [--cases N] [--rss MiB,MiB,...] [-- CHILD_ARGS...]
//!
//! Prints forkserver vs exec-per-case round trips for the given target (outcomes are discarded,
//! so dowsing's corpus bookkeeping stays out of the numbers), and fork cost against child RSS
//! when the target is `echo_child` (pass `-- --always-pass` so no case crashes or spins).

use coverage_bridge::supervisor::{BridgeConfig, ChildCoverage, Mode};
use iterator_fuzz::curious;
use std::ffi::OsString;
use std::{path::PathBuf, time::Instant};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut child: Option<PathBuf> = None;
    let mut cases = 2_000usize;
    let mut rss: Vec<usize> = Vec::new();
    let mut child_args: Vec<OsString> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                child_args = iter.by_ref().map(OsString::from).collect();
            }
            "--child" => child = Some(PathBuf::from(iter.next().expect("--child PATH"))),
            "--cases" => cases = iter.next().and_then(|v| v.parse().ok()).expect("--cases N"),
            "--rss" => {
                rss = iter
                    .next()
                    .expect("--rss MiB,MiB")
                    .split(',')
                    .map(|v| v.parse().expect("MiB"))
                    .collect()
            }
            other => panic!("unknown argument {other}"),
        }
    }
    let child = child.expect("--child PATH");

    for mode in [Mode::Fork, Mode::Exec] {
        let cases = if mode == Mode::Exec {
            cases.min(500)
        } else {
            cases
        };
        let mut config = BridgeConfig::new(&child, mode).quiet(true);
        config.args = child_args.clone();
        measure(config, cases, &format!("{mode:?}"));
    }
    for mib in rss {
        let mut config = BridgeConfig::new(&child, Mode::Fork).quiet(true);
        config.args = child_args.clone();
        config.args.extend(["--rss".into(), mib.to_string().into()]);
        measure(config, cases, &format!("Fork, child RSS +{mib} MiB"));
    }
}

fn measure(config: BridgeConfig, cases: usize, label: &str) {
    let bridge = match ChildCoverage::spawn(config) {
        Ok(bridge) => bridge,
        Err(err) => {
            println!("{label}: cannot spawn: {err}");
            return;
        }
    };
    // Warm up one case (first exec pays page-cache costs).
    for rng in curious().with_coverage(bridge.clone()).take(1) {
        bridge.run(rng).expect("warm-up").discard();
    }
    let before = bridge.stats();
    let start = Instant::now();
    let mut statuses = std::collections::BTreeMap::new();
    for rng in curious().with_coverage(bridge.clone()).take(cases) {
        let outcome = bridge.run(rng).expect("run");
        *statuses
            .entry(format!("{:?}", outcome.status))
            .or_insert(0usize) += 1;
        outcome.discard();
    }
    let elapsed = start.elapsed();
    let after = bridge.stats();
    let runs = (after.runs - before.runs).max(1) as f64;
    let us = |d: std::time::Duration| d.as_secs_f64() * 1e6 / runs;
    println!(
        "{label}: {cases} cases in {elapsed:.2?} = {:.0} exec/s; per case fill {:.1} us, launch {:.1} us, execute {:.1} us, decode {:.1} us; statuses {statuses:?}",
        cases as f64 / elapsed.as_secs_f64(),
        us(after.fill - before.fill),
        us(after.launch - before.launch),
        us(after.execute - before.execute),
        us(after.decode - before.decode),
    );
}
