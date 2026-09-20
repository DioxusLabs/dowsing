//! Harness: run a scheduled target once, fuzz its schedule with dowsing, minimize a failure with
//! `cautious()`, and verify byte-for-byte replay.
//!
//! ```text
//! sched_fuzz run   <target>            one run with the FIFO schedule (verbose trace)
//! sched_fuzz fuzz  <target> [seed]     curious() -> fork_case -> cautious() -> replay check
//! sched_fuzz seeds <target> [n]        cases-to-first-failure over n seeds
//! sched_fuzz bench <target> [n]        native vs scheduled wall time, stops/case, us/stop
//! sched_fuzz replay <target> [n]       run the FIFO schedule n times, assert identical trace hash
//! ```

use iterator_fuzz::{Case, CaseRng, cautious, curious};
use std::{
    process::Command,
    rc::Rc,
    time::{Duration, Instant},
};
use thread_scheduler::{
    CaseScheduler, FifoScheduler, Outcome, RunReport, Shm, ShmCoverage, Supervisor,
};

const REPLAYS: usize = 100;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// `SCHED_DISCOVERY_CASES`: cap on curious() cases per seed.
fn discovery_cases() -> usize {
    env_usize("SCHED_DISCOVERY_CASES", 2000)
}

/// `SCHED_MIN_CASES`: cap on cautious() variants.
fn minimization_cases() -> usize {
    env_usize("SCHED_MIN_CASES", 1500)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = match args.split_first() {
        Some((cmd, rest)) => (cmd.as_str(), rest),
        None => usage(),
    };
    let target = rest.first().cloned().unwrap_or_else(|| usage());
    let extra = rest.get(1).and_then(|s| s.parse::<usize>().ok());
    let verbose = std::env::var_os("SCHED_VERBOSE").is_some();

    let shm = Rc::new(Shm::new().expect("memfd + mmap"));
    let mut sup = Supervisor::new(Rc::clone(&shm), &target, &[]);
    sup.verbose = verbose;

    match cmd {
        "run" => {
            let report = sup.run(&mut FifoScheduler).expect("supervised run");
            print_report(&report, true);
        }
        "replay" => replay_fifo(&sup, extra.unwrap_or(REPLAYS)),
        "bench" => bench(&sup, &target, extra.unwrap_or(20)),
        "fuzz" => {
            fuzz(&sup, extra.unwrap_or(0) as u64, true);
        }
        "seeds" => seeds(&sup, extra.unwrap_or(20)),
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!("usage: sched_fuzz (run|fuzz|seeds|bench|replay) <target-binary> [n]");
    std::process::exit(2)
}

fn print_report(report: &RunReport, trace: bool) {
    println!(
        "outcome {} | threads {} | scheduling points {} | ptrace stops {} | decisions {} ({} non-zero) | edges {} | wall {:.2?}",
        report.outcome,
        report.threads,
        report.scheduling_points(),
        report.stops,
        report.decisions.len(),
        report.non_zero_decisions(),
        report.edges,
        report.wall
    );
    if trace {
        print!("{}", report.describe());
    }
    if !report.uncontrolled.is_empty() {
        println!("uncontrolled: {:?}", report.uncontrolled);
    }
    if !report.stderr.trim().is_empty() {
        println!("target stderr:\n{}", indent(report.stderr.trim_end()));
    }
}

fn indent(s: &str) -> String {
    s.lines().map(|l| format!("    {l}\n")).collect()
}

fn replay_fifo(sup: &Supervisor, n: usize) {
    let mut hashes = std::collections::BTreeSet::new();
    let mut stops = 0usize;
    let mut wall = Duration::ZERO;
    for _ in 0..n {
        let report = sup.run(&mut FifoScheduler).expect("supervised run");
        hashes.insert(report.trace_hash());
        stops += report.stops;
        wall += report.wall;
    }
    println!(
        "{n} FIFO replays: {} distinct trace hash(es), avg {} stops, avg wall {:.2?}",
        hashes.len(),
        stops / n,
        wall / n as u32
    );
    assert_eq!(hashes.len(), 1, "FIFO schedule is not deterministic");
}

fn bench(sup: &Supervisor, target: &str, n: usize) {
    // Native.
    let start = Instant::now();
    let mut native_fail = 0;
    for _ in 0..n {
        let status = Command::new(target).status().expect("native run");
        if !status.success() {
            native_fail += 1;
        }
    }
    let native = start.elapsed() / n as u32;
    // Scheduled (FIFO, no preemption).
    let start = Instant::now();
    let mut stops = 0;
    let mut points = 0;
    let mut edges = 0;
    let mut sched_fail = 0;
    for _ in 0..n {
        let report = sup.run(&mut FifoScheduler).expect("supervised run");
        stops += report.stops;
        points += report.scheduling_points();
        edges += report.edges;
        if !report.outcome.is_ok() {
            sched_fail += 1;
        }
    }
    let scheduled = start.elapsed() / n as u32;
    let stops_per_case = stops as f64 / n as f64;
    println!(
        "native: {native:.2?}/run ({native_fail}/{n} failed) | scheduled FIFO: {scheduled:.2?}/run ({sched_fail}/{n} failed) = {:.1}x | {:.1} ptrace stops/case, {:.1} scheduling points/case, {} edges/case | {:.1} us/stop (whole scheduled wall / stops)",
        scheduled.as_secs_f64() / native.as_secs_f64().max(1e-9),
        stops_per_case,
        points as f64 / n as f64,
        edges / n as u64,
        scheduled.as_secs_f64() * 1e6 / stops_per_case
    );
}

struct Found {
    case: Case,
    report: RunReport,
    cases_tried: usize,
}

/// Run one dowsing case under the supervisor, returning the report. The caller finishes the rng.
fn run_case(sup: &Supervisor, rng: &mut CaseRng<ShmCoverage>) -> RunReport {
    let mut sched = CaseScheduler::new(rng);
    sup.run(&mut sched).expect("supervised run")
}

fn cost_of(report: &RunReport) -> usize {
    report.non_zero_decisions() * 1000 + (report.edges / 1024) as usize
}

fn discover(sup: &Supervisor, seed: u64, max_cases: usize) -> Option<Found> {
    let coverage = ShmCoverage::new(Rc::clone(sup.shm()));
    let mut tried = 0;
    for mut rng in curious()
        .with_coverage(coverage.clone())
        .with_seed(seed)
        .take(max_cases)
    {
        tried += 1;
        let report = run_case(sup, &mut rng);
        // Feed the schedule shape back as coverage so curious() explores new interleavings.
        coverage.add_features(
            report
                .trace
                .iter()
                .enumerate()
                .map(|(i, ev)| ((i as u64) << 32) ^ ((ev.thread as u64) << 16) ^ point_id(ev.kind)),
        );
        if !report.outcome.is_ok() {
            let case = rng.fork_case();
            rng.coverage().expect("finish discovery coverage");
            return Some(Found {
                case,
                report,
                cases_tried: tried,
            });
        }
        rng.coverage().expect("finish discovery coverage");
    }
    None
}

fn point_id(kind: thread_scheduler::PointKind) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::hash::DefaultHasher::new();
    kind.hash(&mut h);
    h.finish() & 0xffff
}

fn fuzz(sup: &Supervisor, seed: u64, verbose: bool) -> Option<(usize, usize)> {
    let start = Instant::now();
    let discovery_cases = discovery_cases();
    let Some(found) = discover(sup, seed, discovery_cases) else {
        println!(
            "seed {seed}: no failure in {discovery_cases} cases ({:.2?})",
            start.elapsed()
        );
        return None;
    };
    println!(
        "seed {seed}: failure after {} cases ({:.2?}): {}",
        found.cases_tried,
        start.elapsed(),
        found.report.outcome
    );
    if verbose {
        print_report(&found.report, true);
    }

    // Minimize: keep only variants with the same failure class.
    let coverage = ShmCoverage::new(Rc::clone(sup.shm()));
    let target_outcome = found.report.outcome.clone();
    let start = Instant::now();
    let mut best: Option<(usize, Case, RunReport)> = None;
    let mut reproducing = 0;
    let mut variants = 0;
    for mut variant in cautious()
        .with_coverage(coverage)
        .with_case(found.case.clone())
        .take(minimization_cases())
    {
        variants += 1;
        let report = run_case(sup, &mut variant);
        if same_class(&report.outcome, &target_outcome) {
            reproducing += 1;
            let cost = cost_of(&report);
            let case = variant.fork_case();
            variant
                .coverage_with_cost(cost)
                .expect("finish minimization coverage");
            if best.as_ref().is_none_or(|(c, _, _)| cost < *c) {
                best = Some((cost, case, report));
            }
        } else {
            variant.discard();
        }
    }
    let (cost, min_case, min_report) = best.expect("the found case itself reproduces");
    println!(
        "minimized in {:.2?}: {reproducing}/{variants} variants reproduced; best cost {cost}: {} non-zero variant spans, {} decisions consumed, outcome {}",
        start.elapsed(),
        min_report.non_zero_decisions(),
        min_report.decisions.len(),
        min_report.outcome
    );
    if verbose {
        println!("minimized schedule:");
        print_report(&min_report, true);
        println!("decisions: {:?}", min_report.decisions);
    }

    // Replay byte-for-byte.
    let start = Instant::now();
    let mut hashes = std::collections::BTreeSet::new();
    for _ in 0..REPLAYS {
        let coverage = ShmCoverage::new(Rc::clone(sup.shm()));
        let mut rng = curious()
            .with_coverage(coverage)
            .with_case(min_case.clone())
            .take(1)
            .next()
            .expect("replay case");
        let report = run_case(sup, &mut rng);
        rng.discard();
        assert_eq!(report.outcome, min_report.outcome, "replay outcome differs");
        hashes.insert(report.trace_hash());
    }
    hashes.insert(min_report.trace_hash());
    println!(
        "{REPLAYS} replays of the minimized case in {:.2?}: {} distinct trace hash(es) {:#x}",
        start.elapsed(),
        hashes.len(),
        min_report.trace_hash()
    );
    assert_eq!(hashes.len(), 1, "replay is not byte-for-byte deterministic");
    Some((found.cases_tried, min_report.non_zero_decisions()))
}

fn same_class(a: &Outcome, b: &Outcome) -> bool {
    match (a, b) {
        (Outcome::Exited(x), Outcome::Exited(y)) => x == y,
        (Outcome::Signaled(x), Outcome::Signaled(y)) => x == y,
        (Outcome::Deadlock { .. }, Outcome::Deadlock { .. }) => true,
        (Outcome::Timeout, Outcome::Timeout) => true,
        _ => false,
    }
}

fn seeds(sup: &Supervisor, n: usize) {
    let mut cases = Vec::new();
    let mut lengths = Vec::new();
    for seed in 0..n as u64 {
        if let Some((tried, len)) = fuzz(sup, seed, false) {
            cases.push(tried);
            lengths.push(len);
        }
    }
    cases.sort_unstable();
    lengths.sort_unstable();
    println!(
        "{}/{n} seeds found the bug; cases-to-first-failure min/median/max {}/{}/{}; minimized non-zero decisions min/median/max {}/{}/{}",
        cases.len(),
        cases.first().copied().unwrap_or(0),
        cases.get(cases.len() / 2).copied().unwrap_or(0),
        cases.last().copied().unwrap_or(0),
        lengths.first().copied().unwrap_or(0),
        lengths.get(lengths.len() / 2).copied().unwrap_or(0),
        lengths.last().copied().unwrap_or(0),
    );
}
