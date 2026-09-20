//! The discovery + minimisation loop shared by the examples: `curious()` until a case crashes
//! the target, then `cautious()` on the forked case, ranking reproducing variants by
//! `coverage_with_cost(decisions)` so the shortest exchange wins.

use std::time::{Duration, Instant};

use iterator_fuzz::{
    CaseCoverage, Cautious, Curious, NoCoverage, cautious, coverage::CoverageCapture, curious,
};

use crate::sandbox::{Sandbox, Verdict};

pub struct FuzzOptions {
    pub discovery_cases: usize,
    pub minimization_cases: usize,
    /// Use `ChildCoverage` (sancov counters from the child) instead of `NoCoverage`.
    pub coverage: bool,
    pub seed: Option<u64>,
    pub verbose: bool,
}

impl Default for FuzzOptions {
    fn default() -> Self {
        Self {
            discovery_cases: 20_000,
            minimization_cases: 2_000,
            coverage: true,
            seed: None,
            verbose: false,
        }
    }
}

#[derive(Debug)]
pub struct FuzzReport {
    pub discovery_cases: usize,
    pub discovery_time: Duration,
    pub timeouts: usize,
    pub supervisor_errors: usize,
    pub found: Option<Verdict>,
    pub minimization_cases: usize,
    pub minimization_time: Duration,
    pub reproducing_variants: usize,
    pub best: Option<(CaseCoverage, Verdict)>,
    pub syscalls: u64,
    pub continued: u64,
    pub time_skips: u64,
    /// Distinct unhandled-syscall notes seen across all cases (capped).
    pub unhandled: Vec<String>,
}

impl FuzzReport {
    pub fn cases_per_second(&self) -> f64 {
        let total = self.discovery_cases + self.minimization_cases;
        total as f64 / (self.discovery_time + self.minimization_time).as_secs_f64().max(1e-9)
    }

    pub fn print(&self) {
        println!(
            "discovery: {} cases in {:.2}s ({:.0} cases/s), {} timeouts, {} supervisor errors",
            self.discovery_cases,
            self.discovery_time.as_secs_f64(),
            self.discovery_cases as f64 / self.discovery_time.as_secs_f64().max(1e-9),
            self.timeouts,
            self.supervisor_errors
        );
        match &self.found {
            None => println!("no bug found"),
            Some(v) => {
                println!("bug found: {:?}", v.outcome);
                println!("  transcript ({} decisions):", v.decisions);
                for line in &v.transcript {
                    println!("    {line}");
                }
            }
        }
        if self.minimization_cases > 0 {
            println!(
                "minimization: {} variants in {:.2}s, {} reproduced",
                self.minimization_cases,
                self.minimization_time.as_secs_f64(),
                self.reproducing_variants
            );
        }
        if let Some((cov, v)) = &self.best {
            println!(
                "shrunk: {:?}, cost {:?}, {} features, {} rng bytes",
                v.outcome,
                cov.case_cost(),
                cov.feature_count(),
                cov.bytes_consumed()
            );
            for line in &v.transcript {
                println!("    {line}");
            }
        }
        println!(
            "syscalls intercepted: {} ({} continued into the kernel, {} timed waits skipped)",
            self.syscalls, self.continued, self.time_skips
        );
        if !self.unhandled.is_empty() {
            println!("unhandled syscall notes:");
            for u in &self.unhandled {
                println!("    {u}");
            }
        }
    }
}

/// Fuzz `target` inside `sandbox`.
pub fn fuzz(sandbox: &mut Sandbox, target: fn(), opts: &FuzzOptions) -> FuzzReport {
    if opts.coverage {
        let cov = sandbox.coverage();
        let mut cur = curious().with_coverage(cov.clone());
        let mut cau = cautious().with_coverage(cov);
        if let Some(seed) = opts.seed {
            cur = cur.with_seed(seed);
            cau = cau.with_seed(seed);
        }
        run(sandbox, target, opts, cur, cau)
    } else {
        let mut cur = curious().with_coverage(NoCoverage);
        let mut cau = cautious().with_coverage(NoCoverage);
        if let Some(seed) = opts.seed {
            cur = cur.with_seed(seed);
            cau = cau.with_seed(seed);
        }
        run(sandbox, target, opts, cur, cau)
    }
}

fn run<C: CoverageCapture>(
    sandbox: &mut Sandbox,
    target: fn(),
    opts: &FuzzOptions,
    curious: Curious<C>,
    cautious: Cautious<C>,
) -> FuzzReport {
    let mut report = FuzzReport {
        discovery_cases: 0,
        discovery_time: Duration::ZERO,
        timeouts: 0,
        supervisor_errors: 0,
        found: None,
        minimization_cases: 0,
        minimization_time: Duration::ZERO,
        reproducing_variants: 0,
        best: None,
        syscalls: 0,
        continued: 0,
        time_skips: 0,
        unhandled: Vec::new(),
    };
    let note = |report: &mut FuzzReport, v: &Verdict| {
        report.syscalls += v.syscalls;
        report.continued += v.continued;
        report.time_skips += v.time_skips;
        for u in &v.unhandled {
            if !report.unhandled.contains(u) && report.unhandled.len() < 32 {
                report.unhandled.push(u.clone());
            }
        }
    };

    let start = Instant::now();
    let mut case = None;
    for mut rng in curious.take(opts.discovery_cases) {
        report.discovery_cases += 1;
        let v = sandbox.run(&mut rng, target);
        note(&mut report, &v);
        match &v.outcome {
            crate::sandbox::Outcome::TimedOut => report.timeouts += 1,
            crate::sandbox::Outcome::SupervisorError(_) => report.supervisor_errors += 1,
            _ => {}
        }
        if opts.verbose {
            eprintln!("case {}: {:?} {:?}", report.discovery_cases, v.outcome, v.transcript);
        }
        if v.outcome.is_bug() {
            case = Some(rng.fork_case());
            let _ = rng.coverage_with_cost(v.decisions);
            report.found = Some(v);
            break;
        }
    }
    report.discovery_time = start.elapsed();
    let Some(case) = case else {
        return report;
    };

    let start = Instant::now();
    let mut cautious = cautious.with_case(case);
    for mut variant in cautious.by_ref().take(opts.minimization_cases) {
        report.minimization_cases += 1;
        let v = sandbox.run(&mut variant, target);
        note(&mut report, &v);
        if v.outcome.is_bug() {
            report.reproducing_variants += 1;
            if let Ok(cov) = variant.coverage_with_cost(v.decisions)
                && report.best.as_ref().is_none_or(|(best, _)| cov < *best)
            {
                report.best = Some((cov, v));
            }
        } else {
            variant.discard();
        }
    }
    report.minimization_time = start.elapsed();
    report
}
