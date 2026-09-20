//! End-to-end tests against the demo binaries (built by cargo for the test run).

use std::time::Duration;

use iterator_fuzz::{Case, NoCoverage, curious};
use virtual_time::{Outcome, RunReport, Sandbox};

fn natural(program: &str) -> Sandbox {
    Sandbox::new(program)
        .quiet(true)
        .max_jumps(0)
        .wall_limit(Duration::from_secs(20))
}

fn run_once(sandbox: &Sandbox) -> (Case, RunReport) {
    let mut search = curious().with_coverage(NoCoverage);
    let mut rng = search.by_ref().take(1).next().expect("one case");
    let report = sandbox.run(&mut rng);
    let case = rng.fork_case();
    rng.discard();
    (case, report)
}

fn replays_identical(sandbox: &Sandbox, case: &Case, report: &RunReport, n: usize) -> usize {
    (0..n)
        .filter(|_| {
            let mut rng = case.clone().replay();
            let again = sandbox.run(&mut rng);
            rng.discard();
            again.event_hash == report.event_hash && again.outcome == report.outcome
        })
        .count()
}

#[test]
fn std_time_apis_see_the_virtual_clock() {
    let sandbox = natural(env!("CARGO_BIN_EXE_probe_target"));
    let (case, report) = run_once(&sandbox);
    assert_eq!(report.outcome, Outcome::Exited(0), "{report:?}");
    // 1+2+3+4+5+1 s of std waits, 7 s timerfd, 0.5 s select, 1 ms spin.
    let virtual_secs = report.virtual_elapsed.as_secs_f64();
    assert!(
        (23.5..23.6).contains(&virtual_secs),
        "virtual {virtual_secs}"
    );
    assert!(
        report.wall < Duration::from_secs(5),
        "wall {:?}",
        report.wall
    );
    assert!(report.stats.sleeps >= 12 && report.stats.futex_parked >= 4);
    assert!(report.stats.poll_parked >= 2 && report.stats.timerfd == 1);
    // Multi-threaded: the schedule may legitimately differ between runs, so only require the
    // outcome and virtual duration to be stable.
    for _ in 0..5 {
        let mut rng = case.clone().replay();
        let again = sandbox.run(&mut rng);
        rng.discard();
        assert_eq!(again.outcome, Outcome::Exited(0));
        assert_eq!(
            again.virtual_elapsed.as_millis(),
            report.virtual_elapsed.as_millis()
        );
    }
}

#[test]
fn without_auxv_hiding_clock_reads_never_reach_the_supervisor() {
    let sandbox = natural(env!("CARGO_BIN_EXE_probe_target"))
        .hide_vdso(false)
        .arg("bench")
        .arg("1000");
    let (_, report) = run_once(&sandbox);
    assert_eq!(report.outcome, Outcome::Exited(0));
    assert_eq!(report.stats.clock_reads, 0);
    let hidden = natural(env!("CARGO_BIN_EXE_probe_target"))
        .arg("bench")
        .arg("1000");
    let (_, report) = run_once(&hidden);
    assert!(report.stats.clock_reads >= 1000, "{:?}", report.stats);
}

#[test]
fn backoff_target_fails_after_120_virtual_seconds_and_replays_identically() {
    let sandbox = Sandbox::new(env!("CARGO_BIN_EXE_backoff_target"))
        .quiet(true)
        .max_jumps(8)
        .wall_limit(Duration::from_secs(20));
    let mut found = None;
    for mut rng in curious().with_coverage(NoCoverage).take(300) {
        let report = sandbox.run(&mut rng);
        if report.outcome.is_failure() {
            let case = rng.fork_case();
            rng.discard();
            found = Some((case, report));
            break;
        }
        rng.discard();
    }
    let (case, report) = found.expect("the backoff bug should be found within 300 runs");
    assert_eq!(report.outcome, Outcome::Exited(101), "{report:?}");
    assert!(report.virtual_elapsed >= Duration::from_secs(120));
    assert!(
        report.wall < Duration::from_millis(500),
        "wall {:?}",
        report.wall
    );
    assert_eq!(replays_identical(&sandbox, &case, &report, 100), 100);
}

#[test]
fn tokio_current_thread_timers_are_virtual_and_deterministic() {
    let sandbox = Sandbox::new(env!("CARGO_BIN_EXE_backoff_tokio_target"))
        .quiet(true)
        .max_jumps(4)
        .wall_limit(Duration::from_secs(20));
    let (case, report) = run_once(&sandbox);
    assert!(
        matches!(report.outcome, Outcome::Exited(0) | Outcome::Exited(101)),
        "{report:?}"
    );
    assert!(report.stats.poll_parked >= 1, "{:?}", report.stats);
    assert!(
        report.wall < Duration::from_millis(500),
        "wall {:?}",
        report.wall
    );
    assert_eq!(replays_identical(&sandbox, &case, &report, 20), 20);
}

#[test]
fn hang_in_unsupervised_syscall_is_reported_by_the_watchdog() {
    // Opening a FIFO with no writer blocks in open(): not a time syscall, so the supervisor only
    // notices through the wall-clock watchdog.
    let fifo = std::env::temp_dir().join(format!("vt-hang-{}", std::process::id()));
    let sandbox = Sandbox::new("/bin/sh")
        .arg("-c")
        .arg(format!("mkfifo {0} && cat {0}", fifo.display()))
        .quiet(true)
        .wall_limit(Duration::from_millis(300));
    let (_, report) = run_once(&sandbox);
    let _ = std::fs::remove_file(&fifo);
    assert_eq!(report.outcome, Outcome::Hang, "{report:?}");
}
