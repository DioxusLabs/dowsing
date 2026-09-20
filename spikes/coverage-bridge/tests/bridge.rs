//! Bridge behaviour tests against `echo_child` (uninstrumented) and, when the instrumented
//! `buggy_stack_child` is available at `$COVERAGE_BRIDGE_TARGET`, against sancov feedback.

use coverage_bridge::{
    Verdict,
    supervisor::{BridgeConfig, ChildCoverage, Mode, Status},
};
use iterator_fuzz::{
    Case, CaseRng, NoCoverage, cautious,
    coverage::CoverageCapture,
    curious,
    raw::{RawCase, RawSpan},
};
use rand::Rng;
use std::{path::PathBuf, time::Duration};

fn bin(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_BIN_EXE_echo_child"));
    path.set_file_name(name);
    path
}

/// Same harness as `echo_child::harness`, in-process, for trace comparison.
fn echo_harness<Capture: CoverageCapture>(rng: &mut CaseRng<Capture>) -> Verdict {
    let kind = rng.variant(5);
    let payload: Vec<u8> = rng
        .range(0..16)
        .map(|mut item| item.random::<u8>())
        .collect();
    let cost = payload.len() as u64;
    if kind == 1 {
        Verdict::failed().with_cost(cost)
    } else {
        Verdict::ok().with_cost(cost)
    }
}

fn scripted(kind: u8) -> Case {
    Case::from_raw(RawCase {
        seed: 0,
        prefix: vec![kind, 0, 0, 0],
        zero_tail: false,
        draws: vec![RawSpan {
            start: 0,
            len: 4,
            kind: RawSpan::WORD,
        }],
        semantics: vec![],
        sequences: vec![],
    })
}

fn spawn(mode: Mode) -> ChildCoverage {
    ChildCoverage::spawn(
        BridgeConfig::new(bin("echo_child"), mode)
            .quiet(true)
            .with_timeout(Duration::from_millis(300)),
    )
    .expect("spawn echo child")
}

#[test]
fn echo_child_runs_cases_in_both_modes() {
    for mode in [Mode::Fork, Mode::Exec] {
        let bridge = spawn(mode);
        let mut seen_pass = false;
        let mut seen_fail = false;
        for rng in curious().with_coverage(bridge.clone()).take(40) {
            let outcome = bridge.run(rng).expect("run");
            match outcome.status {
                Status::Passed => seen_pass = true,
                Status::Failed => seen_fail = true,
                // Kinds 2..5 crash, hang or exit; all must be reported, never Broken.
                Status::Crashed(_) | Status::TimedOut | Status::Exited(_) => {}
                ref other => panic!("{mode:?}: unexpected status {other:?}"),
            }
            assert!(
                outcome.consumed >= 4,
                "{mode:?}: consumed {}",
                outcome.consumed
            );
            outcome.coverage().expect("coverage");
        }
        assert!(
            seen_pass && seen_fail,
            "{mode:?}: pass={seen_pass} fail={seen_fail}"
        );
        let stats = bridge.stats();
        assert_eq!(stats.runs, 40);
    }
}

#[test]
fn child_trace_matches_in_process_trace() {
    let bridge = spawn(Mode::Fork);
    for seed in 0..20u64 {
        let mut expected_cases = curious().with_coverage(NoCoverage).with_seed(seed);
        let mut bridged_cases = curious().with_coverage(bridge.clone()).with_seed(seed);
        for _ in 0..5 {
            let mut expected = expected_cases.next().expect("in-process rng");
            let verdict = echo_harness(&mut expected);
            let expected_case = expected.fork_case();
            let expected_consumed = expected_case.clone().into_raw().prefix.len();
            expected
                .coverage_with_cost(verdict.cost as usize)
                .expect("coverage");

            let rng = bridged_cases.next().expect("bridged rng");
            let outcome = bridge.run(rng).expect("run");
            if !matches!(outcome.status, Status::Passed | Status::Failed) {
                // Crash/hang/exit paths export the whole budget or a partial trace; the
                // comparison only holds for cases that ran to completion.
                outcome.discard();
                continue;
            }
            assert_eq!(outcome.consumed, expected_consumed, "seed {seed}");
            assert_eq!(
                outcome.case.clone().into_raw(),
                expected_case.into_raw(),
                "seed {seed}"
            );
            assert_eq!(outcome.cost, verdict.cost);
            assert_eq!(outcome.status == Status::Failed, verdict.failed);
            outcome.coverage().expect("coverage");
        }
    }
}

#[test]
fn scripted_cases_report_every_exit_path() {
    let bridge = spawn(Mode::Fork);
    let expectations = [
        (0u8, "pass"),
        (1, "fail"),
        (2, "crash"),
        (3, "timeout"),
        (4, "exit"),
    ];
    for (kind, label) in expectations {
        let mut cases = cautious()
            .with_coverage(bridge.clone())
            .with_case(scripted(kind));
        let rng = cases.next().expect("seed case first");
        let outcome = bridge.run(rng).expect("run");
        match (label, &outcome.status) {
            ("pass", Status::Passed)
            | ("fail", Status::Failed)
            | ("crash", Status::Crashed(libc::SIGSEGV))
            | ("timeout", Status::TimedOut)
            | ("exit", Status::Exited(7)) => {}
            other => panic!("kind {kind}: {other:?}"),
        }
        if label == "pass" || label == "fail" {
            // The scripted prefix is 4 bytes; the range length and payload follow.
            assert!(outcome.consumed > 4);
            let raw = outcome.case.clone().into_raw();
            assert_eq!(raw.prefix[..4], [kind, 0, 0, 0]);
            assert!(
                !raw.semantics.is_empty(),
                "range() should record semantic spans"
            );
        }
        outcome.coverage().expect("coverage");
    }
    let stats = bridge.stats();
    assert_eq!(stats.crashes, 1);
    assert_eq!(stats.timeouts, 1);
    assert!(
        stats.respawns == 0,
        "forkserver must survive case crashes: {stats:?}"
    );
}

#[test]
fn forkserver_survives_after_timeout_and_keeps_serving() {
    let bridge = spawn(Mode::Fork);
    for _ in 0..3 {
        let mut cases = cautious()
            .with_coverage(bridge.clone())
            .with_case(scripted(3));
        let outcome = bridge.run(cases.next().unwrap()).expect("run");
        assert_eq!(outcome.status, Status::TimedOut);
        outcome.discard();
        let mut cases = cautious()
            .with_coverage(bridge.clone())
            .with_case(scripted(0));
        let outcome = bridge.run(cases.next().unwrap()).expect("run");
        assert_eq!(outcome.status, Status::Passed);
        outcome.discard();
    }
}

#[test]
fn absorbed_trace_replays_identically() {
    let bridge = spawn(Mode::Fork);
    let mut cases = curious().with_coverage(bridge.clone()).with_seed(7);
    let mut checked = 0;
    while checked < 10 {
        let outcome = bridge.run(cases.next().unwrap()).expect("run");
        if !matches!(outcome.status, Status::Passed | Status::Failed) {
            outcome.discard();
            continue;
        }
        let case = outcome.case.clone();
        let expected_failed = outcome.status == Status::Failed;
        outcome.coverage().expect("coverage");
        let mut replay = case.clone().replay();
        let verdict = echo_harness(&mut replay);
        assert_eq!(verdict.failed, expected_failed);
        assert_eq!(replay.fork_case().into_raw(), case.into_raw());
        replay.discard();
        checked += 1;
    }
}

#[test]
fn instrumented_target_reports_features() {
    let Some(target) = std::env::var_os("COVERAGE_BRIDGE_TARGET") else {
        eprintln!("skipped: set COVERAGE_BRIDGE_TARGET to an instrumented buggy_stack_child");
        return;
    };
    for mode in [Mode::Fork, Mode::Exec] {
        let bridge = ChildCoverage::spawn(BridgeConfig::new(&target, mode).quiet(true)).unwrap();
        let mut total_features = 0usize;
        for rng in curious().with_coverage(bridge.clone()).take(20) {
            let outcome = bridge.run(rng).expect("run");
            assert!(
                matches!(outcome.status, Status::Passed | Status::Failed),
                "{:?}",
                outcome.status
            );
            total_features += outcome.feature_count;
            let coverage = outcome.coverage().expect("coverage");
            assert!(
                coverage.feature_count() > 0,
                "{mode:?}: no features decoded"
            );
        }
        assert!(bridge.instrumented(), "{mode:?}: counters not detected");
        assert!(total_features > 0);
    }
}
