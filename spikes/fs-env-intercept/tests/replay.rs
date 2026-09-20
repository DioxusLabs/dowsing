//! Replay determinism and minimization on the real demo target, without SanitizerCoverage (so it
//! runs under plain `cargo test`). The structured-config search needs coverage feedback to find
//! the bug in reasonable time (see `examples/sandboxed_config.rs`), so this test pins the config
//! file and lets random search find the entropy/env part of the trigger.

#[path = "../examples/demo_target/mod.rs"]
mod demo_target;
#[path = "../examples/demo_target/harness.rs"]
#[allow(dead_code)]
mod harness;

use std::sync::Arc;

use fs_env_intercept::{Content, Sandbox, Spec};
use harness::{is_bug, run_target, structured_config};
use iterator_fuzz::{NoCoverage, cautious, curious};

fn pinned_spec() -> Arc<Spec> {
    Arc::new(
        Spec::new()
            .file("/etc/app/app.conf", Content::Fixed(b"mode=strict\nretries=0\n".to_vec()))
            .file("/var/lib/app/state.db", Content::Random { max_len: 16 })
            .dir("/var/lib/app", 2)
            .env("APP_MODE", vec![Some("lenient"), Some("strict"), None]),
    )
}

#[test]
fn found_case_replays_identically_and_minimizes() {
    // The target's panic is the bug we hunt; keep the test's own failures visible.
    std::panic::set_hook(Box::new(|info| {
        if !info.location().is_some_and(|l| l.file().contains("demo_target")) {
            eprintln!("{info}");
        }
    }));
    let mut sandbox = Sandbox::install().expect("install sandbox");
    let spec = pinned_spec();

    // The trigger needs APP_MODE=strict (1/3), a full urandom read (1/3) whose first byte is 0
    // (1/256) and a successful getrandom (1/3): ~1 in 7 000 random cases.
    let mut found = None;
    for rng in curious().with_coverage(NoCoverage).take(200_000) {
        let (rng, report, result) = sandbox.run_case(rng, &spec, run_target);
        if is_bug(&result) {
            found = Some((rng.fork_case(), result.unwrap_err(), report));
            rng.discard();
            break;
        }
        rng.discard();
    }
    let (case, error, report) = found.expect("random search hits the pinned trigger");
    assert!(error.contains("index out of bounds"), "{error}");
    assert_eq!(report.entropy[0], 0, "nonce[0] must be zero: {:?}", report.entropy);

    for _ in 0..3 {
        let (rng, replayed, result) = sandbox.run_case(case.clone().replay(), &spec, run_target);
        assert_eq!(result.unwrap_err(), error);
        assert_eq!(replayed.files, report.files);
        assert_eq!(replayed.entropy, report.entropy);
        assert_eq!(replayed.applied_env, report.applied_env);
        rng.discard();
    }

    let mut minimized = None;
    for rng in cautious().with_coverage(NoCoverage).with_case(case).take(5_000) {
        let (rng, report, result) = sandbox.run_case(rng, &spec, run_target);
        if is_bug(&result) {
            let cost = report.cost();
            minimized = Some((rng.fork_case(), report));
            rng.coverage_with_cost(cost).unwrap();
        } else {
            rng.discard();
        }
    }
    let (_, minimized) = minimized.expect("the original case still fails");
    assert_eq!(minimized.applied_env, vec![("APP_MODE".to_string(), Some("strict".to_string()))]);
    assert!(
        minimized.entropy.iter().all(|b| *b == 0),
        "minimized entropy is all zero: {:?}",
        minimized.entropy
    );
    assert_eq!(minimized.non_default_variants, 0, "{minimized:?}");
    assert_eq!(minimized.files[0].1, b"mode=strict\nretries=0\n");
}

#[test]
fn structured_config_replays_byte_for_byte() {
    let mut sandbox = Sandbox::install().expect("install sandbox");
    // Same tree and generator as the demo, minus the environment (tests share one process
    // environment and the other test already mutates it).
    let spec = Arc::new(
        Spec::new()
            .file("/etc/app/app.conf", Content::Generate(Arc::new(structured_config)))
            .file("/var/lib/app/state.db", Content::Random { max_len: 16 })
            .dir("/var/lib/app", 2),
    );
    for rng in curious().with_coverage(NoCoverage).take(50) {
        let case = rng.fork_case();
        let (rng, first, _) = sandbox.run_case(rng, &spec, run_target);
        rng.discard();
        let (rng, second, _) = sandbox.run_case(case.replay(), &spec, run_target);
        rng.discard();
        assert_eq!(first.files, second.files);
        assert_eq!(first.entropy, second.entropy);
        assert_eq!(first.applied_env, second.applied_env);
    }
}
