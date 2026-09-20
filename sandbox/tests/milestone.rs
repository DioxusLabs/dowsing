//! End-to-end checks against the instrumented targets in `targets/` (built on demand by
//! `build-targets.sh`). Sessions share `waitpid(-1)`, so tests that spawn a target serialize
//! on a mutex.

use dowsing_sandbox::{Budget, Event, Kind, Options, Outcome, Search, Session};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, Once};
use std::time::{Duration, Instant};

static BUILT: Once = Once::new();
static LOCK: Mutex<()> = Mutex::new(());

fn target(name: &str) -> (MutexGuard<'static, ()>, String) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin = dir.join("targets/target/release").join(name);
    BUILT.call_once(|| {
        if !bin.exists() {
            let status = std::process::Command::new(dir.join("build-targets.sh"))
                .status()
                .expect("run build-targets.sh");
            assert!(status.success(), "build-targets.sh failed");
        }
    });
    assert!(bin.exists(), "missing {}", bin.display());
    let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    (guard, bin.to_string_lossy().into_owned())
}

fn spawn(bin: &str) -> Session {
    Session::spawn(bin, &[], Options::default()).expect("spawn")
}

fn search_until_failure(bin: &str, seed: u64, runs: usize) -> Search {
    let mut search = Search::new(spawn(bin), seed).expect("root");
    let budget = Budget {
        runs,
        wall: Duration::from_secs(120),
        stop_on_failure: true,
    };
    search.run(&budget).expect("search");
    search
}

/// Run to the end with the default policy, returning the outcome and trace hash.
fn run_default(session: &mut Session) -> (Outcome, u64, Vec<Kind>) {
    let mut kinds = Vec::new();
    loop {
        match session.step().expect("step") {
            Event::Decision { kind, .. } => {
                kinds.push(kind);
                session.choose(0).expect("choose");
            }
            Event::Done(outcome) => return (outcome, session.world.trace_hash(), kinds),
        }
    }
}

#[test]
fn natively_passing_targets_pass_under_default_policy() {
    for name in ["lost_update", "deadlock", "sleep_race"] {
        let (_g, bin) = target(name);
        let native = std::process::Command::new(&bin)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(native.success(), "{name} fails natively");
        let mut s = spawn(&bin);
        let (outcome, _, kinds) = run_default(&mut s);
        assert_eq!(outcome, Outcome::Exited(0), "{name} under default policy");
        assert!(kinds.contains(&Kind::Schedule), "{name} never scheduled");
        assert!(s.uncontrolled.is_empty(), "{name}: {:?}", s.uncontrolled);
    }
}

#[test]
fn lost_update_race_found_replayed_and_shrunk() {
    let (_g, bin) = target("lost_update");
    let mut search = search_until_failure(&bin, 1, 3000);
    let failure = search
        .stats
        .failures
        .first()
        .cloned()
        .expect("race not found");
    assert_eq!(failure.outcome, Outcome::Exited(101));
    assert!(failure.stderr.contains("lost update"), "{}", failure.stderr);
    assert_eq!(search.stats.divergences, 0);
    assert!(
        search.stats.restores > 0,
        "search never restored a snapshot"
    );

    let choices: Vec<u32> = failure.decisions.iter().map(|d| d.choice).collect();
    let mut hashes = HashSet::new();
    for _ in 0..10 {
        let r = search.replay(&choices).expect("replay");
        assert_eq!(r.outcome, Outcome::Exited(101));
        hashes.insert(r.trace_hash);
    }
    assert_eq!(hashes.len(), 1, "replay is not deterministic");

    let (small, _) = search
        .shrink(&failure.decisions, &failure.outcome, 400)
        .expect("shrink");
    assert!(small.len() <= failure.decisions.len());
    let small_choices: Vec<u32> = small.iter().map(|d| d.choice).collect();
    assert_eq!(
        search.replay(&small_choices).unwrap().outcome,
        Outcome::Exited(101)
    );
    // The race needs both threads to run in the read/write window: never all-default.
    assert!(small.iter().any(|d| d.choice != 0));
}

#[test]
fn deadlock_found_via_variant_and_reported_as_deadlock() {
    let (_g, bin) = target("deadlock");
    let mut search = search_until_failure(&bin, 2, 3000);
    let failure = search
        .stats
        .failures
        .first()
        .cloned()
        .expect("deadlock not found");
    assert_eq!(
        failure.outcome,
        Outcome::Deadlock {
            waiting: vec![0, 1]
        }
    );
    assert_eq!(failure.decisions[0].kind, Kind::Variant);
    assert_eq!(
        failure.decisions[0].choice, 3,
        "only variant 3 inverts the lock order"
    );
    let (small, _) = search
        .shrink(&failure.decisions, &failure.outcome, 200)
        .expect("shrink");
    assert!(small.len() <= 5, "{small:?}");
}

#[test]
fn sleep_race_found_under_virtual_time() {
    let (_g, bin) = target("sleep_race");
    let t = Instant::now();
    let search = search_until_failure(&bin, 1, 3000);
    let failure = search
        .stats
        .failures
        .first()
        .cloned()
        .expect("timeout race not found");
    assert_eq!(failure.outcome, Outcome::Exited(101));
    assert!(
        failure.stderr.contains("worker result missing"),
        "{}",
        failure.stderr
    );
    // Every run sleeps 5 ms and may wait 50 ms; virtual time makes that free.
    let virtual_floor = Duration::from_millis(5) * search.stats.runs as u32;
    assert!(
        t.elapsed() < virtual_floor.max(Duration::from_secs(1)) * 4,
        "{:?} for {} runs",
        t.elapsed(),
        search.stats.runs
    );
}

#[test]
fn snapshot_restore_yields_identical_continuation() {
    let (_g, bin) = target("lost_update");
    let mut s = spawn(&bin);
    // Run a few decisions in, snapshot, then finish twice from that point.
    let mut steps = 0;
    let ev = loop {
        let ev = s.step().unwrap();
        match ev {
            Event::Decision { .. } if steps < 4 => {
                steps += 1;
                s.choose(0).unwrap();
            }
            other => break other,
        }
    };
    let Event::Decision { n, .. } = ev else {
        panic!("target finished before snapshot point")
    };
    let (id, st) = s.snapshot().unwrap();
    assert!(st.pages_copied > 0);
    let decisions_at_snapshot = s.world.decisions.clone();

    s.choose(0).unwrap();
    let (o1, h1, k1) = run_default(&mut s);
    assert_eq!(o1, Outcome::Exited(0));

    let rs = s.restore(id).unwrap();
    assert!(rs.pages_written > 0, "nothing was dirty after a full run?");
    assert!(rs.threads >= 1);
    assert_eq!(s.world.decisions, decisions_at_snapshot);
    assert!(s.world.outcome.is_none());

    s.choose(0).unwrap();
    let (o2, h2, k2) = run_default(&mut s);
    assert_eq!((o1, h1, k1), (o2, h2, k2), "restored continuation diverged");

    // A different choice from the same restored state changes the trace.
    s.restore(id).unwrap();
    s.choose(n - 1).unwrap();
    let (o3, h3, _) = run_default(&mut s);
    assert!(o3.is_ok());
    assert_ne!(h1, h3, "sibling choice produced the same trace");
}

#[test]
fn restore_after_target_exit_reanimates_process() {
    let (_g, bin) = target("lost_update");
    let mut s = spawn(&bin);
    let Event::Decision { .. } = s.step().unwrap() else {
        panic!()
    };
    let (id, _) = s.snapshot().unwrap();
    s.choose(0).unwrap();
    let (o, h, _) = run_default(&mut s);
    assert_eq!(o, Outcome::Exited(0));
    for _ in 0..3 {
        s.restore(id).unwrap();
        s.choose(0).unwrap();
        assert_eq!(run_default(&mut s).1, h);
    }
}

#[test]
fn restore_skips_expensive_setup_and_survives_its_teardown() {
    let (_g, bin) = target("slow_setup");
    let t = Instant::now();
    let mut search = Search::new(spawn(&bin), 1).expect("root");
    let fresh = t.elapsed();

    // The run frees the 64 MB table on the way out; restoring must bring it back intact.
    let search_budget = Budget {
        runs: 3000,
        wall: Duration::from_secs(120),
        stop_on_failure: true,
    };
    search.run(&search_budget).expect("search");
    let failure = search
        .stats
        .failures
        .first()
        .cloned()
        .expect("race not found");
    assert_eq!(failure.outcome, Outcome::Exited(101));
    assert!(failure.stderr.contains("lost update"), "{}", failure.stderr);
    assert_eq!(search.stats.divergences, 0);

    let choices: Vec<u32> = failure.decisions.iter().map(|d| d.choice).collect();
    let t = Instant::now();
    let mut hashes = HashSet::new();
    for _ in 0..5 {
        let r = search.replay(&choices).expect("replay");
        assert_eq!(r.outcome, Outcome::Exited(101));
        hashes.insert(r.trace_hash);
    }
    let replay = t.elapsed() / 5;
    assert_eq!(hashes.len(), 1, "replay is not deterministic");
    assert!(
        replay * 2 < fresh,
        "replay from snapshot {replay:?} vs fresh execution {fresh:?}"
    );
}

#[test]
fn unmodelled_syscalls_are_reported_not_hidden() {
    let (_g, bin) = target("uncontrolled");
    let mut s = spawn(&bin);
    let (outcome, _, _) = run_default(&mut s);
    assert_eq!(outcome, Outcome::Exited(0));
    assert!(
        s.uncontrolled
            .iter()
            .any(|u| u.contains(&format!("syscall {} passed through", libc::SYS_poll))),
        "{:?}",
        s.uncontrolled
    );
}

const INC: &[u8] = b"POST /inc HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
const CHECK: &[u8] = b"GET /check HTTP/1.1\r\nHost: x\r\n\r\n";

fn spawn_axum(bin: &str, clients: usize, requests: &[&[u8]]) -> Session {
    Session::spawn(
        bin,
        &[],
        Options {
            max_clients: clients,
            requests: requests.iter().map(|r| r.to_vec()).collect(),
            ..Options::default()
        },
    )
    .expect("spawn")
}

/// An unmodified axum + tokio (2 workers) server, driven entirely through the virtual socket
/// API: the request is accepted, read and answered, then every thread waits on the world.
#[test]
fn axum_serves_a_request_through_virtual_sockets() {
    let (_g, bin) = target("axum_counter");
    let mut s = spawn_axum(&bin, 1, &[b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"]);
    let (outcome, _, kinds) = run_default(&mut s);
    assert_eq!(outcome, Outcome::Quiescent);
    assert!(
        kinds.contains(&Kind::Chunk),
        "no delivery decision: {kinds:?}"
    );
    assert!(s.uncontrolled.is_empty(), "{:?}", s.uncontrolled);
    let c = &s.world.net.clients[0];
    assert!(c.accepted && c.fin && c.server_closed);
    assert_eq!(dowsing_sandbox::net::http_status(&c.response), Some(200));
    assert!(
        c.response.ends_with(b"ok\n"),
        "{:?}",
        String::from_utf8_lossy(&c.response)
    );
}

/// Two `POST /inc` and a `GET /check` from three clients: the search finds the schedule that
/// loses an update (the server's own assertion), replays it bit-identically and shrinks it.
#[test]
fn axum_lost_update_found_via_sockets_replayed_and_shrunk() {
    let (_g, bin) = target("axum_counter");
    let mut search = Search::new(spawn_axum(&bin, 3, &[INC, CHECK]), 1).expect("root");
    search.snapshot_every = 32;
    let budget = Budget {
        runs: 3000,
        wall: Duration::from_secs(120),
        stop_on_failure: true,
    };
    search.run(&budget).expect("search");
    let failure = search
        .stats
        .failures
        .first()
        .cloned()
        .expect("lost update not found");
    assert_eq!(failure.outcome, Outcome::Panic);
    assert!(failure.stderr.contains("lost update"), "{}", failure.stderr);
    assert_eq!(search.stats.divergences, 0);
    assert!(
        failure
            .decisions
            .iter()
            .filter(|d| d.kind == Kind::Payload)
            .count()
            >= 2,
        "{:?}",
        failure.decisions
    );

    let choices: Vec<u32> = failure.decisions.iter().map(|d| d.choice).collect();
    let mut hashes = HashSet::new();
    for _ in 0..5 {
        let r = search.replay(&choices).expect("replay");
        assert_eq!(r.outcome, Outcome::Panic);
        hashes.insert(r.trace_hash);
    }
    assert_eq!(hashes.len(), 1, "replay is not deterministic");

    let (small, _) = search
        .shrink(&failure.decisions, &failure.outcome, 200)
        .expect("shrink");
    let small_choices: Vec<u32> = small.iter().map(|d| d.choice).collect();
    assert_eq!(
        search.replay(&small_choices).unwrap().outcome,
        Outcome::Panic
    );
}
