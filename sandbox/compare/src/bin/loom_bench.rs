//! loom (exhaustive model checker). Substitutions loom forces: `thread::sleep` does not exist
//! (→ `yield_now`), `Condvar::wait_timeout` never times out (loom has no notion of time), and
//! `variant(4)` has no equivalent — the harness enumerates the four values itself.

use std::time::Duration;

use loom::sync::{Condvar, MutexGuard};

fn wait_for_some<'a>(
    cv: &Condvar,
    mut guard: MutexGuard<'a, Option<u32>>,
    dur: Duration,
) -> MutexGuard<'a, Option<u32>> {
    while guard.is_none() {
        guard = cv.wait_timeout(guard, dur).unwrap().0;
    }
    guard
}

dowsing_compare::models!(
    loom::sync,
    loom::thread,
    sleep = |_d: Duration| loom::thread::yield_now(),
    wait_for_some = wait_for_some
);

fn main() {
    let which = std::env::args().nth(1).unwrap_or_default();
    match which.as_str() {
        "lost_update" => dowsing_compare::report("loom", "lost_update", "exhaustive", || {
            loom::model(lost_update)
        }),
        // loom reports a deadlock with a non-unwinding panic (process abort), so each variant
        // runs in a child and the iteration count is read from its trace.
        "deadlock" => {
            let exe = std::env::current_exe().unwrap();
            let t = std::time::Instant::now();
            let mut iterations = 0;
            let mut found = None;
            for v in 0..4u32 {
                let out = std::process::Command::new(&exe)
                    .args(["deadlock-one", &v.to_string()])
                    .env("DOWSING_COMPARE_TRACE", "1")
                    .output()
                    .unwrap();
                let err = String::from_utf8_lossy(&out.stderr);
                iterations += err.lines().filter(|l| l.starts_with("iteration ")).count();
                if !out.status.success() {
                    found = Some(
                        err.lines()
                            .find(|l| l.contains("deadlock") || l.contains("panicked"))
                            .unwrap_or("aborted")
                            .to_string(),
                    );
                    break;
                }
            }
            let ms = t.elapsed().as_secs_f64() * 1e3;
            println!(
                "tool=loom target=deadlock mode=\"exhaustive x4 variants\" iterations={iterations} time_ms={ms:.1} found={} {}",
                found.is_some(),
                found.map(|m| format!("msg={m:?}")).unwrap_or_default()
            );
        }
        "deadlock-one" => {
            let v: u32 = std::env::args().nth(2).unwrap().parse().unwrap();
            loom::model(move || deadlock(v == 3));
        }
        "sleep_race" => dowsing_compare::report("loom", "sleep_race", "exhaustive", || {
            loom::model(sleep_race)
        }),
        _ => eprintln!("usage: loom_bench lost_update|deadlock|sleep_race"),
    }
}
