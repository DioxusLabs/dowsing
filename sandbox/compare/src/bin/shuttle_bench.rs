//! shuttle (randomized / PCT / DFS scheduler). shuttle has `thread::sleep` (a plain context
//! switch) and `Condvar::wait_timeout_while` (never times out — shuttle does not model time);
//! `variant(4)` maps onto shuttle's scheduler-controlled `rand`.

use std::time::Duration;

use shuttle::rand::Rng;
use shuttle::sync::{Condvar, MutexGuard};

fn wait_for_some<'a>(
    cv: &Condvar,
    guard: MutexGuard<'a, Option<u32>>,
    dur: Duration,
) -> MutexGuard<'a, Option<u32>> {
    cv.wait_timeout_while(guard, dur, |v| v.is_none())
        .unwrap()
        .0
}

dowsing_compare::models!(
    shuttle::sync,
    shuttle::thread,
    sleep = shuttle::thread::sleep,
    wait_for_some = wait_for_some
);

fn deadlock_rand() {
    let inverted = shuttle::rand::thread_rng().gen_range(0..4u32) == 3;
    deadlock(inverted)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let which = args.next().unwrap_or_default();
    let mode = args.next().unwrap_or_else(|| "random".into());
    let iters: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let run = |name: &str, f: fn()| {
        let label = format!("{mode} max={iters}");
        match mode.as_str() {
            "random" => {
                dowsing_compare::report("shuttle", name, &label, || shuttle::check_random(f, iters))
            }
            "pct" => {
                dowsing_compare::report("shuttle", name, &label, || shuttle::check_pct(f, iters, 2))
            }
            // DFS refuses random data, so the harness enumerates the four variants itself.
            "dfs" if name == "deadlock" => {
                dowsing_compare::report("shuttle", name, "dfs x4 variants", || {
                    for v in 0..4u32 {
                        shuttle::check_dfs(move || deadlock(v == 3), Some(iters));
                    }
                })
            }
            "dfs" => dowsing_compare::report("shuttle", name, &label, || {
                shuttle::check_dfs(f, Some(iters))
            }),
            _ => eprintln!("mode: random|pct|dfs"),
        }
    };
    match which.as_str() {
        "lost_update" => run("lost_update", lost_update),
        "deadlock" => run("deadlock", deadlock_rand),
        "sleep_race" => run("sleep_race", sleep_race),
        _ => eprintln!(
            "usage: shuttle_bench lost_update|deadlock|sleep_race [random|pct|dfs] [iters]"
        ),
    }
}
