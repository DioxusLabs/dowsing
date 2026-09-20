//! The three sandbox demo bugs (`sandbox/targets/src/bin/{lost_update,deadlock,sleep_race}.rs`)
//! written against a pluggable `sync`/`thread` namespace so the same code can be checked by
//! loom and shuttle. Semantics are kept identical to the targets; the only substitutions are
//! the ones the tool forces (see the per-tool notes in `bin/`).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

pub static ITERATIONS: AtomicUsize = AtomicUsize::new(0);

pub fn tick() {
    let n = ITERATIONS.fetch_add(1, Ordering::Relaxed) + 1;
    if std::env::var_os("DOWSING_COMPARE_TRACE").is_some() {
        eprintln!("iteration {n}");
    }
}

/// Runs `f`, capturing the first panic (the tool's failure report) and printing one result line.
pub fn report(tool: &str, target: &str, mode: &str, f: impl FnOnce()) {
    ITERATIONS.store(0, Ordering::Relaxed);
    std::panic::set_hook(Box::new(|_| {}));
    let t = Instant::now();
    let r = catch_unwind(AssertUnwindSafe(f));
    let ms = t.elapsed().as_secs_f64() * 1e3;
    let _ = std::panic::take_hook();
    let iters = ITERATIONS.load(Ordering::Relaxed);
    let (found, why) = match r {
        Ok(()) => (false, String::new()),
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            (true, msg.lines().next().unwrap_or("").to_string())
        }
    };
    println!(
        "tool={tool} target={target} mode={mode} iterations={iters} time_ms={ms:.1} found={found} {}",
        if found { format!("msg={why:?}") } else { String::new() }
    );
}

#[macro_export]
macro_rules! models {
    ($sync:path, $thread:path, sleep = $sleep:expr, wait_for_some = $wait:path) => {
        use $sync as sync;
        use $thread as thread;

        pub const ITERS: u64 = 2;

        fn bump(counter: &sync::Mutex<u64>) {
            for _ in 0..ITERS {
                let v = *counter.lock().unwrap();
                *counter.lock().unwrap() = v + 1;
            }
        }

        pub fn lost_update() {
            $crate::tick();
            let counter = sync::Arc::new(sync::Mutex::new(0u64));
            let workers: Vec<_> = (0..2)
                .map(|_| {
                    let counter = sync::Arc::clone(&counter);
                    thread::spawn(move || bump(&counter))
                })
                .collect();
            for worker in workers {
                worker.join().unwrap();
            }
            let total = *counter.lock().unwrap();
            assert_eq!(total, 2 * ITERS, "lost update");
        }

        pub fn deadlock(inverted: bool) {
            $crate::tick();
            let a = sync::Arc::new(sync::Mutex::new(0u32));
            let b = sync::Arc::new(sync::Mutex::new(0u32));
            let t = {
                let (a, b) = (sync::Arc::clone(&a), sync::Arc::clone(&b));
                thread::spawn(move || {
                    if inverted {
                        let gb = b.lock().unwrap();
                        let mut ga = a.lock().unwrap();
                        *ga += *gb;
                    } else {
                        let ga = a.lock().unwrap();
                        let mut gb = b.lock().unwrap();
                        *gb += *ga;
                    }
                })
            };
            {
                let mut ga = a.lock().unwrap();
                let gb = b.lock().unwrap();
                *ga += *gb + 1;
            }
            t.join().unwrap();
        }

        pub fn sleep_race() {
            $crate::tick();
            let slot = sync::Arc::new((sync::Mutex::new(None::<u32>), sync::Condvar::new()));
            let worker = {
                let slot = sync::Arc::clone(&slot);
                thread::spawn(move || {
                    ($sleep)(std::time::Duration::from_millis(5));
                    let (m, cv) = &*slot;
                    *m.lock().unwrap() = Some(42);
                    cv.notify_one();
                })
            };
            let (m, cv) = &*slot;
            let guard = m.lock().unwrap();
            let guard = $wait(cv, guard, std::time::Duration::from_millis(50));
            let value = guard.expect("worker result missing");
            drop(guard);
            worker.join().unwrap();
            assert_eq!(value, 42);
        }
    };
}
