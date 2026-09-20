//! Missed notification: the worker waits on a `Condvar` without re-checking the predicate, so if
//! the main thread's `notify_one` happens *before* the worker reaches `wait`, the worker sleeps
//! forever. Natively the main thread does enough work after `spawn` that the worker practically
//! always waits first; the scheduler only has to run the main thread through `notify_one` before
//! letting the worker run. The resulting hang is an emulated futex deadlock for the supervisor.

use std::sync::{Arc, Condvar, Mutex};

#[inline(never)]
fn prepare(n: u64) -> u64 {
    let mut acc = 0u64;
    for i in 0..n {
        acc = acc.wrapping_mul(31).wrapping_add(i ^ (acc >> 3));
    }
    acc
}

fn main() {
    sched_target_rt::init();
    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    let worker = {
        let pair = Arc::clone(&pair);
        std::thread::spawn(move || {
            let (lock, cvar) = &*pair;
            let guard = lock.lock().unwrap();
            // BUG: no `while !*guard` loop -> a notification sent before this point is lost.
            let guard = cvar.wait(guard).unwrap();
            assert!(*guard, "woken without the flag being set");
        })
    };

    let result = prepare(200_000);
    {
        let (lock, cvar) = &*pair;
        *lock.lock().unwrap() = result != 42;
        cvar.notify_one();
    }
    worker.join().unwrap();
}
