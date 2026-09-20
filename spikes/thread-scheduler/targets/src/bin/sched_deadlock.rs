//! Classic AB/BA lock-order deadlock with two `std::sync::Mutex`es. Natively the threads almost
//! never overlap in the tiny critical section, so the program finishes; under the scheduler one
//! preemption between the two `lock()` calls of either thread deadlocks both, which the
//! supervisor detects as "no runnable thread, emulated futex waiters remain".

use std::sync::{Arc, Mutex};

#[inline(never)]
fn work(seed: u64) -> u64 {
    // A little instrumented work between the two lock acquisitions so the edge budget has
    // something to count.
    let mut x = seed;
    for i in 0..16u64 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(i);
        if x & 8 == 0 {
            x ^= i;
        }
    }
    x
}

fn main() {
    sched_target_rt::init();
    let a = Arc::new(Mutex::new(0u64));
    let b = Arc::new(Mutex::new(0u64));

    let t1 = {
        let (a, b) = (Arc::clone(&a), Arc::clone(&b));
        std::thread::spawn(move || {
            let mut ga = a.lock().unwrap();
            *ga += work(1);
            let mut gb = b.lock().unwrap();
            *gb += *ga;
        })
    };
    let t2 = {
        let (a, b) = (Arc::clone(&a), Arc::clone(&b));
        std::thread::spawn(move || {
            let mut gb = b.lock().unwrap();
            *gb += work(2);
            let mut ga = a.lock().unwrap();
            *ga += *gb;
        })
    };
    t1.join().unwrap();
    t2.join().unwrap();
    let total = *a.lock().unwrap() + *b.lock().unwrap();
    assert_ne!(total, 0);
}
