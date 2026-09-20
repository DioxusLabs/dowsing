//! Real lost update: two `std::thread`s share an `Arc<Mutex<u64>>` and each performs a
//! check-then-act sequence with *two separate* lock acquisitions. Uncontended `Mutex::lock`
//! makes no syscall, so this never fails natively on this machine (see README), but a scheduler
//! that preempts between the two `lock()` calls exposes the bug.

use std::sync::{Arc, Mutex};

const ITERS: u64 = 2;

fn bump(counter: &Mutex<u64>) {
    for _ in 0..ITERS {
        let v = *counter.lock().unwrap();
        // BUG: the mutex is released here; another thread can read the same `v`.
        *counter.lock().unwrap() = v + 1;
    }
}

fn main() {
    sched_target_rt::init();
    let counter = Arc::new(Mutex::new(0u64));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let counter = Arc::clone(&counter);
            std::thread::spawn(move || bump(&counter))
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let final_count = *counter.lock().unwrap();
    assert_eq!(final_count, 2 * ITERS, "lost update");
}
