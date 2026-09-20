//! Two threads, a check-then-act race on a Mutex<u64>: read under one lock, write under
//! another. Natively the interleaving that loses an update almost never happens.

use std::sync::{Arc, Mutex};

const ITERS: u64 = 2;

fn bump(counter: &Mutex<u64>) {
    for _ in 0..ITERS {
        let v = *counter.lock().unwrap();
        *counter.lock().unwrap() = v + 1;
    }
}

fn main() {
    dowsing_target_rt::init();
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
    let total = *counter.lock().unwrap();
    assert_eq!(total, 2 * ITERS, "lost update");
}
