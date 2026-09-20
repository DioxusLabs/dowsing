//! Same race as `lost_update`, behind an expensive single-threaded setup (a 64 MB table
//! that takes ~100 ms to build). Re-executing from scratch pays the setup every run;
//! restoring the root snapshot does not.

use std::hint::black_box;
use std::sync::{Arc, Mutex};

const ITERS: u64 = 2;
const TABLE_BYTES: usize = 64 << 20;

fn build_table() -> Vec<u64> {
    let mut table = vec![0u64; TABLE_BYTES / 8];
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    for slot in table.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *slot = x;
    }
    table
}

fn bump(counter: &Mutex<u64>, table: &[u64]) {
    for i in 0..ITERS {
        let v = *counter.lock().unwrap();
        black_box(table[i as usize]);
        *counter.lock().unwrap() = v + 1;
    }
}

fn main() {
    dowsing_target_rt::init();
    let table = Arc::new(build_table());
    let checksum = table.iter().fold(0u64, |a, b| a.wrapping_add(*b));
    black_box(checksum);
    let counter = Arc::new(Mutex::new(0u64));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let counter = Arc::clone(&counter);
            let table = Arc::clone(&table);
            std::thread::spawn(move || bump(&counter, &table))
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let total = *counter.lock().unwrap();
    assert_eq!(total, 2 * ITERS, "lost update");
}
