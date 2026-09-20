//! Edge-callback overhead microbenchmark. Two loops:
//! * `latency`: a serial dependency chain (callback work overlaps with the chain);
//! * `throughput`: independent iterations (callback work is on the critical path).
//! Prints ns/iteration and the edges seen by the shared mapping (if any); compare
//! uninstrumented / instrumented-unattached / instrumented-attached builds.

use std::{hint::black_box, time::Instant};

const ITERS: u64 = 20_000_000;

#[inline(never)]
fn step(x: u64) -> u64 {
    let mut y = x
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    if y & 1 == 0 {
        y ^= y >> 13;
    } else {
        y = y.rotate_left(7);
    }
    if y % 3 == 0 {
        y = y.wrapping_add(x);
    }
    y
}

#[inline(never)]
fn classify(i: u64) -> u64 {
    match i % 4 {
        0 => i >> 2,
        1 => i.wrapping_mul(3),
        2 => i ^ 0x55,
        _ => i.rotate_left(3),
    }
}

fn measure(name: &str, f: impl FnOnce() -> u64) {
    let before = sched_target_rt::edges();
    let start = Instant::now();
    let result = f();
    let elapsed = start.elapsed();
    let edges = sched_target_rt::edges() - before;
    println!(
        "{name}: iters {ITERS} result {result} | {:.2} ns/iter | edges {edges} ({:.2} edges/iter) | attached {}",
        elapsed.as_nanos() as f64 / ITERS as f64,
        edges as f64 / ITERS as f64,
        sched_target_rt::supervised()
    );
}

fn main() {
    sched_target_rt::init();
    measure("latency", || {
        let mut x = 1u64;
        for _ in 0..ITERS {
            x = step(black_box(x));
        }
        x
    });
    measure("throughput", || {
        let mut acc = 0u64;
        for i in 0..ITERS {
            acc = acc.wrapping_add(classify(black_box(i)));
        }
        acc
    });
}
