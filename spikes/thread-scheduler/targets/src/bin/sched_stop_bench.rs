//! Scheduling-stop cost microbenchmark: `N` `sched_yield` syscalls (each one is a scheduling
//! point under the supervisor). Compare wall time native vs supervised and divide by `N`
//! (`N` from `STOP_BENCH_N`, default 10000).

use std::time::Instant;

fn main() {
    sched_target_rt::init();
    let n: u64 = std::env::var("STOP_BENCH_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);
    let start = Instant::now();
    for _ in 0..n {
        std::thread::yield_now();
    }
    let elapsed = start.elapsed();
    println!(
        "{n} sched_yield in {elapsed:.2?} = {:.2} us/yield | supervised {}",
        elapsed.as_secs_f64() * 1e6 / n as f64,
        sched_target_rt::supervised()
    );
}
