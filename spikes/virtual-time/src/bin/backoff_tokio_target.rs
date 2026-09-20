//! Demo target: the same backoff bug on tokio timers.  `tokio::time::sleep` and
//! `tokio::time::timeout` drive the runtime's timer wheel, which parks in `epoll_wait` with a
//! millisecond timeout on the current-thread runtime (and on a worker thread plus futex-parked
//! workers on the multi-thread runtime, pass `--multi`).

#[path = "../announce.rs"]
mod announce;

use std::time::{Duration, Instant};

use rand::{Rng, SeedableRng, rngs::SmallRng};

const OVERALL_DEADLINE: Duration = Duration::from_secs(120);
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

async fn request(attempt: u32, succeed_after: u32, latency: Duration) -> Result<(), &'static str> {
    tokio::time::sleep(latency).await;
    if attempt >= succeed_after {
        Ok(())
    } else {
        Err("503 service unavailable")
    }
}

async fn run() {
    let mut rng = SmallRng::from_os_rng();
    let succeed_after = rng.random_range(1..=16_u32);

    let start = Instant::now();
    let deadline = start + OVERALL_DEADLINE;
    let mut backoff = INITIAL_BACKOFF;

    for attempt in 1.. {
        let now = Instant::now();
        let remaining = deadline
            .checked_duration_since(now)
            .expect("retry loop overshot its deadline: sleep ended after the deadline");
        eprintln!(
            "attempt {attempt}: t+{:.3}s remaining {:.3}s",
            now.duration_since(start).as_secs_f64(),
            remaining.as_secs_f64(),
        );
        let latency = Duration::from_millis(rng.random_range(5..=50));
        match tokio::time::timeout(remaining, request(attempt, succeed_after, latency)).await {
            Ok(Ok(())) => {
                eprintln!(
                    "success after {attempt} attempts, {:.3}s elapsed",
                    start.elapsed().as_secs_f64()
                );
                return;
            }
            Ok(Err(err)) => eprintln!("  failed: {err}"),
            Err(_) => {
                eprintln!("giving up: request timed out at the deadline");
                std::process::exit(2);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            eprintln!("giving up: deadline reached");
            std::process::exit(2);
        }
        let clamped = backoff.min(remaining);
        let jitter_ms = rng.random_range(0..=(backoff.as_millis() as u64 / 2).max(1));
        tokio::time::sleep(clamped + Duration::from_millis(jitter_ms)).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

fn main() {
    let multi = std::env::args().any(|a| a == "--multi");
    let runtime = if multi {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }
    .expect("build runtime");
    runtime.block_on(run());
}
