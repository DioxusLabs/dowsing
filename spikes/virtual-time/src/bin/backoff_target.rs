//! Demo target: a std-only retry loop with exponential backoff, jitter and a 120 s overall
//! deadline.  Bug: the jitter is added *after* the sleep is clamped to the remaining budget, so
//! the last retry can sleep past the deadline; the next iteration then computes
//! `deadline.checked_duration_since(now)` and panics.  Under real time this takes at least two
//! minutes of wall clock to reach.  No fuzzing API is linked: the only inputs are the clock and
//! `getrandom`, both answered by the sandbox.

#[path = "../announce.rs"]
mod announce;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::{Rng, SeedableRng, rngs::SmallRng};

const OVERALL_DEADLINE: Duration = Duration::from_secs(120);
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Fake flaky server: fails until `succeed_after` attempts have been made.
fn request(attempt: u32, succeed_after: u32) -> Result<(), &'static str> {
    if attempt >= succeed_after {
        Ok(())
    } else {
        Err("503 service unavailable")
    }
}

fn main() {
    let mut rng = SmallRng::from_os_rng();
    // The "server" recovers after a random number of attempts (1..=16).
    let succeed_after = rng.random_range(1..=16_u32);

    let start = Instant::now();
    let wall_start = SystemTime::now();
    let deadline = start + OVERALL_DEADLINE;
    let mut backoff = INITIAL_BACKOFF;

    for attempt in 1.. {
        let now = Instant::now();
        let remaining = deadline
            .checked_duration_since(now)
            .expect("retry loop overshot its deadline: sleep ended after the deadline");
        eprintln!(
            "attempt {attempt}: t+{:.3}s remaining {:.3}s (unix {})",
            now.duration_since(start).as_secs_f64(),
            remaining.as_secs_f64(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        match request(attempt, succeed_after) {
            Ok(()) => {
                eprintln!(
                    "success after {attempt} attempts, {:.3}s elapsed (wall clock moved {:?})",
                    start.elapsed().as_secs_f64(),
                    SystemTime::now().duration_since(wall_start)
                );
                return;
            }
            Err(err) => eprintln!("  failed: {err}"),
        }
        if remaining.is_zero() {
            eprintln!("giving up: deadline reached");
            std::process::exit(2);
        }
        // Clamp to the remaining budget ... then add jitter.  That is the bug.
        let clamped = backoff.min(remaining);
        let jitter_ms = rng.random_range(0..=(backoff.as_millis() as u64 / 2).max(1));
        let sleep_for = clamped + Duration::from_millis(jitter_ms);
        std::thread::sleep(sleep_for);
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}
