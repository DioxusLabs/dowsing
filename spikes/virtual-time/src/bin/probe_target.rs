//! Exercises every std time API the sandbox claims to handle and prints what the target observed.
//! Exit code 0 if every virtual duration matched what was requested; the sandbox harness
//! compares the wall time against the virtual seconds this program reports.

#[path = "../announce.rs"]
mod announce;

use std::{
    sync::{Arc, Condvar, Mutex, mpsc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn check(name: &str, observed: Duration, expected: Duration, failures: &mut u32) {
    let ok = observed >= expected && observed < expected + Duration::from_millis(50);
    println!(
        "{name}: observed {:.6}s expected {:.3}s {}",
        observed.as_secs_f64(),
        expected.as_secs_f64(),
        if ok { "ok" } else { "MISMATCH" }
    );
    if !ok {
        *failures += 1;
    }
}

fn main() {
    let mut failures = 0;
    let start = Instant::now();
    let wall = SystemTime::now();
    println!(
        "unix time at start: {}",
        wall.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    );

    // thread::sleep -> clock_nanosleep
    let t = Instant::now();
    thread::sleep(Duration::from_secs(1));
    check("thread::sleep(1s)", t.elapsed(), Duration::from_secs(1), &mut failures);

    // park_timeout -> futex WAIT_BITSET with absolute monotonic deadline
    let t = Instant::now();
    thread::park_timeout(Duration::from_secs(2));
    check("park_timeout(2s)", t.elapsed(), Duration::from_secs(2), &mut failures);

    // Condvar::wait_timeout
    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    let guard = pair.0.lock().unwrap();
    let t = Instant::now();
    let (_guard, res) = pair.1.wait_timeout(guard, Duration::from_secs(3)).unwrap();
    assert!(res.timed_out());
    check("Condvar::wait_timeout(3s)", t.elapsed(), Duration::from_secs(3), &mut failures);
    drop(_guard);

    // mpsc recv_timeout
    let (tx, rx) = mpsc::channel::<u32>();
    let t = Instant::now();
    assert!(rx.recv_timeout(Duration::from_secs(4)).is_err());
    check("recv_timeout(4s)", t.elapsed(), Duration::from_secs(4), &mut failures);

    // Cross-thread: a worker sleeps 5 s virtual then sends; main blocks in an untimed recv
    // (futex WAIT without timeout), so the wake must come from FUTEX_WAKE matching.
    let t = Instant::now();
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_secs(5));
        tx.send(42).unwrap();
        // Then wait to be joined (untimed futex).
    });
    assert_eq!(rx.recv().unwrap(), 42);
    check("worker sleep(5s) + recv()", t.elapsed(), Duration::from_secs(5), &mut failures);
    worker.join().unwrap();

    // Mutex handoff between two threads with a timed wait in between.
    let shared = Arc::new(Mutex::new(0_u32));
    let s2 = Arc::clone(&shared);
    let t = Instant::now();
    let h = thread::spawn(move || {
        for _ in 0..10 {
            *s2.lock().unwrap() += 1;
            thread::sleep(Duration::from_millis(100));
        }
    });
    h.join().unwrap();
    assert_eq!(*shared.lock().unwrap(), 10);
    check("10 x sleep(100ms) in worker", t.elapsed(), Duration::from_secs(1), &mut failures);

    // SystemTime must move with the virtual clock.
    let mono_elapsed = start.elapsed();
    let wall_elapsed = SystemTime::now().duration_since(wall).unwrap_or_default();
    check("SystemTime elapsed", wall_elapsed, mono_elapsed, &mut failures);

    // Spin on Instant::now() must still terminate (read quantum).
    let t = Instant::now();
    let mut reads = 0_u64;
    while t.elapsed() < Duration::from_millis(1) {
        reads += 1;
    }
    println!("spin on Instant::now(): {reads} reads to pass 1ms");

    println!(
        "total virtual {:.6}s failures {failures}",
        start.elapsed().as_secs_f64()
    );
    std::process::exit(if failures == 0 { 0 } else { 1 });
}
