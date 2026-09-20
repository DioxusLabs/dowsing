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
    // `probe_target bench N`: cost of N Instant::now() reads (wall time measured by the harness).
    if let Some(n) = std::env::args().nth(2).filter(|_| std::env::args().nth(1).as_deref() == Some("bench")) {
        let n: u64 = n.parse().expect("bench N");
        let t = Instant::now();
        let mut acc = 0_u128;
        for _ in 0..n {
            acc = acc.wrapping_add(t.elapsed().as_nanos());
        }
        println!("bench: {n} reads, virtual elapsed {:.6}s (acc {acc})", t.elapsed().as_secs_f64());
        return;
    }

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

    // timerfd armed for 7 s, waited on with poll(); then read() must return 1 expiration.
    unsafe {
        let tfd = libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC);
        assert!(tfd >= 0);
        let spec = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: 7, tv_nsec: 0 },
        };
        assert_eq!(libc::timerfd_settime(tfd, 0, &spec, std::ptr::null_mut()), 0);
        let mut cur = std::mem::zeroed::<libc::itimerspec>();
        assert_eq!(libc::timerfd_gettime(tfd, &mut cur), 0);
        println!("timerfd_gettime after arming 7s: {}s", cur.it_value.tv_sec);
        let t = Instant::now();
        let mut pfd = libc::pollfd { fd: tfd, events: libc::POLLIN, revents: 0 };
        let n = libc::poll(&mut pfd, 1, 60_000);
        assert_eq!(n, 1, "poll on timerfd");
        let mut expirations = 0_u64;
        let r = libc::read(tfd, (&mut expirations as *mut u64).cast(), 8);
        assert_eq!(r, 8);
        assert_eq!(expirations, 1);
        check("timerfd 7s via poll()", t.elapsed(), Duration::from_secs(7), &mut failures);
        libc::close(tfd);
    }

    // select() with a 500 ms timeout on a pipe nobody writes to.
    unsafe {
        let mut fds = [0_i32; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        let mut set = std::mem::zeroed::<libc::fd_set>();
        libc::FD_SET(fds[0], &mut set);
        let mut tv = libc::timeval { tv_sec: 0, tv_usec: 500_000 };
        let t = Instant::now();
        let n = libc::select(fds[0] + 1, &mut set, std::ptr::null_mut(), std::ptr::null_mut(), &mut tv);
        assert_eq!(n, 0);
        check("select(500ms)", t.elapsed(), Duration::from_millis(500), &mut failures);
        libc::close(fds[0]);
        libc::close(fds[1]);
    }

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
