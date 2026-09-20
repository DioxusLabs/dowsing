//! Timing-dependent bug: a worker publishes a result after a sleep; the main thread waits with
//! a timeout that is "long enough" natively. Under virtual time the timeout may fire first.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

fn main() {
    dowsing_target_rt::init();
    let slot = Arc::new((Mutex::new(None::<u32>), Condvar::new()));
    let worker = {
        let slot = Arc::clone(&slot);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(5));
            let (m, cv) = &*slot;
            *m.lock().unwrap() = Some(42);
            cv.notify_one();
        })
    };
    let (m, cv) = &*slot;
    let guard = m.lock().unwrap();
    let (guard, _) = cv
        .wait_timeout_while(guard, Duration::from_millis(50), |v| v.is_none())
        .unwrap();
    let value = guard.expect("worker result missing");
    drop(guard);
    worker.join().unwrap();
    assert_eq!(value, 42);
}
