//! Classic lock-order inversion: A→B on one thread, B→A on the other, only when the
//! harness-chosen mode says so. Deadlocks under the wrong interleaving.

use std::sync::{Arc, Mutex};

fn main() {
    dowsing_target_rt::init();
    let a = Arc::new(Mutex::new(0u32));
    let b = Arc::new(Mutex::new(0u32));
    let inverted = dowsing_target_rt::variant(4) == 3;
    let t = {
        let (a, b) = (Arc::clone(&a), Arc::clone(&b));
        std::thread::spawn(move || {
            if inverted {
                let gb = b.lock().unwrap();
                let mut ga = a.lock().unwrap();
                *ga += *gb;
            } else {
                let ga = a.lock().unwrap();
                let mut gb = b.lock().unwrap();
                *gb += *ga;
            }
        })
    };
    {
        let mut ga = a.lock().unwrap();
        let gb = b.lock().unwrap();
        *ga += *gb + 1;
    }
    t.join().unwrap();
    println!("ok");
}
