//! Baselines for the `slow_setup` snapshot/restore measurement.
//!
//! `fork`: after the 64 MB setup, run the two-thread race in a forked child N times and time
//! fork → child exit (copy-on-write "snapshot" of a single-threaded state).
//! `fresh`: exec this binary with `setup-only` N times (what re-executing from scratch costs).
//! `pause`: do the setup, print the pid, block forever — target for `criu dump`/`restore`.

use std::hint::black_box;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Instant;

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

fn race(table: &Arc<Vec<u64>>) -> u64 {
    let counter = Arc::new(Mutex::new(0u64));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let counter = Arc::clone(&counter);
            let table = Arc::clone(table);
            std::thread::spawn(move || {
                for i in 0..ITERS {
                    let v = *counter.lock().unwrap();
                    black_box(table[i as usize]);
                    *counter.lock().unwrap() = v + 1;
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let total = *counter.lock().unwrap();
    total
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let n: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(20);
    let t0 = Instant::now();
    let table = Arc::new(build_table());
    black_box(table.iter().fold(0u64, |a, b| a.wrapping_add(*b)));
    let setup_ms = t0.elapsed().as_secs_f64() * 1e3;
    match mode.as_str() {
        "setup-only" => {
            std::process::exit(if race(&table) == 2 * ITERS { 0 } else { 101 });
        }
        "fresh" => {
            let exe = std::env::current_exe().unwrap();
            let t = Instant::now();
            let mut fails = 0;
            for _ in 0..n {
                let st = Command::new(&exe).arg("setup-only").status().unwrap();
                fails += (!st.success()) as usize;
            }
            let ms = t.elapsed().as_secs_f64() * 1e3 / n as f64;
            println!("tool=fresh-exec runs={n} per_run_ms={ms:.1} failures={fails}");
        }
        "fork" => {
            let t = Instant::now();
            let mut fails = 0;
            for _ in 0..n {
                let pid = unsafe { libc::fork() };
                assert!(pid >= 0);
                if pid == 0 {
                    let total = race(&table);
                    unsafe { libc::_exit(if total == 2 * ITERS { 0 } else { 101 }) };
                }
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                fails += (libc::WEXITSTATUS(status) != 0) as usize;
            }
            let ms = t.elapsed().as_secs_f64() * 1e3 / n as f64;
            println!(
                "tool=fork-cow setup_ms={setup_ms:.1} runs={n} per_run_ms={ms:.2} failures={fails}"
            );
        }
        "pause" => {
            println!("pid={} setup_ms={setup_ms:.1}", std::process::id());
            loop {
                unsafe { libc::pause() };
            }
        }
        _ => eprintln!("usage: snapshot_baselines fresh|fork|pause|setup-only [n]"),
    }
}
