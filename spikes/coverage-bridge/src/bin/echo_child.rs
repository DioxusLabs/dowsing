//! Uninstrumented test target with scripted behaviour.
//!
//! The first `variant(5)` selects: 0 pass, 1 fail, 2 segfault, 3 spin (timeout),
//! 4 `std::process::exit` (bypasses export). Then a `range(0..16)` of payload bytes is drawn and
//! reported as the cost, so traces have draw, semantic and sequence spans to compare.
//!
//! `--rss <MiB>` allocates and touches that much memory before serving (fork cost vs RSS).
//! `--always-pass` ignores the kind and reports every case as passing (round-trip benchmarks).

use coverage_bridge::{ChildMode, Verdict};
use iterator_fuzz::{CaseRng, NoCoverage, coverage::CoverageCapture};
use rand::Rng;

pub fn harness<Capture: CoverageCapture>(rng: &mut CaseRng<Capture>) -> Verdict {
    let kind = rng.variant(5);
    let payload: Vec<u8> = rng
        .range(0..16)
        .map(|mut item| item.random::<u8>())
        .collect();
    let cost = payload.len() as u64;
    match kind {
        0 => Verdict::ok().with_cost(cost),
        1 => Verdict::failed().with_cost(cost),
        2 => {
            let ptr = std::ptr::null_mut::<u8>();
            unsafe { std::ptr::write_volatile(ptr, payload.first().copied().unwrap_or(1)) };
            Verdict::ok()
        }
        3 => loop {
            std::hint::spin_loop();
        },
        _ => std::process::exit(7),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut ballast: Vec<u8> = Vec::new();
    if let Some(index) = args.iter().position(|arg| arg == "--rss") {
        let mib: usize = args[index + 1].parse().expect("--rss MiB");
        ballast = vec![0u8; mib << 20];
        for (index, page) in ballast.chunks_mut(4096).enumerate() {
            page[0] = index as u8;
        }
    }
    let always_pass = args.iter().any(|arg| arg == "--always-pass");
    let Some(_) = ChildMode::from_env() else {
        eprintln!("echo_child: run through coverage-bridge (see tests/bridge.rs)");
        std::process::exit(2);
    };
    coverage_bridge::child::serve(move |rng: &mut CaseRng<NoCoverage>| {
        std::hint::black_box(&ballast);
        if always_pass {
            let _ = rng.variant(5);
            let payload: Vec<u8> = rng
                .range(0..16)
                .map(|mut item| item.random::<u8>())
                .collect();
            return Verdict::ok().with_cost(payload.len() as u64);
        }
        harness(rng)
    });
}
