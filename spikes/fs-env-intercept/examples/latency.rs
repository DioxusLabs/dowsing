//! Latency and throughput measurements for the sandbox. Run with
//! `cargo run --release --example latency [-- --no-pin]` (no sancov instrumentation needed).
//! `--no-pin` leaves the fuzz thread and supervisor free to run on different CPUs.
//!
//! Every native number is taken on the same thread *before* the seccomp filter is installed
//! (the filter is permanent for the thread), then the same operation is repeated inside cases.

#[path = "demo_target/mod.rs"]
mod demo_target;

use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fs_env_intercept::{Content, Options, Sandbox, Spec};
use iterator_fuzz::{NoCoverage, curious};

const ROUNDS: usize = 20_000;

fn time(label: &str, n: usize, mut f: impl FnMut()) -> Duration {
    // Warm up.
    for _ in 0..n / 10 {
        f();
    }
    let start = Instant::now();
    for _ in 0..n {
        f();
    }
    let per = start.elapsed() / n as u32;
    println!("{label:<52} {:>8.2} us", per.as_secs_f64() * 1e6);
    per
}

fn getpid() {
    // SAFETY: no arguments.
    let _ = unsafe { libc::getpid() };
}

fn open_real() {
    let _ = File::open("/etc/hostname").expect("real file");
}

fn getrandom16() {
    let mut buf = [0u8; 16];
    // SAFETY: valid buffer.
    let n = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
    assert_eq!(n, 16);
}

fn urandom8() {
    let mut buf = [0u8; 8];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("urandom");
}

fn open_read_conf() -> usize {
    std::fs::read("/etc/app/app.conf").expect("virtual conf").len()
}

fn main() {
    let pin = !std::env::args().any(|a| a == "--no-pin");
    println!("--- native (same thread, before the filter is installed) ---");
    let native_getpid = time("getpid", ROUNDS, getpid);
    let native_open = time("open+close /etc/hostname (real file)", ROUNDS, open_real);
    let native_getrandom = time("getrandom(16)", ROUNDS, getrandom16);
    let native_urandom = time("open+read(8)+close /dev/urandom", ROUNDS, urandom8);
    let native_100_opens = time("100 x open+close real file", ROUNDS / 50, || {
        for _ in 0..100 {
            open_real();
        }
    });

    let mut sandbox = Sandbox::install_with(Options { pin, cpu: None }).expect("install sandbox");
    println!(
        "--- sandbox installed: fuzz thread + supervisor {} ---",
        match sandbox.pinned_cpu() {
            Some(cpu) => format!("pinned to CPU {cpu}"),
            None => "unpinned (--no-pin)".to_string(),
        }
    );
    // Entropy faults (short reads / EINTR) are variants the fuzzer explores; the latency bench
    // wants every read to succeed.
    let no_faults = |mut spec: Spec| {
        spec.entropy.faults = false;
        Arc::new(spec)
    };
    let empty = no_faults(Spec::new());
    let conf = no_faults(
        Spec::new().file("/etc/app/app.conf", Content::Fixed(b"mode=strict\nretries=3\n".to_vec())),
    );

    println!("--- sandboxed (inside a case; per-operation cost) ---");
    let mut rngs = curious().with_coverage(NoCoverage);
    let mut inside = |label: &str, spec: &Arc<Spec>, n: usize, f: &mut dyn FnMut()| -> Duration {
        let rng = rngs.next().expect("rng");
        let (rng, _report, per) = sandbox.run_case(rng, spec, || time(label, n, f));
        rng.discard();
        per
    };
    let sb_getpid = inside("getpid (trapped, answered by supervisor)", &empty, ROUNDS, &mut getpid);
    let sb_open = inside("open+close real file (CONTINUE passthrough)", &empty, ROUNDS, &mut open_real);
    let sb_getrandom = inside("getrandom(16) (trapped, drawn from CaseRng)", &empty, ROUNDS, &mut getrandom16);
    let sb_urandom = inside(
        "open+read(8)+close /dev/urandom (2 traps)",
        &empty,
        ROUNDS,
        &mut urandom8,
    );
    let sb_vopen = inside(
        "read virtual /etc/app/app.conf (trap+ADDFD, native read)",
        &conf,
        ROUNDS,
        &mut || {
            open_read_conf();
        },
    );
    let sb_100_opens = inside("100 x open+close real file", &empty, ROUNDS / 50, &mut || {
        for _ in 0..100 {
            open_real();
        }
    });

    println!("--- per-case throughput (NoCoverage, no instrumentation) ---");
    let mut cases = |label: &str, spec: &Arc<Spec>, target: fn()| -> f64 {
        let n = 5_000;
        let mut rngs = curious().with_coverage(NoCoverage);
        for _ in 0..n / 10 {
            let (rng, _, ()) = sandbox.run_case(rngs.next().unwrap(), spec, target);
            rng.discard();
        }
        let start = Instant::now();
        for _ in 0..n {
            let (rng, _, ()) = sandbox.run_case(rngs.next().unwrap(), spec, target);
            rng.discard();
        }
        let per_s = n as f64 / start.elapsed().as_secs_f64();
        println!("{label:<52} {per_s:>8.0} cases/s");
        per_s
    };
    let empty_cases = cases("empty target (start_case + finish_case only)", &empty, || {});
    let conf_cases = cases("target: read one virtual file (materialize + open)", &conf, || {
        open_read_conf();
    });
    let demo_spec = Arc::new(
        Spec::new()
            .file("/etc/app/app.conf", Content::Fixed(b"mode=strict\nretries=3\n".to_vec()))
            .file("/var/lib/app/state.db", Content::Random { max_len: 16 })
            .dir("/var/lib/app", 2),
    ); // faults on: this is what the real harness runs
    let demo_cases = cases("demo target (conf, urandom, getrandom, dir, pid, uname)", &demo_spec, || {
        let _ = demo_target::run();
    });
    let tax_cases = cases("target: 100 real opens (passthrough tax)", &empty, || {
        for _ in 0..100 {
            open_real();
        }
    });

    println!("--- summary ---");
    let us = |d: Duration| d.as_secs_f64() * 1e6;
    println!(
        "trap overhead (getpid):        {:.2} us -> {:.2} us",
        us(native_getpid),
        us(sb_getpid)
    );
    println!(
        "passthrough open tax:          {:.2} us -> {:.2} us ({:+.2} us/open)",
        us(native_open),
        us(sb_open),
        us(sb_open) - us(native_open)
    );
    println!(
        "getrandom(16):                 {:.2} us -> {:.2} us",
        us(native_getrandom),
        us(sb_getrandom)
    );
    println!(
        "urandom open+read+close:       {:.2} us -> {:.2} us",
        us(native_urandom),
        us(sb_urandom)
    );
    println!("virtual file open+read+close:  {:.2} us", us(sb_vopen));
    println!(
        "100 real opens per case:       {:.0} us native -> {:.0} us sandboxed; {:.0} cases/s",
        us(native_100_opens),
        us(sb_100_opens),
        tax_cases
    );
    println!(
        "cases/s: empty {empty_cases:.0}, one virtual file {conf_cases:.0}, demo target {demo_cases:.0}"
    );
}
