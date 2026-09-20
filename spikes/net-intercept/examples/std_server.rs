//! Blocking `std::net` server demo (stretch goal): binds 0.0.0.0:7000, accepts up to three
//! connections and parses frames from each. No client exists; the fuzzer plays every client
//! (accept outcomes, payloads, EOF/reset) through `bind`/`listen`/`accept4`/`recv`.
//!
//!   cargo run --release --example std_server -- --no-coverage
//!
//! Flags as in `std_client`: `--no-coverage`, `--cases N`, `--shrink N`, `--seed S`,
//! `--verbose`, `--once`.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

use net_intercept::{
    FuzzOptions, Sandbox, SandboxConfig,
    demo::{self, Stats, frame_payload},
    fuzz,
};

const MAX_CONNECTIONS: usize = 3;

fn serve(mut stream: TcpStream, stats: &mut Stats) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let _ = stream.write_all(b"HELLO frames/1\n");
    loop {
        let mut header = [0u8; 3];
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        let len = u16::from_be_bytes([header[0], header[1]]) as usize;
        if len == 0 {
            let _ = stream.write_all(b"ERR\n");
            return;
        }
        let mut body = vec![0u8; len - 1];
        if stream.read_exact(&mut body).is_err() {
            return;
        }
        if demo::handle_frame(header[2], &body, stats).is_err() {
            let _ = stream.write_all(b"ERR\n");
            return;
        }
        let _ = stream.write_all(b"ACK\n");
    }
}

/// The target: ordinary std server code.
fn server() {
    let listener = match TcpListener::bind("0.0.0.0:7000") {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind failed: {e}");
            return;
        }
    };
    let mut stats = Stats::default();
    let mut accepted = 0;
    while accepted < MAX_CONNECTIONS {
        match listener.accept() {
            Ok((stream, peer)) => {
                accepted += 1;
                eprintln!("connection from {peer}");
                serve(stream, &mut stats);
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => continue,
            Err(e) => {
                eprintln!("accept failed: {e}");
                return;
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |f: &str| args.iter().any(|a| a == f);
    let value = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .and_then(|v| v.parse::<u64>().ok())
    };

    let config = SandboxConfig {
        verbose: flag("--verbose") || flag("--once"),
        quiet_child: !flag("--once"),
        describe_payload: Some(demo::describe_frames),
        ..SandboxConfig::default()
    };
    let mut sandbox = Sandbox::new(config).expect("sandbox").with_payload(frame_payload);

    if flag("--once") {
        let mut rng_iter = iterator_fuzz::curious()
            .with_coverage(iterator_fuzz::NoCoverage)
            .with_seed(value("--seed").unwrap_or(0))
            .take(1);
        let mut rng = rng_iter.next().unwrap();
        let v = sandbox.run(&mut rng, server);
        println!("{v:#?}");
        return;
    }

    let opts = FuzzOptions {
        discovery_cases: value("--cases").map(|v| v as usize).unwrap_or(20_000),
        minimization_cases: value("--shrink").map(|v| v as usize).unwrap_or(2_000),
        coverage: !flag("--no-coverage"),
        seed: value("--seed"),
        verbose: flag("--verbose"),
    };
    let report = fuzz(&mut sandbox, server, &opts);
    report.print();
    if report.found.is_none() {
        std::process::exit(1);
    }
}
