//! Blocking `std::net` demo: the client connects to 10.66.66.1:7000 (nothing listens there; with
//! the sandbox the SYN never leaves the process), sends a hello, and parses frames until EOF.
//! The fuzzer plays the server. `compressed` frames with n > 64 crash the parser.
//!
//! Plain build (NoCoverage / ChildCoverage without instrumentation):
//!   cargo run --release --example std_client
//! Sancov build (coverage-guided):
//!   cargo rustc --release --example std_client -- -Cpasses=sancov-module \
//!     -Cllvm-args=-sanitizer-coverage-level=3 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
//!     -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares
//!   ./target/release/examples/std_client
//!
//! Flags: `--no-coverage`, `--raw` (byte payloads instead of frame payloads), `--kind-byte`
//! (frame kind drawn as a raw byte: needs trace-compares to find quickly), `--cases N`,
//! `--seed S`, `--verbose`, `--once` (run the target once, print the transcript).

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    time::Duration,
};

use net_intercept::{
    FuzzOptions, Sandbox, SandboxConfig,
    demo::{self, Stats, frame_payload, frame_payload_kind_byte, raw_payload},
    fuzz,
};

const SERVER: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 66, 66, 1)), 7000);

/// The target. Everything here is ordinary std networking.
fn client() {
    let mut stream = match TcpStream::connect_timeout(&SERVER, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("connect failed: {e}");
            return;
        }
    };
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    if let Err(e) = stream.write_all(b"HELLO frames/1\n") {
        eprintln!("hello failed: {e}");
        return;
    }
    let mut stats = Stats::default();
    loop {
        let mut header = [0u8; 3];
        match stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                eprintln!("read failed: {e}");
                return;
            }
        }
        let len = u16::from_be_bytes([header[0], header[1]]) as usize;
        if len == 0 {
            eprintln!("bad frame length");
            return;
        }
        let mut body = vec![0u8; len - 1];
        if stream.read_exact(&mut body).is_err() {
            break;
        }
        if let Err(e) = demo::handle_frame(header[2], &body, &mut stats) {
            eprintln!("protocol error: {e}");
            let _ = stream.write_all(b"ERR\n");
            return;
        }
        let _ = stream.write_all(b"ACK\n");
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
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

    let features = net_intercept::probe_features();
    println!("kernel features: {features:?}");

    let mut config = SandboxConfig {
        verbose: flag("--verbose") || flag("--once"),
        quiet_child: !flag("--once"),
        ..SandboxConfig::default()
    };
    if flag("--no-sync") {
        config.sync_wake_up = false;
    }
    let mut sandbox = Sandbox::new(config).expect("sandbox");
    sandbox = if flag("--raw") {
        sandbox.with_payload(raw_payload)
    } else if flag("--kind-byte") {
        sandbox.with_payload(frame_payload_kind_byte)
    } else {
        sandbox.with_payload(frame_payload)
    };

    if flag("--once") {
        let mut rng_iter = iterator_fuzz::curious().with_coverage(iterator_fuzz::NoCoverage).take(1);
        let mut rng = rng_iter.next().unwrap();
        let v = sandbox.run(&mut rng, client);
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
    let report = fuzz(&mut sandbox, client, &opts);
    report.print();
    if let Some((_, v)) = &report.best {
        println!("\nshrunk exchange as frames:");
        for line in &v.transcript {
            println!("    {line}");
        }
        for (fd, sent) in &v.sent {
            println!("    target sent on fd {fd}: {:?}", String::from_utf8_lossy(sent));
        }
    }
    if report.found.is_none() {
        std::process::exit(1);
    }
}
