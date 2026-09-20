//! Nonblocking demo: the same frame client on a tokio current-thread runtime (mio + epoll).
//! The runtime's eventfd/timerfd and the fake sockets share one epoll; readiness on the fake
//! sockets comes from the AF_UNIX pair the supervisor materialises events into.
//!
//!   cargo run --release --example tokio_client
//!   ./build-sancov.sh tokio_client && ./target/release/examples/tokio_client
//!
//! Flags as in `std_client`: `--no-coverage`, `--kind-byte`, `--raw`, `--cases N`, `--shrink N`,
//! `--seed S`, `--verbose`, `--once`.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use net_intercept::{
    FuzzOptions, Sandbox, SandboxConfig,
    demo::{self, Stats, frame_payload, frame_payload_kind_byte, raw_payload},
    fuzz,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const SERVER: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 66, 66, 1)), 7000);

async fn session() {
    let connect = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(SERVER));
    let mut stream = match connect.await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("connect failed: {e}");
            return;
        }
        Err(_) => {
            eprintln!("connect timed out");
            return;
        }
    };
    stream.set_nodelay(true).ok();
    if let Err(e) = stream.write_all(b"HELLO frames/1\n").await {
        eprintln!("hello failed: {e}");
        return;
    }
    let mut stats = Stats::default();
    loop {
        let mut header = [0u8; 3];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header));
        match read.await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => {
                eprintln!("read failed: {e}");
                return;
            }
            Err(_) => {
                eprintln!("read timed out");
                return;
            }
        }
        let len = u16::from_be_bytes([header[0], header[1]]) as usize;
        if len == 0 {
            eprintln!("bad frame length");
            return;
        }
        let mut body = vec![0u8; len - 1];
        if stream.read_exact(&mut body).await.is_err() {
            break;
        }
        if let Err(e) = demo::handle_frame(header[2], &body, &mut stats) {
            eprintln!("protocol error: {e}");
            let _ = stream.write_all(b"ERR\n").await;
            return;
        }
        let _ = stream.write_all(b"ACK\n").await;
    }
    let _ = stream.shutdown().await;
}

/// The target: builds the runtime inside the sandboxed child.
fn client() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(session());
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

    let config = SandboxConfig {
        verbose: flag("--verbose") || flag("--once"),
        quiet_child: !flag("--once"),
        describe_payload: Some(demo::describe_frames),
        sync_wake_up: !flag("--no-sync"),
        ..SandboxConfig::default()
    };
    let mut sandbox = Sandbox::new(config).expect("sandbox");
    sandbox = if flag("--raw") {
        sandbox.with_payload(raw_payload)
    } else if flag("--kind-byte") {
        sandbox.with_payload(frame_payload_kind_byte)
    } else {
        sandbox.with_payload(frame_payload)
    };

    if flag("--once") {
        let mut rng_iter = iterator_fuzz::curious()
            .with_coverage(iterator_fuzz::NoCoverage)
            .with_seed(value("--seed").unwrap_or(0))
            .take(1);
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
        for (fd, sent) in &v.sent {
            println!("    target sent on fd {fd}: {:?}", String::from_utf8_lossy(sent));
        }
    }
    if report.found.is_none() {
        std::process::exit(1);
    }
}
