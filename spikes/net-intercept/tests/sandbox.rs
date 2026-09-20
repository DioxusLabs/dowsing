//! End-to-end checks of the sandbox: the target is real `std::net` code, the peer is the
//! supervisor. Each test forks the target under seccomp user notification.

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    time::Duration,
};

use iterator_fuzz::{NoCoverage, curious};
use net_intercept::{Outcome, Sandbox, SandboxConfig, demo};

const SERVER: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 66, 66, 1)), 7000);

fn sandbox() -> Sandbox {
    Sandbox::new(SandboxConfig {
        quiet_child: true,
        timeout: Duration::from_secs(5),
        ..SandboxConfig::default()
    })
    .expect("sandbox")
    .with_payload(demo::frame_payload)
}

/// A target that echoes exactly one frame header back and exits; never panics.
fn benign_client() {
    let Ok(mut s) = TcpStream::connect_timeout(&SERVER, Duration::from_secs(1)) else {
        return;
    };
    let _ = s.write_all(b"HELLO frames/1\n");
    let mut buf = [0u8; 3];
    let _ = s.read(&mut buf);
}

/// A target that panics as soon as the peer sends anything at all.
fn touchy_client() {
    let Ok(mut s) = TcpStream::connect_timeout(&SERVER, Duration::from_secs(1)) else {
        return;
    };
    let _ = s.write_all(b"HELLO frames/1\n");
    let mut buf = [0u8; 3];
    if matches!(s.read(&mut buf), Ok(n) if n > 0) {
        panic!("peer spoke");
    }
}

#[test]
fn nonexistent_server_is_answered_by_the_supervisor() {
    let mut sb = sandbox();
    let mut ok = 0;
    for mut rng in curious().with_coverage(NoCoverage).take(20) {
        let v = sb.run(&mut rng, benign_client);
        assert!(v.unhandled.is_empty(), "unhandled: {:?}", v.unhandled);
        assert!(v.syscalls > 0);
        assert!(
            v.transcript.iter().any(|l| l.starts_with("socket(AF_INET")),
            "transcript: {:?}",
            v.transcript
        );
        if v.outcome == Outcome::Ok {
            ok += 1;
        }
        assert!(
            matches!(v.outcome, Outcome::Ok | Outcome::Exited(_)),
            "unexpected {:?} for {:?}",
            v.outcome,
            v.transcript
        );
    }
    assert!(ok > 0);
}

#[test]
fn panic_in_target_is_reported_with_the_exchange() {
    let mut sb = sandbox();
    let mut found = false;
    for mut rng in curious().with_coverage(NoCoverage).take(200) {
        let v = sb.run(&mut rng, touchy_client);
        if let Outcome::Panicked(msg) = &v.outcome {
            assert_eq!(msg.as_deref(), Some("peer spoke"));
            assert!(v.transcript.iter().any(|l| l.contains("<- Data")), "{:?}", v.transcript);
            found = true;
            break;
        }
    }
    assert!(found, "no case made the peer send data");
}
