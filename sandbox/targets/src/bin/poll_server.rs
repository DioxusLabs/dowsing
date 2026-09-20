//! A hand-rolled blocking server: `poll` on the listener with a timeout, then blocking
//! `accept`/`read`/`write` on plain std sockets. Exercises the supervisor's `poll` model,
//! its timeout path, and blocking (non-epoll) socket calls. A request for `/boom` panics.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::fd::AsRawFd;

fn main() {
    dowsing_target_rt::init();
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    let mut fds = [libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }];
    let mut timeouts = 0;
    loop {
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 1, 50) };
        assert!(n >= 0, "poll failed");
        if n == 0 {
            timeouts += 1;
            eprintln!("poll timeout {timeouts}");
            continue;
        }
        assert_eq!(fds[0].revents & libc::POLLIN, libc::POLLIN);
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).unwrap();
        let line = std::str::from_utf8(&buf[..n])
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("")
            .to_owned();
        assert!(!line.contains("/boom"), "boom requested: {line}");
        let body = format!("{line}\n");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    }
}
