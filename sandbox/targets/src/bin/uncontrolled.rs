//! Uses a syscall the supervisor traces but does not model (`poll`), so the run is reported
//! as uncontrolled rather than silently treated as deterministic.

use std::os::fd::AsRawFd;

fn main() {
    dowsing_target_rt::init();
    let file = std::fs::File::open("/dev/null").unwrap();
    let mut fds = [libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }];
    let n = unsafe { libc::poll(fds.as_mut_ptr(), 1, 10) };
    assert!(n >= 0);
    println!("polled {n}");
}
