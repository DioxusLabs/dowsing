//! What `fork()` does and does not preserve about the file descriptor table.
//!
//! The child gets a copy of the fd *table*, but every entry points at the same
//! open file description as the parent: offsets, `O_APPEND`/`O_NONBLOCK` flags,
//! and locks are shared. Kernel objects behind sockets, pipes, epoll, timerfd,
//! eventfd, signalfd, inotify and friends are shared too, and any bytes they
//! buffer are consumed once, by whichever process reads first.
//!
//! Before forking a holder we classify every open fd. Regular files opened
//! read-only are fine as long as each continuation restores the offset the
//! holder saw (`restore_offsets`). Everything else is reported and, under
//! `FdPolicy::Refuse`, blocks the snapshot.

use std::{fs, io, os::fd::RawFd, path::Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdClass {
    /// Regular file, read-only: offset can be restored.
    RegularReadOnly { pos: u64 },
    /// Regular file, writable: content and offset diverge between branches.
    RegularWritable,
    /// Character device (tty, /dev/null, /dev/urandom): shared but stateless enough.
    CharDevice,
    /// Directory fd.
    Directory,
    Socket,
    Pipe,
    /// eventfd, timerfd, epoll, signalfd, inotify, io_uring, pidfd, userfaultfd, ...
    AnonInode(String),
    Other(String),
}

#[derive(Debug, Clone)]
pub struct FdInfo {
    pub fd: RawFd,
    pub target: String,
    pub class: FdClass,
}

pub fn scan(skip: &[RawFd]) -> io::Result<Vec<FdInfo>> {
    let mut out = Vec::new();
    let dir = fs::read_dir("/proc/self/fd")?;
    for entry in dir {
        let entry = entry?;
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
        else {
            continue;
        };
        if skip.contains(&fd) {
            continue;
        }
        let target = fs::read_link(entry.path())
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let class = classify(fd, &target);
        out.push(FdInfo { fd, target, class });
    }
    Ok(out)
}

fn classify(fd: RawFd, target: &str) -> FdClass {
    if target.starts_with("socket:") {
        return FdClass::Socket;
    }
    if target.starts_with("pipe:") {
        return FdClass::Pipe;
    }
    if let Some(rest) = target.strip_prefix("anon_inode:") {
        return FdClass::AnonInode(rest.to_string());
    }
    if target.starts_with("/proc/") && target.ends_with("/fd") {
        // the ReadDir handle used by `scan` itself
        return FdClass::Directory;
    }
    let (pos, flags) = fdinfo(fd).unwrap_or((0, 0));
    let metadata = fs::metadata(Path::new(&format!("/proc/self/fd/{fd}")));
    match metadata {
        Ok(meta) if meta.file_type().is_dir() => FdClass::Directory,
        Ok(meta) if meta.file_type().is_file() => {
            if flags & (libc::O_ACCMODE as u64) == libc::O_RDONLY as u64 {
                FdClass::RegularReadOnly { pos }
            } else {
                FdClass::RegularWritable
            }
        }
        Ok(meta) => {
            use std::os::unix::fs::FileTypeExt;
            if meta.file_type().is_char_device() {
                FdClass::CharDevice
            } else {
                FdClass::Other(target.to_string())
            }
        }
        Err(_) => FdClass::Other(target.to_string()),
    }
}

/// `(pos, flags)` from `/proc/self/fdinfo/<fd>`.
pub fn fdinfo(fd: RawFd) -> Option<(u64, u64)> {
    let text = fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).ok()?;
    let mut pos = None;
    let mut flags = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("pos:") {
            pos = value.trim().parse().ok();
        } else if let Some(value) = line.strip_prefix("flags:") {
            flags = u64::from_str_radix(value.trim(), 8).ok();
        }
    }
    Some((pos?, flags?))
}

/// Fds whose state a continuation cannot own.
pub fn problems(infos: &[FdInfo]) -> Vec<String> {
    infos
        .iter()
        .filter_map(|info| match &info.class {
            FdClass::RegularReadOnly { .. } | FdClass::CharDevice | FdClass::Directory => None,
            FdClass::RegularWritable => Some(format!(
                "fd {} ({}) is a writable regular file",
                info.fd, info.target
            )),
            FdClass::Socket => Some(format!("fd {} is a socket", info.fd)),
            FdClass::Pipe => Some(format!("fd {} is a pipe", info.fd)),
            FdClass::AnonInode(kind) => Some(format!("fd {} is an anon inode ({kind})", info.fd)),
            FdClass::Other(target) => Some(format!("fd {} is {target}", info.fd)),
        })
        .collect()
}

/// Re-seat read-only regular file offsets to what the holder recorded.
pub fn restore_offsets(infos: &[FdInfo]) -> Vec<String> {
    let mut errors = Vec::new();
    for info in infos {
        if let FdClass::RegularReadOnly { pos } = info.class {
            let rc = unsafe { libc::lseek(info.fd, pos as libc::off_t, libc::SEEK_SET) };
            if rc < 0 {
                errors.push(format!(
                    "lseek fd {} to {pos}: {}",
                    info.fd,
                    io::Error::last_os_error()
                ));
            }
        }
    }
    errors
}

/// Number of threads in this process (`fork` only carries the caller).
pub fn thread_count() -> usize {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("Threads:"))
                .and_then(|value| value.trim().parse().ok())
        })
        .unwrap_or(1)
}

/// Resident set size in kB, from `/proc/self/statm`.
pub fn rss_kb() -> u64 {
    fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|text| {
            let mut fields = text.split_whitespace();
            fields.next();
            fields.next()?.parse::<u64>().ok()
        })
        .map(|pages| pages * 4)
        .unwrap_or(0)
}

/// `MemAvailable` in kB.
pub fn mem_available_kb() -> u64 {
    fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("MemAvailable:"))
                .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
        })
        .unwrap_or(0)
}

/// Proportional set size of another process in kB (`/proc/<pid>/smaps_rollup`).
pub fn pss_kb(pid: i32) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("Pss:"))
        .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
}
