//! Path-based syscalls: classify the path, `CONTINUE` real ones, serve virtual ones from the
//! materialized tree.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::notif::Notification;
use crate::spec::{Classification, normalize};
use crate::supervisor::{Answer, Ctx, Session};
use crate::vfs::{Node, Resolved};

const URANDOM_PATHS: &[&str] = &["/dev/urandom", "/dev/random"];

/// Where a path argument points after joining with `dirfd`/cwd, before symlink resolution.
enum Located {
    /// Operate natively (real path, or an fd-relative operation on an fd we did not inject).
    Real,
    Virtual(PathBuf),
}

fn locate(session: &mut Session, dirfd: i64, path_addr: u64, allow_empty: bool) -> io::Result<Located> {
    let raw = session.mem.read_cstr(path_addr)?;
    if raw.is_empty() {
        if allow_empty {
            return Ok(Located::Real);
        }
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    let path = Path::new(std::ffi::OsStr::from_bytes(&raw));
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let base = if dirfd == i64::from(libc::AT_FDCWD) {
            std::fs::read_link(format!("/proc/{}/cwd", session.mem.pid()))?
        } else {
            let real = std::fs::read_link(format!("/proc/{}/fd/{dirfd}", session.mem.pid()))?;
            match session.vfs.virtual_path(&real) {
                Some(virtual_dir) => virtual_dir,
                None => real,
            }
        };
        base.join(path)
    };
    let normalized = normalize(&joined);
    if session.vfs.virtual_path(&normalized).is_some() {
        // Absolute path into the materialized tree (e.g. from readlink /proc/self/fd): native.
        return Ok(Located::Real);
    }
    match session.spec.classify(&normalized) {
        Classification::Real => Ok(Located::Real),
        Classification::Virtual => Ok(Located::Virtual(normalized)),
    }
}

fn errno(err: io::Error) -> Answer {
    Answer::Errno(err.raw_os_error().unwrap_or(libc::EIO))
}

pub fn handle(session: &mut Session, ctx: &Ctx, n: &Notification) -> Answer {
    match n.nr {
        libc::SYS_open => open(session, i64::from(libc::AT_FDCWD), n.args[0], n.args[1] as i32),
        libc::SYS_openat => open(session, n.args[0] as i32 as i64, n.args[1], n.args[2] as i32),
        libc::SYS_openat2 => match locate(session, n.args[0] as i32 as i64, n.args[1], false) {
            Ok(Located::Real) => Answer::Continue,
            Ok(Located::Virtual(path)) => {
                session.unsupported(format!("openat2({})", path.display()))
            }
            Err(err) => errno(err),
        },
        libc::SYS_stat => stat(session, ctx, i64::from(libc::AT_FDCWD), n.args[0], n.args[1], 0),
        libc::SYS_lstat => stat(
            session,
            ctx,
            i64::from(libc::AT_FDCWD),
            n.args[0],
            n.args[1],
            libc::AT_SYMLINK_NOFOLLOW,
        ),
        libc::SYS_newfstatat => stat(
            session,
            ctx,
            n.args[0] as i32 as i64,
            n.args[1],
            n.args[2],
            n.args[3] as i32,
        ),
        libc::SYS_statx => statx(session, ctx, n),
        libc::SYS_readlink => readlink(session, ctx, i64::from(libc::AT_FDCWD), n.args[0], n.args[1], n.args[2]),
        libc::SYS_readlinkat => readlink(
            session,
            ctx,
            n.args[0] as i32 as i64,
            n.args[1],
            n.args[2],
            n.args[3],
        ),
        libc::SYS_access => access(session, i64::from(libc::AT_FDCWD), n.args[0], n.args[1] as i32, 0),
        libc::SYS_faccessat => access(
            session,
            n.args[0] as i32 as i64,
            n.args[1],
            n.args[2] as i32,
            0,
        ),
        libc::SYS_faccessat2 => access(
            session,
            n.args[0] as i32 as i64,
            n.args[1],
            n.args[2] as i32,
            n.args[3] as i32,
        ),
        _ => Answer::Continue,
    }
}

fn open(session: &mut Session, dirfd: i64, path_addr: u64, flags: i32) -> Answer {
    if session.spec.entropy.urandom {
        if let Ok(raw) = session.mem.read_cstr(path_addr) {
            if URANDOM_PATHS.iter().any(|p| p.as_bytes() == raw.as_slice()) {
                let source = CString::new("/dev/urandom").unwrap();
                // SAFETY: valid C string.
                let fd = unsafe { libc::open(source.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                if fd < 0 {
                    return errno(io::Error::last_os_error());
                }
                let slot = session.entropy.allocate_slot();
                session.report.virtual_opens += 1;
                return Answer::AddFd {
                    fd,
                    newfd: Some(slot),
                    cloexec: flags & libc::O_CLOEXEC != 0,
                };
            }
        }
    }
    let path = match locate(session, dirfd, path_addr, false) {
        Ok(Located::Real) => return Answer::Continue,
        Ok(Located::Virtual(path)) => path,
        Err(err) => return errno(err),
    };
    let accmode = flags & libc::O_ACCMODE;
    // `O_TMPFILE` includes the `O_DIRECTORY` bit, so compare it as a whole.
    if accmode != libc::O_RDONLY
        || flags & (libc::O_CREAT | libc::O_TRUNC) != 0
        || flags & libc::O_TMPFILE == libc::O_TMPFILE
    {
        // The virtual tree is read-only.
        return Answer::Errno(libc::EROFS);
    }
    let follow = flags & (libc::O_NOFOLLOW | libc::O_PATH) == 0;
    let real = match session.vfs.resolve(&session.spec.clone(), session.draw.as_mut(), &path, follow) {
        Ok(Resolved::Real(real)) => real,
        Ok(Resolved::Virtual(_, Node::Missing { errno })) => return Answer::Errno(errno),
        Ok(Resolved::Virtual(_, Node::Symlink { .. })) if flags & libc::O_PATH == 0 => {
            return Answer::Errno(libc::ELOOP);
        }
        Ok(Resolved::Virtual(virtual_path, _)) => session.vfs.real_path(&virtual_path),
        Err(err) => return errno(err),
    };
    let c_path = match CString::new(real.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return Answer::Errno(libc::EINVAL),
    };
    // Symlinks were resolved virtually above; open the final node itself.
    let open_flags = (flags & !libc::O_CLOEXEC) | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: valid C string.
    let fd = unsafe { libc::open(c_path.as_ptr(), open_flags) };
    if fd < 0 {
        return errno(io::Error::last_os_error());
    }
    session.report.virtual_opens += 1;
    Answer::AddFd {
        fd,
        newfd: None,
        cloexec: flags & libc::O_CLOEXEC != 0,
    }
}

/// Resolve a virtual path to the materialized (or real, via symlink) path to stat.
fn resolve_for_stat(session: &mut Session, path: &Path, follow: bool) -> Result<PathBuf, Answer> {
    let spec = session.spec.clone();
    match session.vfs.resolve(&spec, session.draw.as_mut(), path, follow) {
        Ok(Resolved::Real(real)) => Ok(real),
        Ok(Resolved::Virtual(_, Node::Missing { errno })) => Err(Answer::Errno(errno)),
        Ok(Resolved::Virtual(virtual_path, _)) => Ok(session.vfs.real_path(&virtual_path)),
        Err(err) => Err(errno(err)),
    }
}

fn stat(session: &mut Session, ctx: &Ctx, dirfd: i64, path_addr: u64, buf: u64, flags: i32) -> Answer {
    let path = match locate(session, dirfd, path_addr, flags & libc::AT_EMPTY_PATH != 0) {
        Ok(Located::Real) => return Answer::Continue,
        Ok(Located::Virtual(path)) => path,
        Err(err) => return errno(err),
    };
    let real = match resolve_for_stat(session, &path, flags & libc::AT_SYMLINK_NOFOLLOW == 0) {
        Ok(real) => real,
        Err(answer) => return answer,
    };
    let c_path = CString::new(real.as_os_str().as_bytes()).unwrap();
    // SAFETY: stat is plain old data.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointers.
    let rc = unsafe { libc::fstatat(libc::AT_FDCWD, c_path.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc != 0 {
        return errno(io::Error::last_os_error());
    }
    crate::identity::write_struct(session, ctx, buf, &st)
}

fn statx(session: &mut Session, ctx: &Ctx, n: &Notification) -> Answer {
    let (dirfd, path_addr, flags, mask, buf) = (
        n.args[0] as i32 as i64,
        n.args[1],
        n.args[2] as i32,
        n.args[3] as u32,
        n.args[4],
    );
    let path = match locate(session, dirfd, path_addr, flags & libc::AT_EMPTY_PATH != 0) {
        Ok(Located::Real) => return Answer::Continue,
        Ok(Located::Virtual(path)) => path,
        Err(err) => return errno(err),
    };
    let real = match resolve_for_stat(session, &path, flags & libc::AT_SYMLINK_NOFOLLOW == 0) {
        Ok(real) => real,
        Err(answer) => return answer,
    };
    let c_path = CString::new(real.as_os_str().as_bytes()).unwrap();
    // SAFETY: statx is plain old data.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let sync_flags = flags & libc::AT_STATX_SYNC_TYPE;
    // SAFETY: valid pointers.
    let rc = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            sync_flags | libc::AT_SYMLINK_NOFOLLOW,
            mask,
            &mut stx,
        )
    };
    if rc != 0 {
        return errno(io::Error::last_os_error());
    }
    crate::identity::write_struct(session, ctx, buf, &stx)
}

fn readlink(session: &mut Session, ctx: &Ctx, dirfd: i64, path_addr: u64, buf: u64, bufsiz: u64) -> Answer {
    let path = match locate(session, dirfd, path_addr, false) {
        Ok(Located::Real) => return Answer::Continue,
        Ok(Located::Virtual(path)) => path,
        Err(err) => return errno(err),
    };
    let spec = session.spec.clone();
    match session.vfs.resolve(&spec, session.draw.as_mut(), &path, false) {
        Ok(Resolved::Real(_)) => Answer::Continue,
        Ok(Resolved::Virtual(_, Node::Missing { errno })) => Answer::Errno(errno),
        Ok(Resolved::Virtual(_, Node::Symlink { target })) => {
            let bytes = target.as_os_str().as_bytes();
            let len = bytes.len().min(bufsiz as usize);
            match ctx.write(&session.mem, buf, &bytes[..len]) {
                Ok(()) => Answer::Ret(len as i64),
                Err(err) => errno(err),
            }
        }
        Ok(Resolved::Virtual(_, _)) => Answer::Errno(libc::EINVAL),
        Err(err) => errno(err),
    }
}

fn access(session: &mut Session, dirfd: i64, path_addr: u64, mode: i32, flags: i32) -> Answer {
    let path = match locate(session, dirfd, path_addr, false) {
        Ok(Located::Real) => return Answer::Continue,
        Ok(Located::Virtual(path)) => path,
        Err(err) => return errno(err),
    };
    let real = match resolve_for_stat(session, &path, flags & libc::AT_SYMLINK_NOFOLLOW == 0) {
        Ok(real) => real,
        Err(answer) => return answer,
    };
    if mode & libc::W_OK != 0 {
        return Answer::Errno(libc::EROFS);
    }
    let c_path = CString::new(real.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid C string.
    let rc = unsafe { libc::faccessat(libc::AT_FDCWD, c_path.as_ptr(), mode, libc::AT_SYMLINK_NOFOLLOW) };
    if rc != 0 {
        return errno(io::Error::last_os_error());
    }
    Answer::Ret(0)
}
