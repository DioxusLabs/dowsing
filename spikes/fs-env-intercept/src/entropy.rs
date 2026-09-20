//! `getrandom` and reads from injected `/dev/urandom` fds.
//!
//! Outcome per call: `variant(3)` = full / short / error (0 = full), then the bytes via
//! `fill_bytes`, which are zero under `zero_tail` so minimized entropy is all zeros. Requests longer
//! than `MAX_DRAWN` bytes draw only `MAX_DRAWN` bytes and expand them deterministically so a large
//! read cannot blow the 4096-byte trace budget.

use rand::{RngCore, SeedableRng};

use crate::bpf::{URANDOM_FD_BASE, URANDOM_FD_SLOTS};
use crate::notif::Notification;
use crate::supervisor::{Answer, Ctx, Session};

pub const MAX_DRAWN: usize = 64;

#[derive(Default)]
pub struct EntropyState {
    next_slot: u32,
    pub non_default: usize,
}

impl EntropyState {
    /// Next fd number for an injected urandom fd.
    pub fn allocate_slot(&mut self) -> u32 {
        let slot = URANDOM_FD_BASE + (self.next_slot % URANDOM_FD_SLOTS);
        self.next_slot += 1;
        slot
    }
}

enum Outcome {
    Full,
    Short(usize),
    Error(i32),
}

fn outcome(session: &mut Session, len: usize) -> Outcome {
    if !session.spec.entropy.faults || len <= 1 {
        return Outcome::Full;
    }
    match session.draw.variant(3) {
        0 => Outcome::Full,
        1 => {
            session.entropy.non_default += 1;
            Outcome::Short(1 + session.draw.variant(len - 1))
        }
        _ => {
            session.entropy.non_default += 1;
            let errno = if session.draw.variant(2) == 0 {
                libc::EINTR
            } else {
                libc::EAGAIN
            };
            Outcome::Error(errno)
        }
    }
}

pub fn generate(session: &mut Session, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let drawn = len.min(MAX_DRAWN);
    session.draw.fill(&mut out[..drawn]);
    if len > drawn {
        let mut seed = [0u8; 32];
        seed[..drawn.min(32)].copy_from_slice(&out[..drawn.min(32)]);
        let mut expand = rand::rngs::SmallRng::from_seed(seed);
        expand.fill_bytes(&mut out[drawn..]);
    }
    session.report.entropy_bytes += len as u64;
    session.report.entropy.extend_from_slice(&out[..drawn]);
    out
}

pub fn getrandom(session: &mut Session, ctx: &Ctx, n: &Notification) -> Answer {
    if !session.spec.entropy.getrandom {
        return Answer::Continue;
    }
    let (buf, len) = (n.args[0], n.args[1] as usize);
    if len == 0 {
        return Answer::Ret(0);
    }
    fill_single(session, ctx, buf, len)
}

fn fill_single(session: &mut Session, ctx: &Ctx, buf: u64, len: usize) -> Answer {
    let len = match outcome(session, len) {
        Outcome::Full => len,
        Outcome::Short(short) => short,
        Outcome::Error(errno) => return Answer::Errno(errno),
    };
    let bytes = generate(session, len);
    match ctx.write(&session.mem, buf, &bytes) {
        Ok(()) => Answer::Ret(len as i64),
        Err(err) => Answer::Errno(err.raw_os_error().unwrap_or(libc::EFAULT)),
    }
}

/// `read`/`pread64`/`readv`/`preadv`/`preadv2` on an fd in the urandom window.
pub fn read(session: &mut Session, ctx: &Ctx, n: &Notification) -> Answer {
    let fd = n.args[0] as u32;
    if !(URANDOM_FD_BASE..URANDOM_FD_BASE + URANDOM_FD_SLOTS).contains(&fd)
        || !session.spec.entropy.urandom
    {
        return Answer::Continue;
    }
    match n.nr {
        libc::SYS_read | libc::SYS_pread64 => {
            let len = n.args[2] as usize;
            if len == 0 {
                return Answer::Ret(0);
            }
            fill_single(session, ctx, n.args[1], len)
        }
        _ => {
            let iovcnt = (n.args[2] as usize).min(1024);
            let mut raw = vec![0u8; iovcnt * std::mem::size_of::<libc::iovec>()];
            if let Err(err) = session.mem.read_exact(n.args[1], &mut raw) {
                return Answer::Errno(err.raw_os_error().unwrap_or(libc::EFAULT));
            }
            let iovs: Vec<(u64, usize)> = raw
                .chunks_exact(16)
                .map(|c| {
                    (
                        u64::from_ne_bytes(c[..8].try_into().unwrap()),
                        u64::from_ne_bytes(c[8..].try_into().unwrap()) as usize,
                    )
                })
                .collect();
            let total: usize = iovs.iter().map(|(_, len)| *len).sum();
            if total == 0 {
                return Answer::Ret(0);
            }
            let len = match outcome(session, total) {
                Outcome::Full => total,
                Outcome::Short(short) => short,
                Outcome::Error(errno) => return Answer::Errno(errno),
            };
            let bytes = generate(session, len);
            let mut offset = 0;
            for (base, iov_len) in iovs {
                if offset >= len {
                    break;
                }
                let chunk = iov_len.min(len - offset);
                if let Err(err) = ctx.write(&session.mem, base, &bytes[offset..offset + chunk]) {
                    return Answer::Errno(err.raw_os_error().unwrap_or(libc::EFAULT));
                }
                offset += chunk;
            }
            Answer::Ret(len as i64)
        }
    }
}
