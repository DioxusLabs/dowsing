//! Verdicts: turning what the supervisor observed into an [`Outcome`].
//!
//! The core produces the process-level outcomes itself (`Exited`, `Signaled`, `Timeout`,
//! `Deadlock`) because they fall out of the ptrace event stream. Everything that needs
//! interpretation lives here or behind a model:
//!
//! - [`Oracle::observe_stderr`]: the default panic hook's message ("panicked at"). A runtime
//!   that catches task panics never exits 101, so this is remembered and reported once the
//!   run goes idle.
//! - [`Oracle::idle`]: the verdict when nothing is runnable and no timer is left: panic seen,
//!   a model's own failure (a peer whose complete request went unanswered: `Hang`), or the
//!   normal end states `Quiescent` (threads wait on the world) and `Deadlock` (threads wait
//!   only on each other).
//! - A protocol's [`crate::models::net::Protocol::verdict`] on a response (a 5xx status).

use crate::{sched::Sched, world::Outcome};
use std::{
    io::Read,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

/// Evidence gathered over a path; cloned into snapshots with the rest of the world.
#[derive(Debug, Clone, Default)]
pub struct Oracle {
    /// A panic message has appeared on the target's stderr.
    pub panicked: bool,
}

impl Oracle {
    /// `tail` is the stderr just read (with up to 16 bytes of what preceded it).
    pub fn observe_stderr(&mut self, tail: &[u8]) {
        if !self.panicked && tail.windows(11).any(|w| w == b"panicked at") {
            self.panicked = true;
        }
    }

    /// Nothing runnable, no timer to fire. `model_failure` is the first failure any model
    /// reports for this state.
    pub fn idle(&self, sched: &Sched, model_failure: Option<Outcome>) -> Outcome {
        let waiting = sched.waiters();
        if self.panicked {
            Outcome::Panic
        } else if let Some(failure) = model_failure {
            failure
        } else if waiting
            .iter()
            .any(|i| sched.threads[*i].state.waits_on_world())
        {
            Outcome::Quiescent
        } else {
            Outcome::Deadlock { waiting }
        }
    }
}

/// The target's stderr pipe (non-blocking) and what was read from it but not yet handed out.
pub struct Stderr {
    fd: Option<OwnedFd>,
    buf: Vec<u8>,
}

impl Stderr {
    pub fn new(fd: Option<OwnedFd>) -> Self {
        Self {
            fd,
            buf: Vec::new(),
        }
    }

    /// Drain the pipe and let the oracle see what arrived.
    pub fn poll(&mut self, oracle: &mut Oracle) {
        let Some(fd) = &self.fd else {
            return;
        };
        let mut file = unsafe { std::fs::File::from_raw_fd(fd.as_raw_fd()) };
        let before = self.buf.len();
        let _ = file.read_to_end(&mut self.buf);
        std::mem::forget(file);
        if self.buf.len() != before {
            oracle.observe_stderr(&self.buf[before.saturating_sub(16)..]);
        }
    }

    /// Everything read since the last call.
    pub fn take(&mut self, oracle: &mut Oracle) -> String {
        self.poll(oracle);
        String::from_utf8_lossy(&std::mem::take(&mut self.buf)).into_owned()
    }
}
