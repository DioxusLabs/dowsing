//! Fork-based copy-on-write snapshots for dowsing's search loop.
//!
//! ```text
//! P  (harness process; owns the search State and this Supervisor)
//! └─ R0 (runner for candidate c0: forked by P)
//!    ├─ at span boundary k1: fork → H1 (holder, paused at k1) ; R0 continues
//!    └─ at span boundary k2: fork → H2 ; R0 continues, finishes, _exit
//! later candidate c7 whose first k2 bytes equal c0's:
//!    P → H2: Spawn → C7 (continuation) resumes at k2 with c7's stream
//! ```
//!
//! See `README.md` and `DESIGN.md` next to this crate.

pub mod fds;
pub mod policy;
pub mod proto;
pub mod runner;
pub mod supervisor;
pub mod tree;

pub use policy::{FdPolicy, SnapshotPolicy};
pub use proto::{Kind, Verdict};
pub use supervisor::{Outcome, SnapshotStats, Supervisor, describe_us};

use iterator_fuzz::{CaseRng, coverage::CoverageCapture};
use std::marker::PhantomData;

/// Wraps any `Iterator<Item = CaseRng<C>>` (`curious()`, `cautious()`,
/// `.with_case(..)`, `.take(n)`) and runs each candidate's harness body in a
/// forked runner, resuming from a matching holder when one exists.
pub struct Snapshotted<I, C: CoverageCapture> {
    inner: I,
    supervisor: Supervisor,
    _capture: PhantomData<C>,
}

impl<I, C> Snapshotted<I, C>
where
    I: Iterator<Item = CaseRng<C>>,
    C: CoverageCapture + 'static,
{
    pub fn new(inner: I, policy: SnapshotPolicy) -> Self {
        Self {
            inner,
            supervisor: Supervisor::new(policy),
            _capture: PhantomData,
        }
    }

    /// Run the next candidate. The body executes in a child process: it must not
    /// rely on mutating captured state, and `println!` output is flushed on exit.
    pub fn next_outcome(
        &mut self,
        body: &mut dyn FnMut(&mut CaseRng<C>) -> Verdict,
    ) -> Option<Outcome> {
        let rng = self.inner.next()?;
        Some(self.supervisor.run_candidate(rng, body))
    }

    /// Run every candidate until the inner iterator ends or `on_outcome` returns `false`.
    pub fn run(
        &mut self,
        mut body: impl FnMut(&mut CaseRng<C>) -> Verdict,
        mut on_outcome: impl FnMut(&Outcome) -> bool,
    ) {
        while let Some(outcome) = self.next_outcome(&mut body) {
            if !on_outcome(&outcome) {
                break;
            }
        }
    }

    pub fn stats(&self) -> &SnapshotStats {
        self.supervisor.stats()
    }

    pub fn supervisor(&mut self) -> &mut Supervisor {
        &mut self.supervisor
    }

    pub fn inner(&self) -> &I {
        &self.inner
    }

    /// Tear down holders and hand back the inner iterator.
    pub fn finish(mut self) -> I {
        self.supervisor.shutdown();
        // SAFETY-free: Supervisor's Drop runs shutdown again (idempotent), then
        // we move the iterator out.
        let Self { inner, .. } = self;
        inner
    }
}
