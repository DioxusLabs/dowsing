//! Turn a dowsing [`CaseRng`] into a [`Scheduler`].
//!
//! Encoding (see DESIGN.md): the case opens one `rng.range(0..MAX_DECISIONS)` (a `Length`
//! span). Every scheduling point with >= 2 runnable threads consumes one child of the range (an
//! `Item` span, deletable by `cautious()`) and draws two variants from it: which candidate runs
//! (`0` = keep the current / lowest-index thread) and which edge budget applies (`0` = run to the
//! next syscall). `getrandom` requests are answered from the same child (`ChildRng: RngCore`).
//! Once the range is exhausted the scheduler answers `0, 0` forever, so a fully zeroed case is a
//! deterministic run-to-completion schedule in creation order.

use crate::supervisor::{BUDGET_TABLE, Decision, Scheduler};
use iterator_fuzz::{CaseRng, ChildRng, RangeIter, coverage::CoverageCapture};
use rand::RngCore;

pub const MAX_DECISIONS: usize = 64;

pub struct CaseScheduler<'a, C: CoverageCapture> {
    decisions: RangeIter<'a, C>,
    /// Child kept alive across the `getrandom` calls that follow a decision.
    current: Option<ChildRng<'a, C>>,
    pub consumed: usize,
}

impl<'a, C: CoverageCapture> CaseScheduler<'a, C> {
    pub fn new(rng: &'a mut CaseRng<C>) -> Self {
        Self {
            decisions: rng.range(0..MAX_DECISIONS),
            current: None,
            consumed: 0,
        }
    }
}

impl<C: CoverageCapture> Scheduler for CaseScheduler<'_, C> {
    fn decide(&mut self, candidates: usize) -> Decision {
        // Drop the previous child first so its Item span closes before the next one opens.
        self.current = None;
        match self.decisions.next() {
            Some(mut child) => {
                let pick = child.variant(candidates);
                let budget = child.variant(BUDGET_TABLE.len());
                self.consumed += 1;
                self.current = Some(child);
                Decision { pick, budget }
            }
            None => Decision { pick: 0, budget: 0 },
        }
    }

    fn random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        match self.current.as_mut() {
            Some(child) => child.fill_bytes(&mut bytes),
            None => {
                // Before the first decision (or after exhaustion) entropy is a constant so the
                // run stays deterministic without spending case bytes.
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = (i as u8).wrapping_mul(0x9d) ^ 0x5a;
                }
            }
        }
        bytes
    }
}
