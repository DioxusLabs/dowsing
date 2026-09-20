//! `CoverageCapture` backend fed by sancov 8-bit counters read out of the tracee's memory.
//!
//! The instrumented target announces its `[start, end)` counter range through the reserved
//! [`crate::seccomp::ANNOUNCE_NR`] syscall (see `src/bin/announce.rs`); the supervisor copies the
//! bytes at `PTRACE_EVENT_EXIT` and [`Sandbox::run`](crate::Sandbox::run) stores them in the slot
//! shared with this capture.

use std::sync::{Arc, Mutex};

use iterator_fuzz::coverage::{CoverageCapture, CoverageId, CoverageSet, ExecutionFeedback};

#[derive(Debug, Default)]
pub struct Slot {
    pub counters: Option<Vec<u8>>,
}

pub type SharedSlot = Arc<Mutex<Slot>>;

/// Coverage capture whose data arrives from the sandboxed target.
#[derive(Debug, Clone, Default)]
pub struct SandboxCoverage {
    slot: SharedSlot,
}

impl SandboxCoverage {
    pub fn new() -> Self {
        Self::default()
    }

    /// The slot [`crate::Sandbox`] writes into after each run.
    pub fn slot(&self) -> SharedSlot {
        Arc::clone(&self.slot)
    }
}

pub fn feedback_from_counters(counters: &[u8]) -> ExecutionFeedback {
    let mut ids = Vec::new();
    let mut hit_count_weight = 0_u64;
    for (index, counter) in counters.iter().copied().enumerate() {
        if counter != 0 {
            let bucket = hit_count_bucket(counter);
            ids.push(CoverageId::new(((index as u64) << 8) | u64::from(bucket)));
            hit_count_weight = hit_count_weight.saturating_add(1 + u64::from(bucket));
        }
    }
    ExecutionFeedback::from_features(ids.into_iter().collect::<CoverageSet>())
        .with_hit_count_weight(hit_count_weight)
}

// Same buckets as iterator-fuzz's sancov backend.
fn hit_count_bucket(counter: u8) -> u8 {
    match counter {
        0 | 1 => 0,
        2 => 1,
        3 => 2,
        4..=7 => 3,
        8..=15 => 4,
        16..=31 => 5,
        32..=127 => 6,
        _ => 7,
    }
}

impl CoverageCapture for SandboxCoverage {
    type Token = ();

    fn start_capture(&mut self) -> Result<Self::Token, String> {
        self.slot.lock().map_err(|e| e.to_string())?.counters = None;
        Ok(())
    }

    fn finish_capture(&mut self, _token: Self::Token) -> Result<ExecutionFeedback, String> {
        let counters = self.slot.lock().map_err(|e| e.to_string())?.counters.take();
        Ok(counters
            .as_deref()
            .map(feedback_from_counters)
            .unwrap_or_default())
    }
}
