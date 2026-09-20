//! Where and when to take a snapshot.
//!
//! The runner evaluates `SnapshotPolicy::decide` at every span boundary the base
//! crate reports (start of a `range` item, start of a `variant` draw, or an
//! explicit `checkpoint_hint`). The supervisor owns the budget side (how many
//! holders may exist) and the reuse estimate (how many continuations a holder is
//! expected to serve).

use crate::proto::Kind;
use std::time::Duration;

/// What to do when the runner holds file descriptors whose state would be shared
/// between the holder and its continuations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdPolicy {
    /// Do not snapshot; report the reason to the supervisor.
    Refuse,
    /// Snapshot anyway, but report the shared fds to the supervisor.
    Warn,
    /// Snapshot silently.
    Allow,
}

#[derive(Debug, Clone)]
pub struct SnapshotPolicy {
    /// Span boundary kinds that may host a snapshot.
    pub kinds: Vec<Kind>,
    /// Do not snapshot before this much wall time has elapsed in the runner
    /// since it started (or since its own snapshot origin). This is the "cost
    /// cliff": microsecond executions like `buggy_stack` never cross it.
    pub min_prefix_cost: Duration,
    /// Do not take two snapshots in one runner closer together than this.
    pub min_gap: Duration,
    /// Do not snapshot before this many stream bytes were consumed.
    pub min_cursor: usize,
    /// Maximum holders one runner may create.
    pub max_holders_per_run: usize,
    /// Maximum live holders overall.
    pub max_holders: usize,
    /// Keep at least this fraction of `MemAvailable` untouched by holder RSS.
    pub mem_available_floor: f64,
    /// Prior for how many continuations a holder will serve before the supervisor
    /// has observed anything.
    pub expected_reuse_prior: f64,
    /// Per-fork constant cost (ms) in the cost model.
    pub fork_base_ms: f64,
    /// Per-MB fork cost (ms) in the cost model.
    pub fork_per_mb_ms: f64,
    pub fds: FdPolicy,
    /// Only take snapshots when the supervisor can actually serve them: with
    /// `false` the runner still reports where it *would* have snapshotted.
    pub enabled: bool,
}

impl Default for SnapshotPolicy {
    fn default() -> Self {
        Self {
            kinds: vec![Kind::Item, Kind::Variant, Kind::Hint],
            min_prefix_cost: Duration::from_millis(1),
            min_gap: Duration::from_millis(1),
            min_cursor: 0,
            max_holders_per_run: 4,
            max_holders: 32,
            mem_available_floor: 0.25,
            expected_reuse_prior: 4.0,
            // Measured on the 6.8 box: ~0.17 ms at 10 MB, 1.1 ms at 100 MB, 4.2 ms at 1 GB.
            fork_base_ms: 0.13,
            fork_per_mb_ms: 0.0041,
            fds: FdPolicy::Refuse,
            enabled: true,
        }
    }
}

impl SnapshotPolicy {
    /// Snapshot only at explicit `checkpoint_hint` calls.
    pub fn hints_only() -> Self {
        Self {
            kinds: vec![Kind::Hint],
            ..Self::default()
        }
    }

    /// Never snapshot, but keep the forkserver-shaped runner (overhead measurement).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    pub fn fork_cost_ms(&self, rss_kb: u64) -> f64 {
        self.fork_base_ms + self.fork_per_mb_ms * (rss_kb as f64 / 1024.0)
    }

    /// Should the runner snapshot at this boundary?
    pub fn decide(&self, input: &DecisionInput) -> Decision {
        if !self.kinds.contains(&input.kind) {
            return Decision::Skip(SkipReason::Kind);
        }
        if input.cursor < self.min_cursor {
            return Decision::Skip(SkipReason::Cursor);
        }
        if input.holders_this_run >= self.max_holders_per_run || input.free_slots == 0 {
            return Decision::Skip(SkipReason::Budget);
        }
        if input.since_origin < self.min_prefix_cost {
            return Decision::Skip(SkipReason::Cliff);
        }
        if input.since_last_snapshot < self.min_gap {
            return Decision::Skip(SkipReason::Gap);
        }
        // expected_reuse × prefix_cost > snapshot_cost + expected_reuse × continuation_overhead
        let fork_ms = self.fork_cost_ms(input.rss_kb);
        let prefix_ms = input.since_last_snapshot.as_secs_f64() * 1e3;
        let reuse = input.expected_reuse.max(0.0);
        let benefit = reuse * prefix_ms;
        let cost = fork_ms + reuse * fork_ms;
        if benefit <= cost {
            return Decision::Skip(SkipReason::CostModel { benefit, cost });
        }
        if !self.enabled {
            return Decision::Skip(SkipReason::Disabled);
        }
        Decision::Snapshot
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DecisionInput {
    pub kind: Kind,
    pub cursor: usize,
    /// Wall time since this process started executing (runner start or continuation resume).
    pub since_origin: Duration,
    /// Wall time since the last snapshot in this process (== `since_origin` if none).
    pub since_last_snapshot: Duration,
    pub holders_this_run: usize,
    pub free_slots: u32,
    pub expected_reuse: f64,
    pub rss_kb: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Decision {
    Snapshot,
    Skip(SkipReason),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SkipReason {
    Kind,
    Cursor,
    Budget,
    Cliff,
    Gap,
    CostModel { benefit: f64, cost: f64 },
    Disabled,
}
