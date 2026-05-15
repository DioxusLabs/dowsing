use super::{no_coverage::NoCoverage, run::Candidate};
use crate::{
    coverage::{CoverageCapture, CoverageId, CoverageSet},
    sancov::SancovCoverage,
};
use rand::{Rng, rngs::SmallRng};
use std::{
    cmp::Ordering,
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

pub(super) const DEFAULT_MUTATE_DEPTH: usize = 5;
pub(super) const DEFAULT_CAUTIOUS_MUTATE_DEPTH: usize = 1;
pub(super) const DEFAULT_SEED_RATIO: u64 = 8;
pub(super) const CURIOUS_ENERGY_REFRESH_INTERVAL: u64 = 64;
pub(super) const CAUTIOUS_ENERGY_REFRESH_INTERVAL: u64 = 1024;
pub(super) const MAX_PREFIX_LEN: usize = 4096;
pub(super) const MAX_CORPUS_LEN: usize = 4096;
pub(super) const MAX_PENDING_CANDIDATES: usize = 512;
pub(super) const MAX_CAUTIOUS_BEST_NEIGHBORS: usize = 256;
pub(super) const MAX_DICTIONARY_VALUES: usize = 256;
pub(super) const INTERESTING_BYTES: [u8; 10] = [0, 1, 16, 31, 32, 63, 64, 127, 128, 255];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Curious,
    Cautious,
}

/// Replayable RNG path produced by [`crate::CaseRng::fork_case`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    pub(super) seed: u64,
    pub(super) prefix: Vec<u8>,
    pub(super) zero_tail: bool,
}

impl Case {
    /// Replay this case without recording coverage.
    pub fn replay(self) -> crate::CaseRng<NoCoverage> {
        let mut engine = Engine::new(NoCoverage, Mode::Curious).with_case(self);
        engine.next().expect("seeded replay case should yield")
    }

    #[cfg(test)]
    pub(crate) fn from_raw_parts(seed: u64, prefix: Vec<u8>, zero_tail: bool) -> Self {
        Self {
            seed,
            prefix,
            zero_tail,
        }
    }
}

/// Coverage and path-size stats for one completed [`crate::CaseRng`] execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaseCoverage {
    pub(crate) feature_count: usize,
    pub(crate) hit_count_weight: u64,
    pub(crate) bytes_consumed: usize,
}

impl CaseCoverage {
    /// Build coverage stats from all observed parts.
    pub const fn new(feature_count: usize, hit_count_weight: u64, bytes_consumed: usize) -> Self {
        Self {
            feature_count,
            hit_count_weight,
            bytes_consumed,
        }
    }

    /// Number of unique coverage features observed during the execution.
    pub const fn feature_count(self) -> usize {
        self.feature_count
    }

    /// Coarse execution intensity derived from hit-count buckets when available.
    pub const fn hit_count_weight(self) -> u64 {
        self.hit_count_weight
    }

    /// Number of RNG bytes consumed by the execution.
    pub const fn bytes_consumed(self) -> usize {
        self.bytes_consumed
    }
}

impl PartialOrd for CaseCoverage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CaseCoverage {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.feature_count,
            self.hit_count_weight,
            self.bytes_consumed,
        )
            .cmp(&(
                other.feature_count,
                other.hit_count_weight,
                other.bytes_consumed,
            ))
    }
}

/// Coverage-maximizing RNG iterator.
///
/// Each item is an RNG. The RNG owns a coverage guard; when the item is dropped at the end of the
/// caller's loop body, the guard may record coverage and update the next seed choice.
pub fn curious() -> Curious<SancovCoverage> {
    Curious {
        engine: Engine::new(SancovCoverage::new(), Mode::Curious),
    }
}

/// Code-path-minimizing RNG iterator.
///
/// Seed it with [`Cautious::with_case`]. Each yielded variant records coverage unless the caller
/// excludes it with [`crate::CaseRng::discard`].
pub fn cautious() -> Cautious<SancovCoverage> {
    Cautious {
        engine: Engine::new(SancovCoverage::new(), Mode::Cautious),
    }
}

/// Coverage-maximizing search returned by [`curious`].
pub struct Curious<Capture: CoverageCapture = SancovCoverage> {
    pub(super) engine: Engine<Capture>,
}

/// Code-path-minimizing search returned by [`cautious`].
pub struct Cautious<Capture: CoverageCapture = SancovCoverage> {
    pub(super) engine: Engine<Capture>,
}

pub(super) struct Engine<Capture: CoverageCapture = SancovCoverage> {
    pub(super) shared: Arc<Mutex<State<Capture>>>,
}

#[derive(Debug)]
pub(super) struct State<Capture: CoverageCapture> {
    pub(super) capture: Capture,
    pub(super) mode: Mode,
    pub(super) base_seed: u64,
    pub(super) next: u64,
    pub(super) scheduler: SmallRng,
    pub(super) global: CoverageSet,
    pub(super) coverage_frequency: HashMap<CoverageId, u64>,
    pub(super) min_path_removed_frequency: HashMap<CoverageId, u64>,
    pub(super) min_path_target: CoverageSet,
    pub(super) min_path_target_initialized: bool,
    pub(super) min_path_best: Option<MinPathScore>,
    pub(super) min_path_best_index: Option<usize>,
    pub(super) corpus: Vec<CorpusSeed>,
    pub(super) energy_index: EnergyIndex,
    pub(super) pending_cases: VecDeque<Case>,
    pub(super) pending_candidates: VecDeque<Candidate>,
    pub(super) dictionary: Vec<Vec<u8>>,
    pub(super) executions_since_refresh: u64,
    pub(super) mutate_depth: usize,
    pub(super) seed_ratio: u64,
    pub(super) seed_step: u64,
    pub(super) active_cases: u64,
    pub(super) stats: SearchStats,
}

#[derive(Debug)]
pub(super) struct Active {
    pub(super) seed: u64,
    pub(super) trace: Vec<u8>,
    pub(super) bytes_consumed: usize,
}

#[derive(Debug, Clone)]
pub(super) struct CorpusSeed {
    pub(super) seed: u64,
    pub(super) prefix: Vec<u8>,
    pub(super) coverage: Vec<CoverageId>,
    pub(super) removed: Vec<CoverageId>,
    pub(super) score: usize,
    pub(super) hit_count_weight: u64,
    pub(super) path_len: usize,
    pub(super) energy: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct MinPathScore {
    pub(super) features: usize,
    pub(super) hit_count_weight: u64,
    pub(super) bytes: usize,
}

impl MinPathScore {
    pub(super) fn new(feature_count: usize, hit_count_weight: u64, bytes_consumed: usize) -> Self {
        Self {
            features: feature_count,
            hit_count_weight,
            bytes: bytes_consumed,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct EnergyIndex {
    weights: Vec<f64>,
    tree: Vec<f64>,
    total: f64,
}

impl EnergyIndex {
    pub(super) fn push(&mut self, weight: f64) {
        self.weights.push(0.0);
        self.tree.push(0.0);
        if self.tree.len() == 1 {
            self.tree.push(0.0);
        }
        self.set(self.weights.len() - 1, weight);
    }

    pub(super) fn set(&mut self, index: usize, weight: f64) {
        let Some(slot) = self.weights.get_mut(index) else {
            return;
        };
        let weight = sanitize_energy(weight);
        let delta = weight - *slot;
        *slot = weight;
        self.total += delta;

        let mut tree_index = index + 1;
        while tree_index < self.tree.len() {
            self.tree[tree_index] += delta;
            tree_index += lowbit(tree_index);
        }
    }

    pub(super) fn rebuild(&mut self, weights: impl IntoIterator<Item = f64>) {
        self.weights = weights.into_iter().map(sanitize_energy).collect();
        self.total = self.weights.iter().sum();
        self.tree.clear();
        self.tree.resize(self.weights.len() + 1, 0.0);
        for index in 1..self.tree.len() {
            self.tree[index] += self.weights[index - 1];
            let parent = index + lowbit(index);
            if parent < self.tree.len() {
                self.tree[parent] += self.tree[index];
            }
        }
    }

    pub(super) fn swap_remove(&mut self, index: usize) {
        if index >= self.weights.len() {
            return;
        }
        let last = self.weights.len() - 1;
        if index == last {
            self.set(last, 0.0);
            self.weights.pop();
            self.tree.pop();
            return;
        }

        let moved = self.weights[last];
        self.set(index, moved);
        self.set(last, 0.0);
        self.weights.pop();
        self.tree.pop();
    }

    pub(super) fn sample(&self, rng: &mut SmallRng) -> Option<usize> {
        if self.weights.is_empty() || !self.total.is_finite() || self.total <= 0.0 {
            return None;
        }

        let mut target = rng.random::<f64>() * self.total;
        let mut index = 0;
        let mut bit = self.weights.len().next_power_of_two();
        while bit > 0 {
            let next = index + bit;
            if next < self.tree.len() && self.tree[next] <= target {
                index = next;
                target -= self.tree[next];
            }
            bit >>= 1;
        }

        Some(index.min(self.weights.len() - 1))
    }
}

fn sanitize_energy(weight: f64) -> f64 {
    if weight.is_finite() && weight > 0.0 {
        weight
    } else {
        1.0
    }
}

fn lowbit(value: usize) -> usize {
    value & value.wrapping_neg()
}

/// Counters for a search run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SearchStats {
    pub(crate) generated: u64,
    pub(crate) executed: u64,
    pub(crate) accepted: u64,
    pub(crate) coverage_ids: u64,
    pub(crate) mutated: u64,
}

impl SearchStats {
    /// Build stats from all counters.
    pub const fn new(
        generated: u64,
        executed: u64,
        accepted: u64,
        coverage_ids: u64,
        mutated: u64,
    ) -> Self {
        Self {
            generated,
            executed,
            accepted,
            coverage_ids,
            mutated,
        }
    }

    /// Number of RNG cases yielded.
    pub const fn generated(self) -> u64 {
        self.generated
    }

    /// Number of RNG cases finished.
    pub const fn executed(self) -> u64 {
        self.executed
    }

    /// Number of executions retained in the corpus.
    pub const fn accepted(self) -> u64 {
        self.accepted
    }

    /// Number of accumulated coverage IDs.
    pub const fn coverage_ids(self) -> u64 {
        self.coverage_ids
    }

    /// Number of generated cases derived from mutation.
    pub const fn mutated(self) -> u64 {
        self.mutated
    }
}
