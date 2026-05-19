pub(super) use super::mutation::{MutationWeights, ReductionOp};
pub(super) use super::optimize::{GoalBehavior, MutationSource};
use crate::{
    coverage::{CoverageCapture, CoverageId, CoverageSet},
    sancov::SancovCoverage,
};
pub use dowsing_rng::Trace as Case;
pub(super) use dowsing_rng::{DrawSpan, ScalarSpan, SequenceSpan};
use parking_lot::Mutex;
use rand::{Rng, rngs::SmallRng};
use rustc_hash::FxHashMap;
use std::{
    any::TypeId,
    cmp::Ordering,
    collections::{HashSet, VecDeque},
    ops::{Deref, DerefMut},
    sync::Arc,
};

pub(super) const DEFAULT_MUTATE_DEPTH: usize = 5;
pub(super) const DEFAULT_CAUTIOUS_MUTATE_DEPTH: usize = 1;
pub(super) const DEFAULT_SEED_RATIO: u64 = 8;
pub(super) const CURIOUS_ENERGY_REFRESH_INTERVAL: u64 = 64;
pub(super) const CAUTIOUS_ENERGY_REFRESH_INTERVAL: u64 = 1024;
pub(super) const MAX_PREFIX_LEN: usize = 4096;
pub(super) const MAX_CORPUS_LEN: usize = 4096;
pub(super) const MAX_REDUCER_TRIED_PREFIXES: usize = 65536;
pub(super) const MAX_DICTIONARY_VALUES: usize = 256;
pub(super) const INTERESTING_BYTES: [u8; 10] = [0, 1, 16, 31, 32, 63, 64, 127, 128, 255];
const REDUCTION_OPERATION_COUNT: usize = 15;
const MIN_REDUCTION_WEIGHT: f64 = 0.05;
const MAX_REDUCTION_WEIGHT: f64 = 64.0;
const REDUCTION_WEIGHT_PRIORITY_SCALE: f64 = 1_000_000.0;

/// Tuning knobs for [`cautious`] minimization.
///
/// The defaults favor thorough reduction. Large or expensive harnesses can lower the reducer budget,
/// cap generated candidates per operation, or disable havoc fallback after deterministic reductions are
/// exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CautiousOptions {
    pub(crate) reducer_budget: usize,
    pub(crate) operation_candidate_limit: usize,
    pub(crate) draw_limit: usize,
    pub(crate) range_limit: usize,
    pub(crate) range_reductions: bool,
    pub(crate) havoc: bool,
}

impl CautiousOptions {
    /// Build default minimization options.
    pub const fn new() -> Self {
        Self {
            reducer_budget: 8192,
            operation_candidate_limit: 8192,
            draw_limit: 512,
            range_limit: 4096,
            range_reductions: true,
            havoc: true,
        }
    }

    /// Set the maximum internal reducer attempts spent to produce one yielded candidate.
    pub fn with_reducer_budget(mut self, budget: usize) -> Self {
        self.reducer_budget = budget.max(1);
        self
    }

    pub(super) const fn reducer_budget(self) -> usize {
        self.reducer_budget
    }

    pub(super) const fn operation_candidate_limit(self) -> usize {
        self.operation_candidate_limit
    }

    pub(super) const fn draw_limit(self) -> usize {
        self.draw_limit
    }

    pub(super) const fn range_limit(self) -> usize {
        self.range_limit
    }

    pub(super) const fn range_reductions(self) -> bool {
        self.range_reductions
    }

    pub(super) const fn havoc(self) -> bool {
        self.havoc
    }
}

impl Default for CautiousOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Domain-specific cost for one valid generated value.
///
/// Lower costs are better. `cautious()` uses this before coverage and RNG-path size when the
/// caller finishes a reproducing case with [`crate::CaseRng::coverage_with_cost`]. This lets a
/// harness keep invalid or non-reproducing cases out of the corpus with [`crate::CaseRng::discard`]
/// while still telling the minimizer which reproducing values are smaller in the harness domain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct CaseCost(usize);

impl CaseCost {
    pub(crate) const fn zero() -> Self {
        Self(0)
    }

    pub(crate) const fn new(cost: usize) -> Self {
        Self(cost)
    }

    pub(crate) const fn raw(self) -> usize {
        self.0
    }
}

impl From<usize> for CaseCost {
    fn from(value: usize) -> Self {
        Self::new(value)
    }
}

/// Coverage, path-size, and domain-cost stats for one completed [`crate::CaseRng`] execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaseCoverage {
    pub(crate) case_cost: CaseCost,
    pub(crate) feature_count: usize,
    pub(crate) hit_count_weight: u64,
    pub(crate) bytes_consumed: usize,
}

impl CaseCoverage {
    pub(crate) const fn with_cost(
        case_cost: CaseCost,
        feature_count: usize,
        hit_count_weight: u64,
        bytes_consumed: usize,
    ) -> Self {
        Self {
            case_cost,
            feature_count,
            hit_count_weight,
            bytes_consumed,
        }
    }

    /// Domain-specific cost supplied by the harness.
    pub const fn case_cost(self) -> CaseCost {
        self.case_cost
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
            self.case_cost,
            self.feature_count,
            self.hit_count_weight,
            self.bytes_consumed,
        )
            .cmp(&(
                other.case_cost,
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
#[deprecated(note = "use optimize(goals::MaximizeCoverage)")]
pub fn curious() -> Curious<SancovCoverage> {
    Curious {
        engine: Engine::new(
            SancovCoverage::new(),
            super::optimize::goals::MaximizeCoverage,
        ),
    }
}

/// Code-path-minimizing RNG iterator.
///
/// Seed it with [`Cautious::with_case`]. Each yielded variant records coverage unless the caller
/// excludes it with [`crate::CaseRng::discard`].
#[deprecated(note = "use optimize(goals::MinimizeCoverage)")]
pub fn cautious() -> Cautious<SancovCoverage> {
    Cautious {
        engine: Engine::new(
            SancovCoverage::new(),
            super::optimize::goals::MinimizeCoverage,
        ),
    }
}

/// Build a generalized optimizer for `goal`.
pub fn optimize<G>(goal: G) -> super::optimize::Optimizer<G, SancovCoverage>
where
    G: super::optimize::Goal,
{
    super::optimize::optimizer_from_engine(Engine::new(SancovCoverage::new(), goal))
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
    pub(super) core: StateCore,
}

impl<Capture: CoverageCapture> Deref for State<Capture> {
    type Target = StateCore;
    fn deref(&self) -> &StateCore {
        &self.core
    }
}

impl<Capture: CoverageCapture> DerefMut for State<Capture> {
    fn deref_mut(&mut self) -> &mut StateCore {
        &mut self.core
    }
}

#[derive(Debug)]
pub(super) struct StateCore {
    pub(super) goal: Option<Box<dyn GoalBehavior>>,
    pub(super) base_seed: u64,
    pub(super) next: u64,
    pub(super) scheduler: SmallRng,
    pub(super) global: CoverageSet,
    pub(super) coverage_frequency: FxHashMap<CoverageId, u64>,
    pub(super) min_path_removed_frequency: FxHashMap<CoverageId, u64>,
    pub(super) min_path_target: CoverageSet,
    pub(super) min_path_target_initialized: bool,
    pub(super) min_path_best: Option<MinPathScore>,
    pub(super) min_path_best_index: Option<usize>,
    pub(super) corpus: Vec<CorpusSeed>,
    pub(super) energy_index: EnergyIndex,
    pub(super) pending_cases: VecDeque<Case>,
    pub(super) candidate_sources: Vec<MutationSource>,
    pub(super) fresh_roots: bool,
    pub(super) cautious_reducer: CautiousReducer,
    pub(super) mutation_weights: MutationWeights,
    pub(super) reduction_weights: ReductionWeights,
    pub(super) dictionary: Arc<Vec<Vec<u8>>>,
    pub(super) cautious_options: CautiousOptions,
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
    pub(super) case: Case,
    pub(super) trace: Vec<u8>,
    pub(super) draws: Vec<DrawSpan>,
    pub(super) scalars: Vec<ScalarSpan>,
    pub(super) sequences: Vec<SequenceSpan>,
    pub(super) bytes_consumed: usize,
    pub(super) origin: CandidateOrigin,
}

#[derive(Debug, Clone)]
pub(super) struct CorpusSeed {
    pub(super) case: Case,
    pub(super) seed: u64,
    pub(super) prefix: Vec<u8>,
    pub(super) draws: Vec<DrawSpan>,
    pub(super) scalars: Vec<ScalarSpan>,
    pub(super) sequences: Vec<SequenceSpan>,
    pub(super) coverage: Vec<CoverageId>,
    pub(super) removed: Vec<CoverageId>,
    pub(super) case_cost: CaseCost,
    pub(super) score: usize,
    pub(super) hit_count_weight: u64,
    pub(super) path_len: usize,
    pub(super) nonzero_bytes: usize,
    pub(super) energy: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct MinPathScore {
    pub(super) case_cost: CaseCost,
    pub(super) features: usize,
    pub(super) hit_count_weight: u64,
    pub(super) bytes: usize,
    pub(super) nonzero_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CandidateOrigin {
    SeededCase,
    CuriousMutation(Vec<TypeId>),
    CautiousReduction(ReductionId),
    CautiousHavoc(Vec<TypeId>),
    CustomMutation {
        source: usize,
        mutations: Vec<TypeId>,
    },
}

impl CandidateOrigin {
    pub(super) fn mutation_ids(&self) -> &[TypeId] {
        match self {
            Self::SeededCase => &[],
            Self::CuriousMutation(kinds) | Self::CautiousHavoc(kinds) => kinds,
            Self::CautiousReduction(id) => std::slice::from_ref(&id.type_id),
            Self::CustomMutation { mutations, .. } => mutations,
        }
    }

    pub(super) fn custom_source(&self) -> Option<usize> {
        match self {
            Self::CustomMutation { source, .. } => Some(*source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct CautiousReducer {
    pub(super) epoch: u64,
    pub(super) best_index: Option<usize>,
    pub(super) best_seed: u64,
    pub(super) best_case: Case,
    pub(super) best_prefix: Vec<u8>,
    pub(super) best_draws: Vec<DrawSpan>,
    pub(super) best_scalars: Vec<ScalarSpan>,
    pub(super) best_sequences: Vec<SequenceSpan>,
    pub(super) operation_states: Vec<ReductionOperationState>,
    pub(super) tried_prefixes: HashSet<PrefixFingerprint>,
    pub(super) range_pressure: Vec<u16>,
    pub(super) rejects: u64,
    pub(super) preserves: u64,
    pub(super) exhausted: bool,
}

impl Default for CautiousReducer {
    fn default() -> Self {
        Self {
            epoch: 0,
            best_index: None,
            best_seed: 0,
            best_case: Case::empty(0),
            best_prefix: Vec::new(),
            best_draws: Vec::new(),
            best_scalars: Vec::new(),
            best_sequences: Vec::new(),
            operation_states: Vec::new(),
            tried_prefixes: HashSet::new(),
            range_pressure: Vec::new(),
            rejects: 0,
            preserves: 0,
            exhausted: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct PrefixFingerprint {
    pub(super) len: usize,
    pub(super) hash: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ReductionId {
    pub(super) epoch: u64,
    pub(super) operation: ReductionOperation,
    pub(super) type_id: TypeId,
    pub(super) cursor: usize,
    pub(super) start: usize,
    pub(super) len: usize,
    pub(super) target: u64,
    pub(super) fingerprint: PrefixFingerprint,
}

#[derive(Debug, Clone)]
pub(super) struct ReductionOperationState {
    pub(super) operation: ReductionOperation,
    pub(super) specs: Vec<ReductionSpec>,
    pub(super) cursor: usize,
    pub(super) rejects: u64,
    pub(super) preserves: u64,
    pub(super) drained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ReductionOperation {
    ScalarGroup,
    ScalarCommonOffset,
    ScalarLower,
    DrawLength,
    TailTrim,
    DrawDelete,
    WeightedBlockDelete,
    BlockZero,
    WordLower,
    ByteLower,
    RepeatedValue,
    DictionaryRepair,
    SequenceDelete,
    SequenceProject,
    SequenceReplace,
}

impl ReductionOperation {
    const fn index(self) -> usize {
        match self {
            Self::ScalarGroup => 0,
            Self::ScalarCommonOffset => 1,
            Self::ScalarLower => 2,
            Self::DrawLength => 3,
            Self::TailTrim => 4,
            Self::DrawDelete => 5,
            Self::WeightedBlockDelete => 6,
            Self::BlockZero => 7,
            Self::WordLower => 8,
            Self::ByteLower => 9,
            Self::RepeatedValue => 10,
            Self::DictionaryRepair => 11,
            Self::SequenceDelete => 12,
            Self::SequenceProject => 13,
            Self::SequenceReplace => 14,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ReductionWeights {
    multipliers: [f64; REDUCTION_OPERATION_COUNT],
}

impl Default for ReductionWeights {
    fn default() -> Self {
        Self {
            multipliers: [1.0; REDUCTION_OPERATION_COUNT],
        }
    }
}

impl ReductionWeights {
    pub(super) fn priority_key(&self, operation: ReductionOperation) -> u64 {
        (self.multiplier(operation) * REDUCTION_WEIGHT_PRIORITY_SCALE).round() as u64
    }

    pub(super) fn reward_improved(&mut self, operation: ReductionOperation) {
        self.apply_factor(operation, 3.0);
        match operation {
            ReductionOperation::ScalarGroup => {
                self.apply_factor(ReductionOperation::ScalarCommonOffset, 1.5);
                self.apply_factor(ReductionOperation::ScalarLower, 2.0);
            }
            ReductionOperation::ScalarCommonOffset => {
                self.apply_factor(ReductionOperation::ScalarLower, 4.0);
            }
            _ => {}
        }
    }

    pub(super) fn reward_preserved(&mut self, operation: ReductionOperation) {
        self.apply_factor(operation, 1.15);
    }

    pub(super) fn penalize_rejected(&mut self, operation: ReductionOperation) {
        self.apply_factor(operation, 0.50);
    }

    fn multiplier(&self, operation: ReductionOperation) -> f64 {
        self.multipliers[operation.index()]
    }

    fn apply_factor(&mut self, operation: ReductionOperation, factor: f64) {
        if !factor.is_finite() || factor <= 0.0 {
            return;
        }
        let slot = &mut self.multipliers[operation.index()];
        *slot = (*slot * factor).clamp(MIN_REDUCTION_WEIGHT, MAX_REDUCTION_WEIGHT);
    }
}

#[cfg(test)]
mod reduction_weight_tests {
    use super::{ReductionOperation, ReductionWeights};

    #[test]
    fn scalar_common_offset_success_boosts_scalar_lower_followup() {
        let mut weights = ReductionWeights::default();

        weights.reward_improved(ReductionOperation::ScalarCommonOffset);

        assert!(weights.multiplier(ReductionOperation::ScalarLower) > 1.0);
        assert!(
            weights.multiplier(ReductionOperation::ScalarLower)
                > weights.multiplier(ReductionOperation::ScalarCommonOffset)
        );
        assert_eq!(weights.multiplier(ReductionOperation::ByteLower), 1.0);
    }

    #[test]
    fn rejected_operations_are_penalized_and_clamped() {
        let mut weights = ReductionWeights::default();

        for _ in 0..16 {
            weights.penalize_rejected(ReductionOperation::ScalarLower);
        }

        assert_eq!(weights.multiplier(ReductionOperation::ScalarLower), 0.05);
    }
}

#[derive(Debug, Clone)]
pub(super) struct ReductionSpec {
    pub(super) op: ReductionOp,
    pub(super) bias: u64,
}

impl ReductionSpec {
    pub(super) fn start(&self) -> usize {
        self.op.start()
    }

    pub(super) fn len(&self) -> usize {
        self.op.len()
    }

    pub(super) fn target(&self) -> u64 {
        self.op.target()
    }

    pub(super) fn simplification(&self) -> usize {
        self.op.simplification()
    }
}

impl MinPathScore {
    pub(super) fn with_case_cost(
        case_cost: CaseCost,
        feature_count: usize,
        hit_count_weight: u64,
        bytes_consumed: usize,
        nonzero_bytes: usize,
    ) -> Self {
        Self {
            case_cost,
            features: feature_count,
            hit_count_weight,
            bytes: bytes_consumed,
            nonzero_bytes,
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
