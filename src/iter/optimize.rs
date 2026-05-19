use super::{
    mutate::choose_corpus_index,
    prelude::{
        Active, CAUTIOUS_ENERGY_REFRESH_INTERVAL, CURIOUS_ENERGY_REFRESH_INTERVAL, CandidateOrigin,
        Case, CaseCost, CaseCoverage, CorpusSeed, DEFAULT_CAUTIOUS_MUTATE_DEPTH,
        DEFAULT_MUTATE_DEPTH, MAX_PREFIX_LEN, MinPathScore, StateCore,
    },
    shrink::{
        prune_corpus, record_cautious_discard, record_cautious_improved, record_cautious_preserved,
        refresh_min_path_best, reset_cautious_reducer_to_best,
    },
};
use crate::{
    coverage::{CoverageCapture, CoverageId, CoverageSet},
    sancov::SancovCoverage,
};
use dowsing_rng::{DrawSpan, ScalarSpan, SequenceSpan};
use rand::{Rng, rngs::SmallRng};
use std::{any::TypeId, fmt, marker::PhantomData};

/// Runtime configuration built by a goal.
#[derive(Debug, Clone)]
pub struct GoalConfig {
    pub(super) behavior: Box<dyn GoalBehavior>,
}

impl GoalConfig {
    fn new(behavior: impl GoalBehavior + Clone + 'static) -> Self {
        Self {
            behavior: Box::new(behavior),
        }
    }

    /// Build the built-in coverage discovery configuration.
    pub fn maximize_coverage() -> Self {
        Self::new(MaximizeCoverageGoal)
    }

    /// Build the built-in coverage/path minimization configuration.
    pub fn minimize_coverage() -> Self {
        Self::new(MinimizeCoverageGoal)
    }
}

/// Objective used by [`crate::optimize`].
pub trait Goal: Clone + Send + 'static {
    /// Build the runtime behavior for this goal.
    fn into_config(self) -> GoalConfig;
}

impl Goal for GoalConfig {
    fn into_config(self) -> GoalConfig {
        self
    }
}

pub(super) trait GoalBehavior: fmt::Debug + GoalBehaviorClone + Send {
    fn default_sources(&self) -> Vec<MutationSource>;

    fn fresh_roots(&self) -> bool;

    fn default_mutate_depth(&self) -> usize {
        DEFAULT_MUTATE_DEPTH
    }

    fn energy_refresh_interval(&self) -> u64 {
        CURIOUS_ENERGY_REFRESH_INTERVAL
    }

    fn select_corpus_index(&mut self, state: &mut StateCore) -> Option<usize> {
        choose_corpus_index(state)
    }

    fn builtin_source_enabled(&self, _state: &StateCore, _source: BuiltInMutationSource) -> bool {
        true
    }

    fn record_mutation_scheduled(&mut self, _state: &mut StateCore) {}

    fn record_discarded(
        &mut self,
        state: &mut StateCore,
        origin: &CandidateOrigin,
        mutation_ids: &[TypeId],
    );

    fn record_finished(
        &mut self,
        state: &mut StateCore,
        active: Active,
        run_coverage: CaseCoverage,
        coverage: CoverageSet,
    );

    fn refresh_corpus_energies(&mut self, state: &mut StateCore);

    fn prune_by_worst_score(&self) -> bool {
        false
    }

    fn record_pruned(&mut self, _state: &mut StateCore) {}
}

pub(super) trait GoalBehaviorClone {
    fn clone_goal_box(&self) -> Box<dyn GoalBehavior>;
}

impl<T> GoalBehaviorClone for T
where
    T: GoalBehavior + Clone + 'static,
{
    fn clone_goal_box(&self) -> Box<dyn GoalBehavior> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn GoalBehavior> {
    fn clone(&self) -> Self {
        self.clone_goal_box()
    }
}

/// Built-in optimization goals.
pub mod goals {
    use super::{Goal, GoalConfig};

    /// Coverage-discovery goal used by the deprecated `curious()` wrapper.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct MaximizeCoverage;

    /// Coverage-minimization goal used by the deprecated `cautious()` wrapper.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct MinimizeCoverage;

    /// Deprecated name for [`MinimizeCoverage`].
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    #[deprecated(note = "use MinimizeCoverage")]
    pub struct MinimizePath;

    impl Goal for MaximizeCoverage {
        fn into_config(self) -> GoalConfig {
            GoalConfig::maximize_coverage()
        }
    }

    impl Goal for MinimizeCoverage {
        fn into_config(self) -> GoalConfig {
            GoalConfig::minimize_coverage()
        }
    }

    #[allow(deprecated)]
    impl Goal for MinimizePath {
        fn into_config(self) -> GoalConfig {
            GoalConfig::minimize_coverage()
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct MaximizeCoverageGoal;

impl GoalBehavior for MaximizeCoverageGoal {
    fn default_sources(&self) -> Vec<MutationSource> {
        vec![mutations::coverage_havoc()]
    }

    fn fresh_roots(&self) -> bool {
        true
    }

    fn record_discarded(
        &mut self,
        state: &mut StateCore,
        origin: &CandidateOrigin,
        mutation_ids: &[TypeId],
    ) {
        record_common_discarded(state, origin, mutation_ids);
    }

    fn record_finished(
        &mut self,
        state: &mut StateCore,
        active: Active,
        run_coverage: CaseCoverage,
        coverage: CoverageSet,
    ) {
        record_maximize_coverage_execution(self, state, active, run_coverage, coverage);
    }

    fn refresh_corpus_energies(&mut self, state: &mut StateCore) {
        let ln_executions = (state.stats.executed.max(1) as f64).ln();
        for entry in &mut state.corpus {
            let mut energy = 0.0;
            for id in &entry.coverage {
                let frequency = (*state.coverage_frequency.get(id).unwrap_or(&1)).max(1) as f64;
                energy += (ln_executions - frequency.ln()).max(0.0);
            }
            entry.energy = energy.max(1.0);
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct MinimizeCoverageGoal;

impl GoalBehavior for MinimizeCoverageGoal {
    fn default_sources(&self) -> Vec<MutationSource> {
        vec![
            mutations::semantic_reductions(),
            mutations::minimizing_havoc(),
        ]
    }

    fn fresh_roots(&self) -> bool {
        false
    }

    fn default_mutate_depth(&self) -> usize {
        DEFAULT_CAUTIOUS_MUTATE_DEPTH
    }

    fn energy_refresh_interval(&self) -> u64 {
        CAUTIOUS_ENERGY_REFRESH_INTERVAL
    }

    fn select_corpus_index(&mut self, state: &mut StateCore) -> Option<usize> {
        state
            .energy_index
            .sample(&mut state.scheduler)
            .or_else(|| Some(state.scheduler.random_range(0..state.corpus.len())))
    }

    fn builtin_source_enabled(&self, state: &StateCore, source: BuiltInMutationSource) -> bool {
        source != BuiltInMutationSource::MinimizingHavoc || state.cautious_options.havoc()
    }

    fn record_mutation_scheduled(&mut self, state: &mut StateCore) {
        state.executions_since_refresh = state.executions_since_refresh.saturating_add(1);
        if state.executions_since_refresh >= self.energy_refresh_interval() {
            refresh_goal_corpus_energies(self, state);
        }
    }

    fn record_discarded(
        &mut self,
        state: &mut StateCore,
        origin: &CandidateOrigin,
        mutation_ids: &[TypeId],
    ) {
        record_common_discarded(state, origin, mutation_ids);
        record_cautious_discard(state, origin);
    }

    fn record_finished(
        &mut self,
        state: &mut StateCore,
        active: Active,
        run_coverage: CaseCoverage,
        coverage: CoverageSet,
    ) {
        record_minimize_coverage_execution(self, state, active, run_coverage, coverage);
    }

    fn refresh_corpus_energies(&mut self, state: &mut StateCore) {
        if let Some(best) = state.min_path_best {
            for entry in &mut state.corpus {
                entry.energy = min_path_schedule_energy(
                    &state.min_path_removed_frequency,
                    state.stats.accepted,
                    best,
                    &entry.removed,
                    MinPathScore::with_case_cost(
                        entry.case_cost,
                        entry.score,
                        entry.hit_count_weight,
                        entry.path_len,
                        entry.nonzero_bytes,
                    ),
                );
            }
        }
    }

    fn prune_by_worst_score(&self) -> bool {
        true
    }

    fn record_pruned(&mut self, state: &mut StateCore) {
        refresh_min_path_best(state);
        reset_cautious_reducer_to_best(state);
    }
}

fn with_goal<R>(
    state: &mut StateCore,
    f: impl FnOnce(&mut dyn GoalBehavior, &mut StateCore) -> R,
) -> R {
    let mut goal = state.goal.take().expect("optimizer goal is configured");
    let result = f(goal.as_mut(), state);
    state.goal = Some(goal);
    result
}

pub(super) fn select_goal_corpus_index(state: &mut StateCore) -> Option<usize> {
    with_goal(state, |goal, state| goal.select_corpus_index(state))
}

pub(super) fn builtin_source_enabled(state: &mut StateCore, source: BuiltInMutationSource) -> bool {
    with_goal(state, |goal, state| {
        goal.builtin_source_enabled(state, source)
    })
}

pub(super) fn record_mutation_scheduled(state: &mut StateCore) {
    with_goal(state, |goal, state| {
        goal.record_mutation_scheduled(state);
    });
}

pub(super) fn record_discarded_goal_execution(
    state: &mut StateCore,
    origin: &CandidateOrigin,
    mutation_ids: &[TypeId],
) {
    with_goal(state, |goal, state| {
        goal.record_discarded(state, origin, mutation_ids);
    });
}

fn record_common_discarded(
    state: &mut StateCore,
    origin: &CandidateOrigin,
    mutation_ids: &[TypeId],
) {
    state.mutation_weights.reward_many(mutation_ids, 0.90);
    record_custom_source_feedback(state, origin, SourceFeedback::Discarded);
}

pub(super) fn record_finished_goal_execution(
    state: &mut StateCore,
    active: Active,
    run_coverage: CaseCoverage,
    coverage: CoverageSet,
) {
    with_goal(state, |goal, state| {
        goal.record_finished(state, active, run_coverage, coverage);
    });
}

fn record_maximize_coverage_execution(
    goal: &mut dyn GoalBehavior,
    state: &mut StateCore,
    active: Active,
    run_coverage: CaseCoverage,
    coverage: CoverageSet,
) {
    let mutation_ids = active.origin.mutation_ids().to_vec();
    for id in coverage.iter() {
        *state.coverage_frequency.entry(id).or_insert(0) += 1;
    }
    state.executions_since_refresh = state.executions_since_refresh.saturating_add(1);
    if state.executions_since_refresh >= goal.energy_refresh_interval() {
        refresh_goal_corpus_energies(goal, state);
    }

    if coverage.difference(&state.global).is_empty() {
        record_goal_rejected(state, &active.origin, &mutation_ids);
        return;
    }

    state.mutation_weights.reward_many(&mutation_ids, 1.25);
    record_custom_source_feedback(state, &active.origin, SourceFeedback::Accepted);

    let coverage_ids: Vec<_> = coverage.iter().collect();
    let energy = corpus_energy(state, &coverage_ids);
    state.stats.accepted += 1;
    state.global.extend(coverage.iter());
    state.stats.coverage_ids = state.global.len() as u64;
    push_corpus_seed(
        state,
        active,
        run_coverage,
        coverage_ids,
        Vec::new(),
        energy,
    );
    if prune_corpus(state, goal.prune_by_worst_score()) {
        goal.record_pruned(state);
    }
}

fn record_minimize_coverage_execution(
    goal: &mut dyn GoalBehavior,
    state: &mut StateCore,
    active: Active,
    run_coverage: CaseCoverage,
    coverage: CoverageSet,
) {
    let mutation_ids = active.origin.mutation_ids().to_vec();
    let removed_ids: Vec<_> = if !state.min_path_target_initialized {
        state.min_path_target = coverage.clone();
        state.min_path_target_initialized = true;
        Vec::new()
    } else {
        state.min_path_target.difference(&coverage).iter().collect()
    };
    let candidate_score = min_path_score(run_coverage, &active);
    let improves_best = state
        .min_path_best
        .is_none_or(|_| improves_min_path(state, candidate_score, &active));

    let mutation_reward = if improves_best { 1.25 } else { 1.10 };
    state
        .mutation_weights
        .reward_many(&mutation_ids, mutation_reward);
    record_custom_source_feedback(
        state,
        &active.origin,
        if improves_best {
            SourceFeedback::Improved
        } else {
            SourceFeedback::Accepted
        },
    );
    if improves_best {
        record_cautious_improved(state, &active.origin);
    }

    for id in &removed_ids {
        *state.min_path_removed_frequency.entry(*id).or_insert(0) += 1;
    }
    state.stats.accepted += 1;
    let best = state
        .min_path_best
        .map(|best| best.min(candidate_score))
        .unwrap_or(candidate_score);
    let energy = min_path_schedule_energy(
        &state.min_path_removed_frequency,
        state.stats.accepted,
        best,
        &removed_ids,
        candidate_score,
    );
    let score = run_coverage.feature_count();
    if improves_best {
        state.global = coverage.clone();
        state.stats.coverage_ids = score as u64;
    }

    let origin = active.origin.clone();
    let coverage_ids: Vec<_> = coverage.iter().collect();
    let inserted_index = push_corpus_seed(
        state,
        active,
        run_coverage,
        coverage_ids,
        removed_ids,
        energy,
    );
    if improves_best {
        state.min_path_best = Some(candidate_score);
        state.min_path_best_index = Some(inserted_index);
        refresh_goal_corpus_energies(goal, state);
        reset_cautious_reducer_to_best(state);
    } else {
        record_cautious_preserved(state, &origin);
    }
    if prune_corpus(state, goal.prune_by_worst_score()) {
        goal.record_pruned(state);
    }
}

fn push_corpus_seed(
    state: &mut StateCore,
    active: Active,
    run_coverage: CaseCoverage,
    coverage: Vec<CoverageId>,
    removed: Vec<CoverageId>,
    energy: f64,
) -> usize {
    let mut corpus_prefix = active.case.flatten_prefix();
    if corpus_prefix.len() > MAX_PREFIX_LEN {
        corpus_prefix.truncate(MAX_PREFIX_LEN);
    }
    let score = run_coverage.feature_count();
    let hit_count_weight = run_coverage.hit_count_weight();
    let path_len = run_coverage.bytes_consumed();
    let nonzero_bytes = active.trace.iter().filter(|byte| **byte != 0).count();
    state.corpus.push(CorpusSeed {
        case: active.case,
        seed: active.seed,
        prefix: corpus_prefix,
        draws: active.draws,
        scalars: active.scalars,
        sequences: active.sequences,
        coverage,
        removed,
        case_cost: run_coverage.case_cost(),
        score,
        hit_count_weight,
        path_len,
        nonzero_bytes,
        energy,
    });
    let inserted_index = state.corpus.len() - 1;
    state.energy_index.push(energy);
    inserted_index
}

fn record_goal_rejected(state: &mut StateCore, origin: &CandidateOrigin, mutation_ids: &[TypeId]) {
    state.mutation_weights.reward_many(mutation_ids, 0.90);
    record_custom_source_feedback(state, origin, SourceFeedback::Rejected);
}

fn min_path_score(run_coverage: CaseCoverage, active: &Active) -> MinPathScore {
    let nonzero_bytes = active.trace.iter().filter(|byte| **byte != 0).count();
    MinPathScore::with_case_cost(
        run_coverage.case_cost(),
        run_coverage.feature_count(),
        run_coverage.hit_count_weight(),
        run_coverage.bytes_consumed(),
        nonzero_bytes,
    )
}

fn improves_min_path(state: &StateCore, candidate_score: MinPathScore, active: &Active) -> bool {
    let Some(best_score) = state.min_path_best else {
        return true;
    };

    match candidate_score.cmp(&best_score) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => {
            let Some(best_index) = state.min_path_best_index else {
                return true;
            };
            let Some(best) = state.corpus.get(best_index) else {
                return true;
            };

            (active.draws.len(), active.trace.as_slice())
                < (best.draws.len(), best.prefix.as_slice())
        }
    }
}

fn record_custom_source_feedback(
    state: &mut StateCore,
    origin: &CandidateOrigin,
    feedback: SourceFeedback,
) {
    let Some(index) = origin.custom_source() else {
        return;
    };
    let Some(source) = state.candidate_sources.get_mut(index) else {
        return;
    };
    if let MutationSourceKind::Custom(source) = &mut source.kind {
        source.record_feedback(feedback);
    }
}

pub(super) fn corpus_energy(state: &StateCore, coverage: &[CoverageId]) -> f64 {
    let ln_executions = (state.stats.executed.max(1) as f64).ln();
    let mut energy = 0.0;
    for id in coverage {
        let frequency = (*state.coverage_frequency.get(id).unwrap_or(&1)).max(1) as f64;
        energy += (ln_executions - frequency.ln()).max(0.0);
    }
    energy.max(1.0)
}

fn refresh_goal_corpus_energies(goal: &mut dyn GoalBehavior, state: &mut StateCore) {
    goal.refresh_corpus_energies(state);
    state
        .energy_index
        .rebuild(state.corpus.iter().map(|entry| entry.energy));
    state.executions_since_refresh = 0;
}

pub(super) fn min_path_schedule_energy(
    removed_frequency: &rustc_hash::FxHashMap<CoverageId, u64>,
    accepted: u64,
    best: MinPathScore,
    removed: &[CoverageId],
    candidate: MinPathScore,
) -> f64 {
    let accepted = accepted.max(1) as f64;
    let mut rarity = 0.0;
    for id in removed {
        let frequency = (*removed_frequency.get(id).unwrap_or(&1)).max(1) as f64;
        rarity += (accepted / frequency).ln().max(0.0);
    }

    let byte_quality = ((best.bytes + 1) as f64 / (candidate.bytes + 1) as f64)
        .min(1.0)
        .powi(3);
    let feature_quality = ((best.features + 1) as f64 / (candidate.features + 1) as f64)
        .min(1.0)
        .sqrt();
    let hit_quality = ((best.hit_count_weight + 1) as f64
        / (candidate.hit_count_weight + 1) as f64)
        .min(1.0)
        .sqrt();
    let cost_quality = case_cost_quality(best.case_cost, candidate.case_cost).powi(3);
    let simplicity_quality = ((best.nonzero_bytes + 1) as f64
        / (candidate.nonzero_bytes + 1) as f64)
        .min(1.0)
        .sqrt();
    let quality = cost_quality * byte_quality * feature_quality * hit_quality * simplicity_quality;
    ((rarity + 1.0) * quality).max(0.01)
}

fn case_cost_quality(best: CaseCost, candidate: CaseCost) -> f64 {
    (best.raw().saturating_add(1) as f64 / candidate.raw().saturating_add(1) as f64).min(1.0)
}

/// Context passed to custom candidate sources.
pub struct MutationContext<'a> {
    parent: &'a Case,
    parent_prefix: &'a [u8],
    draws: &'a [DrawSpan],
    scalars: &'a [ScalarSpan],
    sequences: &'a [SequenceSpan],
    dictionary: &'a [Vec<u8>],
    rng: &'a mut SmallRng,
    fallback_seed: u64,
    max_prefix_len: usize,
}

impl<'a> MutationContext<'a> {
    pub(super) fn new(
        parent: &'a Case,
        parent_prefix: &'a [u8],
        draws: &'a [DrawSpan],
        scalars: &'a [ScalarSpan],
        sequences: &'a [SequenceSpan],
        dictionary: &'a [Vec<u8>],
        rng: &'a mut SmallRng,
        fallback_seed: u64,
    ) -> Self {
        Self {
            parent,
            parent_prefix,
            draws,
            scalars,
            sequences,
            dictionary,
            rng,
            fallback_seed,
            max_prefix_len: MAX_PREFIX_LEN,
        }
    }

    /// Parent replay case selected from the corpus.
    pub fn parent(&self) -> &Case {
        self.parent
    }

    /// Flattened parent bytes.
    pub fn parent_prefix(&self) -> &[u8] {
        self.parent_prefix
    }

    /// Semantic byte draws recorded by the parent.
    pub fn draws(&self) -> &[DrawSpan] {
        self.draws
    }

    /// Shrink-aware scalar spans recorded by the parent.
    pub fn scalars(&self) -> &[ScalarSpan] {
        self.scalars
    }

    /// Semantic range spans recorded by the parent.
    pub fn sequences(&self) -> &[SequenceSpan] {
        self.sequences
    }

    /// Comparison dictionary values learned so far.
    pub fn dictionary(&self) -> &[Vec<u8>] {
        self.dictionary
    }

    /// Scheduler RNG for this source invocation.
    pub fn rng(&mut self) -> &mut SmallRng {
        self.rng
    }

    /// Fresh seed component reserved for this candidate.
    pub fn fallback_seed(&self) -> u64 {
        self.fallback_seed
    }

    /// Maximum flattened prefix length retained by the optimizer.
    pub fn max_prefix_len(&self) -> usize {
        self.max_prefix_len
    }
}

/// Candidate emitted by a custom candidate source.
#[derive(Debug, Clone)]
pub struct MutationCandidate {
    case: Option<Case>,
    prefix: Option<Vec<u8>>,
    mutations: Vec<TypeId>,
}

impl MutationCandidate {
    /// Build a candidate from a mutated flattened prefix.
    pub fn from_prefix(prefix: Vec<u8>) -> Self {
        Self {
            case: None,
            prefix: Some(prefix),
            mutations: Vec::new(),
        }
    }

    /// Build a candidate from a full replay case.
    pub fn from_case(case: Case) -> Self {
        Self {
            case: Some(case),
            prefix: None,
            mutations: Vec::new(),
        }
    }

    /// Attach one mutation type to this candidate.
    pub fn with_mutation<T: 'static>(mut self) -> Self {
        self.mutations.push(TypeId::of::<T>());
        self
    }

    /// Attach several mutation type identifiers to this candidate.
    pub fn with_mutations(mut self, ids: impl IntoIterator<Item = TypeId>) -> Self {
        self.mutations.extend(ids);
        self
    }

    pub(super) fn materialize(
        mut self,
        parent_seed: u64,
        fallback: u64,
        rng: &mut SmallRng,
    ) -> (Case, Vec<TypeId>) {
        let case = if let Some(case) = self.case.take() {
            case
        } else {
            let mut prefix = self.prefix.take().unwrap_or_default();
            if prefix.is_empty() {
                prefix.push(rng.random());
            }
            if prefix.len() > MAX_PREFIX_LEN {
                prefix.truncate(MAX_PREFIX_LEN);
            }
            Case::from_flat_prefix(parent_seed ^ fallback.rotate_left(17), prefix)
        };
        (case, self.mutations)
    }
}

/// Feedback delivered to custom candidate sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFeedback {
    /// Candidate was discarded by the harness.
    Discarded,
    /// Candidate was executed but not retained by the goal.
    Rejected,
    /// Candidate was retained by the goal.
    Accepted,
    /// Candidate became the current best retained case.
    Improved,
}

/// User-extensible producer of mutation candidates.
pub trait CandidateSource: fmt::Debug + CandidateSourceClone + Send {
    /// Try to produce one candidate from the selected parent.
    fn next_candidate(&mut self, context: &mut MutationContext<'_>) -> Option<MutationCandidate>;

    /// Observe feedback for a candidate previously emitted by this source.
    fn record_feedback(&mut self, _feedback: SourceFeedback) {}
}

/// Clone support for boxed custom candidate sources.
pub trait CandidateSourceClone {
    /// Clone this source into a boxed trait object.
    fn clone_source_box(&self) -> Box<dyn CandidateSource>;
}

impl<T> CandidateSourceClone for T
where
    T: CandidateSource + Clone + 'static,
{
    fn clone_source_box(&self) -> Box<dyn CandidateSource> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn CandidateSource> {
    fn clone(&self) -> Self {
        self.clone_source_box()
    }
}

/// Configured candidate source.
#[derive(Debug, Clone)]
pub struct MutationSource {
    pub(super) kind: MutationSourceKind,
}

impl MutationSource {
    /// Wrap a custom source.
    pub fn custom(source: impl CandidateSource + Clone + 'static) -> Self {
        Self {
            kind: MutationSourceKind::Custom(Box::new(source)),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum MutationSourceKind {
    BuiltIn(BuiltInMutationSource),
    Custom(Box<dyn CandidateSource>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BuiltInMutationSource {
    CoverageHavoc,
    MinimizingHavoc,
    SemanticReductions,
}

/// Built-in mutation source constructors.
pub mod mutations {
    use super::{BuiltInMutationSource, MutationSource, MutationSourceKind};

    /// Random exploratory mutations suitable for coverage discovery.
    pub fn coverage_havoc() -> MutationSource {
        MutationSource {
            kind: MutationSourceKind::BuiltIn(BuiltInMutationSource::CoverageHavoc),
        }
    }

    /// Random simplifying mutations suitable for minimization fallback.
    pub fn minimizing_havoc() -> MutationSource {
        MutationSource {
            kind: MutationSourceKind::BuiltIn(BuiltInMutationSource::MinimizingHavoc),
        }
    }

    /// Deterministic semantic reductions over ranges, scalars, draws, and byte spans.
    pub fn semantic_reductions() -> MutationSource {
        MutationSource {
            kind: MutationSourceKind::BuiltIn(BuiltInMutationSource::SemanticReductions),
        }
    }
}

/// General optimizer returned by [`crate::optimize`].
pub struct Optimizer<G = goals::MaximizeCoverage, Capture: CoverageCapture = SancovCoverage> {
    pub(super) engine: super::prelude::Engine<Capture>,
    pub(super) goal: PhantomData<G>,
}

impl<G, Capture> Clone for Optimizer<G, Capture>
where
    G: Goal,
    Capture: CoverageCapture,
{
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            goal: PhantomData,
        }
    }
}

pub(super) fn optimizer_from_engine<G, Capture>(
    engine: super::prelude::Engine<Capture>,
) -> Optimizer<G, Capture>
where
    G: Goal,
    Capture: CoverageCapture,
{
    Optimizer {
        engine,
        goal: PhantomData,
    }
}
