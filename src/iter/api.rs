#[cfg(test)]
use super::prelude::MinPathScore;
use super::{
    optimize::{Goal, Optimizer, optimizer_from_engine},
    prelude::{
        Case, Cautious, CautiousOptions, CautiousReducer, Curious, DEFAULT_SEED_RATIO, EnergyIndex,
        Engine, ReductionWeights, SearchStats, State, StateCore,
    },
    rng::CaseRng,
    run::next_parallel_rng,
};
#[cfg(test)]
use crate::coverage::CoverageId;
use crate::{
    coverage::{CoverageCapture, CoverageSet, ParallelCoverageCapture},
    sancov::SancovCoverage,
};
use parking_lot::Mutex;
use rand::{SeedableRng, rngs::SmallRng};
use rayon::iter::{IntoParallelIterator, ParallelIterator, plumbing::UnindexedConsumer};
use rustc_hash::FxHashMap;
use std::{collections::VecDeque, sync::Arc};

impl<Capture: CoverageCapture> Engine<Capture> {
    pub(super) fn new<G>(capture: Capture, goal: G) -> Self
    where
        G: Goal,
    {
        let goal_config = goal.into_config();
        let candidate_sources = goal_config.behavior.default_sources();
        let fresh_roots = goal_config.behavior.fresh_roots();
        let mutate_depth = goal_config.behavior.default_mutate_depth();
        Self {
            shared: Arc::new(Mutex::new(State {
                capture,
                core: StateCore {
                    goal: Some(goal_config.behavior),
                    base_seed: 0,
                    next: 0,
                    scheduler: SmallRng::seed_from_u64(0xD3A0_51C0_FFEE),
                    global: CoverageSet::new(),
                    coverage_frequency: FxHashMap::default(),
                    min_path_removed_frequency: FxHashMap::default(),
                    min_path_target: CoverageSet::new(),
                    min_path_target_initialized: false,
                    min_path_best: None,
                    min_path_best_index: None,
                    corpus: Vec::new(),
                    energy_index: EnergyIndex::default(),
                    pending_cases: VecDeque::new(),
                    candidate_sources,
                    fresh_roots,
                    cautious_reducer: CautiousReducer::default(),
                    mutation_weights: Default::default(),
                    reduction_weights: ReductionWeights::default(),
                    dictionary: Arc::new(Vec::new()),
                    cautious_options: CautiousOptions::default(),
                    executions_since_refresh: 0,
                    mutate_depth,
                    seed_ratio: DEFAULT_SEED_RATIO,
                    seed_step: 0,
                    active_cases: 0,
                    stats: SearchStats::default(),
                },
            })),
        }
    }

    pub(super) fn with_coverage<NewCapture: CoverageCapture>(
        self,
        capture: NewCapture,
    ) -> Engine<NewCapture> {
        let state = self.shared.lock();
        Engine {
            shared: Arc::new(Mutex::new(State {
                capture,
                core: StateCore {
                    goal: Some(
                        state
                            .goal
                            .as_ref()
                            .expect("optimizer goal is configured")
                            .clone(),
                    ),
                    base_seed: state.base_seed,
                    next: state.next,
                    scheduler: state.scheduler.clone(),
                    global: state.global.clone(),
                    coverage_frequency: state.coverage_frequency.clone(),
                    min_path_removed_frequency: state.min_path_removed_frequency.clone(),
                    min_path_target: state.min_path_target.clone(),
                    min_path_target_initialized: state.min_path_target_initialized,
                    min_path_best: state.min_path_best,
                    min_path_best_index: state.min_path_best_index,
                    corpus: state.corpus.clone(),
                    energy_index: state.energy_index.clone(),
                    pending_cases: state.pending_cases.clone(),
                    candidate_sources: state.candidate_sources.clone(),
                    fresh_roots: state.fresh_roots,
                    cautious_reducer: state.cautious_reducer.clone(),
                    mutation_weights: state.mutation_weights.clone(),
                    reduction_weights: state.reduction_weights.clone(),
                    dictionary: state.dictionary.clone(),
                    cautious_options: state.cautious_options,
                    executions_since_refresh: state.executions_since_refresh,
                    mutate_depth: state.mutate_depth,
                    seed_ratio: state.seed_ratio,
                    seed_step: state.seed_step,
                    active_cases: 0,
                    stats: state.stats,
                },
            })),
        }
    }

    pub(super) fn with_case(self, case: Case) -> Self {
        self.shared.lock().pending_cases.push_back(case);
        self
    }

    pub(super) fn with_cases(self, cases: impl IntoIterator<Item = Case>) -> Self {
        self.shared.lock().pending_cases.extend(cases);
        self
    }

    #[cfg(test)]
    pub(super) fn with_mutate_depth(self, depth: usize) -> Self {
        self.shared.lock().mutate_depth = depth.max(1);
        self
    }

    #[cfg(test)]
    pub(super) fn with_seed_ratio(self, ratio: u64) -> Self {
        self.shared.lock().seed_ratio = ratio.max(1);
        self
    }

    pub(super) fn with_seed(self, seed: u64) -> Self {
        let mut state = self.shared.lock();
        state.base_seed = seed;
        state.next = 0;
        state.scheduler = SmallRng::seed_from_u64(seed ^ 0xD3A0_51C0_FFEE);
        drop(state);
        self
    }

    pub(super) fn with_cautious_options(self, options: CautiousOptions) -> Self {
        self.shared.lock().cautious_options = options;
        self
    }

    pub(super) fn with_mutation_sources(
        self,
        sources: impl IntoIterator<Item = super::optimize::MutationSource>,
    ) -> Self {
        self.shared.lock().candidate_sources = sources.into_iter().collect();
        self
    }

    pub(super) fn with_fresh_roots(self, enabled: bool) -> Self {
        self.shared.lock().fresh_roots = enabled;
        self
    }

    pub(super) fn stats(&self) -> SearchStats {
        self.shared.lock().stats
    }

    #[cfg(test)]
    pub(crate) fn test_corpus_energies(&self) -> Vec<f64> {
        self.shared
            .lock()
            .corpus
            .iter()
            .map(|entry| entry.energy)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn test_feature_frequency(&self, id: CoverageId) -> u64 {
        *self.shared.lock().coverage_frequency.get(&id).unwrap_or(&0)
    }

    #[cfg(test)]
    pub(crate) fn test_corpus_path_lens(&self) -> Vec<usize> {
        self.shared
            .lock()
            .corpus
            .iter()
            .map(|entry| entry.path_len)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn test_best_path_score(&self) -> Option<(usize, u64, usize)> {
        self.shared
            .lock()
            .corpus
            .iter()
            .min_by_key(|entry| {
                MinPathScore::with_case_cost(
                    entry.case_cost,
                    entry.score,
                    entry.hit_count_weight,
                    entry.path_len,
                    entry.nonzero_bytes,
                )
            })
            .map(|entry| (entry.score, entry.hit_count_weight, entry.path_len))
    }

    #[cfg(test)]
    pub(crate) fn test_best_case_cost(&self) -> Option<super::prelude::CaseCost> {
        self.shared
            .lock()
            .min_path_best
            .map(|score| score.case_cost)
    }

    #[cfg(test)]
    pub(crate) fn test_best_nonzero_bytes(&self) -> Option<usize> {
        self.shared
            .lock()
            .min_path_best
            .map(|score| score.nonzero_bytes)
    }

    #[cfg(test)]
    pub(crate) fn test_best_prefix(&self) -> Option<Vec<u8>> {
        let state = self.shared.lock();
        let index = state.min_path_best_index?;
        Some(state.corpus.get(index)?.prefix.clone())
    }

    #[cfg(test)]
    pub(crate) fn test_dictionary_values(&self) -> Vec<Vec<u8>> {
        (*self.shared.lock().dictionary).clone()
    }

    #[cfg(test)]
    pub(crate) fn test_reducer_feedback(&self) -> (u64, u64, Vec<u16>, bool) {
        let state = self.shared.lock();
        (
            state.cautious_reducer.rejects,
            state.cautious_reducer.preserves,
            state.cautious_reducer.range_pressure.clone(),
            state.cautious_reducer.exhausted,
        )
    }
}

impl<Capture> Clone for Engine<Capture>
where
    Capture: CoverageCapture,
{
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<Capture> Clone for Curious<Capture>
where
    Capture: CoverageCapture,
{
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
        }
    }
}

impl<Capture> Clone for Cautious<Capture>
where
    Capture: CoverageCapture,
{
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
        }
    }
}

impl<Capture: CoverageCapture> Curious<Capture> {
    /// Use a real coverage capture backend.
    pub fn with_coverage<NewCapture: CoverageCapture>(
        self,
        capture: NewCapture,
    ) -> Curious<NewCapture> {
        Curious {
            engine: self.engine.with_coverage(capture),
        }
    }

    /// Queue a replayable RNG case to run before generated roots.
    pub fn with_case(self, case: Case) -> Self {
        Self {
            engine: self.engine.with_case(case),
        }
    }

    /// Queue replayable RNG cases to run before generated roots.
    pub fn with_cases(self, cases: impl IntoIterator<Item = Case>) -> Self {
        Self {
            engine: self.engine.with_cases(cases),
        }
    }

    /// Set how many byte-prefix mutations are stacked in havoc-style candidate generation.
    #[cfg(test)]
    pub(crate) fn with_mutate_depth(self, depth: usize) -> Self {
        Self {
            engine: self.engine.with_mutate_depth(depth),
        }
    }

    /// Set how often `curious()` explores a fresh random root while a corpus exists.
    #[cfg(test)]
    pub(crate) fn with_seed_ratio(self, ratio: u64) -> Self {
        Self {
            engine: self.engine.with_seed_ratio(ratio),
        }
    }

    /// Set the first seed.
    pub fn with_seed(self, seed: u64) -> Self {
        Self {
            engine: self.engine.with_seed(seed),
        }
    }

    /// Limit the iterator to `limit` cases.
    ///
    /// This mirrors [`Iterator::take`] for serial use and also provides the native Rayon
    /// entrypoint through [`IntoParallelIterator`].
    pub fn take(self, limit: usize) -> Cases<Self> {
        Cases {
            inner: self,
            remaining: limit,
        }
    }

    /// Current counters.
    pub fn stats(&self) -> SearchStats {
        self.engine.stats()
    }

    #[cfg(test)]
    pub(crate) fn test_corpus_energies(&self) -> Vec<f64> {
        self.engine.test_corpus_energies()
    }

    #[cfg(test)]
    pub(crate) fn test_feature_frequency(&self, id: CoverageId) -> u64 {
        self.engine.test_feature_frequency(id)
    }
}

impl<Capture: CoverageCapture> Cautious<Capture> {
    /// Use a real coverage capture backend.
    pub fn with_coverage<NewCapture: CoverageCapture>(
        self,
        capture: NewCapture,
    ) -> Cautious<NewCapture> {
        Cautious {
            engine: self.engine.with_coverage(capture),
        }
    }

    /// Queue a replayable RNG case to run before generated roots.
    pub fn with_case(self, case: Case) -> Self {
        Self {
            engine: self.engine.with_case(case),
        }
    }

    /// Queue replayable RNG cases to run before generated roots.
    pub fn with_cases(self, cases: impl IntoIterator<Item = Case>) -> Self {
        Self {
            engine: self.engine.with_cases(cases),
        }
    }

    /// Set minimization reducer options.
    pub fn with_options(self, options: CautiousOptions) -> Self {
        Self {
            engine: self.engine.with_cautious_options(options),
        }
    }

    /// Set the first seed.
    pub fn with_seed(self, seed: u64) -> Self {
        Self {
            engine: self.engine.with_seed(seed),
        }
    }

    /// Limit the iterator to `limit` cases.
    ///
    /// This mirrors [`Iterator::take`] for serial use and also provides the native Rayon
    /// entrypoint through [`IntoParallelIterator`].
    pub fn take(self, limit: usize) -> Cases<Self> {
        Cases {
            inner: self,
            remaining: limit,
        }
    }

    /// Current counters.
    pub fn stats(&self) -> SearchStats {
        self.engine.stats()
    }

    #[cfg(test)]
    pub(crate) fn test_corpus_energies(&self) -> Vec<f64> {
        self.engine.test_corpus_energies()
    }

    #[cfg(test)]
    pub(crate) fn test_corpus_path_lens(&self) -> Vec<usize> {
        self.engine.test_corpus_path_lens()
    }

    #[cfg(test)]
    pub(crate) fn test_best_path_score(&self) -> Option<(usize, u64, usize)> {
        self.engine.test_best_path_score()
    }

    #[cfg(test)]
    pub(crate) fn test_best_case_cost(&self) -> Option<super::prelude::CaseCost> {
        self.engine.test_best_case_cost()
    }

    #[cfg(test)]
    pub(crate) fn test_best_nonzero_bytes(&self) -> Option<usize> {
        self.engine.test_best_nonzero_bytes()
    }

    #[cfg(test)]
    pub(crate) fn test_best_prefix(&self) -> Option<Vec<u8>> {
        self.engine.test_best_prefix()
    }

    #[cfg(test)]
    pub(crate) fn test_dictionary_values(&self) -> Vec<Vec<u8>> {
        self.engine.test_dictionary_values()
    }

    #[cfg(test)]
    pub(crate) fn test_reducer_feedback(&self) -> (u64, u64, Vec<u16>, bool) {
        self.engine.test_reducer_feedback()
    }
}

impl<G, Capture> Optimizer<G, Capture>
where
    G: Goal,
    Capture: CoverageCapture,
{
    /// Use a real coverage capture backend.
    pub fn with_coverage<NewCapture: CoverageCapture>(
        self,
        capture: NewCapture,
    ) -> Optimizer<G, NewCapture> {
        optimizer_from_engine(self.engine.with_coverage(capture))
    }

    /// Queue a replayable RNG case to run before generated roots.
    pub fn with_case(self, case: Case) -> Self {
        Self {
            engine: self.engine.with_case(case),
            goal: std::marker::PhantomData,
        }
    }

    /// Queue replayable RNG cases to run before generated roots.
    pub fn with_cases(self, cases: impl IntoIterator<Item = Case>) -> Self {
        Self {
            engine: self.engine.with_cases(cases),
            goal: std::marker::PhantomData,
        }
    }

    /// Replace the configured candidate sources.
    pub fn with_mutations(
        self,
        sources: impl IntoIterator<Item = super::optimize::MutationSource>,
    ) -> Self {
        Self {
            engine: self.engine.with_mutation_sources(sources),
            goal: std::marker::PhantomData,
        }
    }

    /// Enable or disable unrelated fresh-root generation.
    pub fn with_fresh_roots(self, enabled: bool) -> Self {
        Self {
            engine: self.engine.with_fresh_roots(enabled),
            goal: std::marker::PhantomData,
        }
    }

    /// Set minimization reducer options.
    pub fn with_options(self, options: CautiousOptions) -> Self {
        Self {
            engine: self.engine.with_cautious_options(options),
            goal: std::marker::PhantomData,
        }
    }

    /// Set the first seed.
    pub fn with_seed(self, seed: u64) -> Self {
        Self {
            engine: self.engine.with_seed(seed),
            goal: std::marker::PhantomData,
        }
    }

    /// Limit the iterator to `limit` cases.
    pub fn take(self, limit: usize) -> Cases<Self> {
        Cases {
            inner: self,
            remaining: limit,
        }
    }

    /// Current counters.
    pub fn stats(&self) -> SearchStats {
        self.engine.stats()
    }
}

/// Bounded case stream returned by [`Curious::take`] or [`Cautious::take`].
pub struct Cases<Search> {
    inner: Search,
    remaining: usize,
}

impl<Capture> Iterator for Cases<Curious<Capture>>
where
    Capture: CoverageCapture,
{
    type Item = CaseRng<Capture>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        self.inner.next()
    }
}

impl<Capture> Iterator for Cases<Cautious<Capture>>
where
    Capture: CoverageCapture,
{
    type Item = CaseRng<Capture>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        self.inner.next()
    }
}

impl<G, Capture> Iterator for Cases<Optimizer<G, Capture>>
where
    G: Goal,
    Capture: CoverageCapture,
{
    type Item = CaseRng<Capture>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        self.inner.next()
    }
}

/// Rayon parallel iterator for a bounded search case stream.
pub struct ParallelCases<Capture: ParallelCoverageCapture = SancovCoverage> {
    shared: Arc<Mutex<State<Capture>>>,
    capture: Capture,
    limit: usize,
}

impl<Capture> IntoParallelIterator for Cases<Curious<Capture>>
where
    Capture: ParallelCoverageCapture,
    Capture::Session: Send,
{
    type Item = CaseRng<Capture>;
    type Iter = ParallelCases<Capture>;

    fn into_par_iter(self) -> Self::Iter {
        into_parallel_cases(self.inner.engine, self.remaining)
    }
}

impl<Capture> IntoParallelIterator for Cases<Cautious<Capture>>
where
    Capture: ParallelCoverageCapture,
    Capture::Session: Send,
{
    type Item = CaseRng<Capture>;
    type Iter = ParallelCases<Capture>;

    fn into_par_iter(self) -> Self::Iter {
        into_parallel_cases(self.inner.engine, self.remaining)
    }
}

impl<G, Capture> IntoParallelIterator for Cases<Optimizer<G, Capture>>
where
    G: Goal,
    Capture: ParallelCoverageCapture,
    Capture::Session: Send,
{
    type Item = CaseRng<Capture>;
    type Iter = ParallelCases<Capture>;

    fn into_par_iter(self) -> Self::Iter {
        into_parallel_cases(self.inner.engine, self.remaining)
    }
}

impl<Capture> ParallelIterator for ParallelCases<Capture>
where
    Capture: ParallelCoverageCapture,
    Capture::Session: Send,
{
    type Item = CaseRng<Capture>;

    fn drive_unindexed<Consumer>(self, consumer: Consumer) -> Consumer::Result
    where
        Consumer: UnindexedConsumer<Self::Item>,
    {
        let shared = self.shared;
        let capture = self.capture;
        (0..self.limit)
            .into_par_iter()
            .filter_map(move |_| {
                let capture = capture.clone();
                next_parallel_rng(&shared, capture)
            })
            .drive_unindexed(consumer)
    }

    fn opt_len(&self) -> Option<usize> {
        None
    }
}

fn into_parallel_cases<Capture>(engine: Engine<Capture>, limit: usize) -> ParallelCases<Capture>
where
    Capture: ParallelCoverageCapture,
    Capture::Session: Send,
{
    let capture = engine.shared.lock().capture.clone();
    capture
        .validate_parallel()
        .expect("coverage backend is not safe for parallel attribution");
    ParallelCases {
        shared: engine.shared,
        capture,
        limit,
    }
}
