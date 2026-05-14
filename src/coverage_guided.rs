use crate::{
    AcceptedCase, CaseFinalizer, CaseMeta, CostModel, CoverageCapture, CoverageEvaluation,
    CoverageId, CoverageSet, ExplorationStats, InputCase, MeasuredCase, NoopFinalize,
    NoopSequenceMutator, SequenceMutator, UnitCost, coverage_delta, is_coverage_interesting,
};
use rand::{Rng, SeedableRng, rngs::SmallRng};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    rc::Rc,
    thread,
    time::Duration,
};

/// Default mutations stacked per generated candidate, matching libFuzzer's `-mutate_depth=5`.
pub const DEFAULT_MUTATE_DEPTH: usize = 5;

/// Default ratio of "pull a fresh root" calls to "mutate an accepted case" calls while roots
/// remain. `8` means roughly one root every eight `next()` calls — once roots are exhausted
/// the explorer mutates corpus entries indefinitely.
pub const DEFAULT_SEED_RATIO: usize = 8;

/// Iterator that keeps measured cases that fail or add new coverage.
pub struct CoverageMaximize<I, Cost = UnitCost> {
    inner: I,
    cost: Cost,
    global: CoverageSet,
    stats: ExplorationStats,
    next_id: u64,
}

impl<I> CoverageMaximize<I, UnitCost> {
    fn new(inner: I) -> Self {
        Self {
            inner,
            cost: UnitCost,
            global: CoverageSet::new(),
            stats: ExplorationStats::default(),
            next_id: 0,
        }
    }
}

impl<I, Cost> CoverageMaximize<I, Cost> {
    /// Replace the cost model used for accepted-case metadata.
    pub fn cost<NewCost>(self, cost: NewCost) -> CoverageMaximize<I, NewCost> {
        CoverageMaximize {
            inner: self.inner,
            cost,
            global: self.global,
            stats: self.stats,
            next_id: self.next_id,
        }
    }

    /// Current aggregate exploration counters.
    pub fn stats(&self) -> ExplorationStats {
        self.stats
    }

    /// Coverage accumulated by accepted entries.
    pub fn global_coverage(&self) -> &CoverageSet {
        &self.global
    }
}

impl<I, Op, Cost> Iterator for CoverageMaximize<I, Cost>
where
    Op: Clone,
    I: Iterator<Item = Result<MeasuredCase<Op>, String>>,
    Cost: CostModel<Op>,
{
    type Item = Result<AcceptedCase<Op>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let measured = match self.inner.next()? {
                Ok(measured) => measured,
                Err(error) => {
                    self.stats.executed += 1;
                    self.stats.errors += 1;
                    return Some(Err(error));
                }
            };
            self.stats.executed += 1;
            if !is_coverage_interesting(
                &self.global,
                &measured.evaluation.coverage,
                measured.evaluation.is_failure(),
            ) {
                continue;
            }

            let unique_coverage = coverage_delta(&self.global, &measured.evaluation.coverage);
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            self.global.extend(measured.evaluation.coverage.iter());
            self.stats.accepted += 1;
            if measured.evaluation.is_failure() {
                self.stats.failures += 1;
            }
            self.stats.coverage_ids = self.global.len() as u64;

            let cost = self.cost.total_cost(&measured.case.ops);
            let len = measured.case.ops.len();
            let accepted = AcceptedCase {
                id,
                seed: measured.case.seed,
                parent: measured.case.parent,
                depth: measured.case.depth,
                ops: measured.case.ops,
                coverage: measured.evaluation.coverage,
                unique_coverage,
                outcome: measured.evaluation.outcome,
                cost,
                len,
            };
            return Some(Ok(accepted));
        }
    }
}

/// Iterator adapters for fallible measured coverage cases.
pub trait MeasuredCaseIteratorExt<Op>:
    Iterator<Item = Result<MeasuredCase<Op>, String>> + Sized
{
    /// Keep only cases that fail or add coverage not yet seen by this iterator.
    fn maximize_coverage(self) -> CoverageMaximize<Self> {
        CoverageMaximize::new(self)
    }
}

impl<I, Op> MeasuredCaseIteratorExt<Op> for I where
    I: Iterator<Item = Result<MeasuredCase<Op>, String>>
{
}

/// Guard-based coverage explorer. It yields runnable cases; finishing or dropping each case
/// records coverage and may add the case to the corpus if it tripped new coverage.
///
/// Scheduling follows the same shape as libFuzzer's Entropic mode:
///
/// - While the inner seed iterator still yields cases, the explorer pulls a fresh root every
///   `seed_ratio` calls and otherwise samples a corpus entry weighted by Entropic energy.
/// - Once roots are exhausted the explorer keeps mutating corpus entries until
///   `accepted_limit` is reached (or forever if no limit is set).
/// - Each mutation candidate is the result of `mutate_depth` stacked mutator calls, picked
///   one-per-step uniformly from the mutator's emit stream.
pub struct CoverageExplorer<
    Op,
    I,
    Capture,
    Cost = UnitCost,
    Mutate = NoopSequenceMutator,
    Finalize = NoopFinalize,
> {
    inner: I,
    shared: Rc<RefCell<CoverageExplorerState<Op, Capture, Cost, Mutate, Finalize>>>,
}

/// Breakdown of where wall time goes inside the explorer. Useful for benchmarking the
/// scheduler in isolation from harness replay cost.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExplorerTiming {
    pub corpus_pick: Duration,
    pub mutation_gen: Duration,
    pub finalize: Duration,
    pub accept: Duration,
    pub capture_start: Duration,
}

struct CoverageExplorerState<Op, Capture, Cost, Mutate, Finalize> {
    capture: Capture,
    cost: Cost,
    mutate: Mutate,
    finalize: Finalize,
    global: CoverageSet,
    coverage_frequency: BTreeMap<CoverageId, u64>,
    corpus: Vec<AcceptedCase<Op>>,
    errors: VecDeque<String>,
    stats: ExplorationStats,
    timing: ExplorerTiming,
    mutate_depth: usize,
    seed_ratio: usize,
    seed_step: u64,
    roots_exhausted: bool,
    active: bool,
    accepted_limit: Option<usize>,
    next_id: u64,
    rng: SmallRng,
}

impl<Op, I, Capture> CoverageExplorer<Op, I, Capture>
where
    Capture: CoverageCapture,
{
    pub(crate) fn new(inner: I, capture: Capture) -> Self {
        Self {
            inner,
            shared: Rc::new(RefCell::new(CoverageExplorerState {
                capture,
                cost: UnitCost,
                mutate: NoopSequenceMutator,
                finalize: NoopFinalize,
                global: CoverageSet::new(),
                coverage_frequency: BTreeMap::new(),
                corpus: Vec::new(),
                errors: VecDeque::new(),
                stats: ExplorationStats::default(),
                timing: ExplorerTiming::default(),
                mutate_depth: DEFAULT_MUTATE_DEPTH,
                seed_ratio: DEFAULT_SEED_RATIO,
                seed_step: 0,
                roots_exhausted: false,
                active: false,
                accepted_limit: None,
                next_id: 0,
                rng: SmallRng::seed_from_u64(0x1F1E33),
            })),
        }
    }
}

impl<Op, I, Capture, Cost, Mutate, Finalize>
    CoverageExplorer<Op, I, Capture, Cost, Mutate, Finalize>
{
    /// Replace the cost model used for accepted-case metadata.
    pub fn cost<NewCost>(
        self,
        cost: NewCost,
    ) -> CoverageExplorer<Op, I, Capture, NewCost, Mutate, Finalize> {
        let state = unwrap_state(self.shared);
        CoverageExplorer {
            inner: self.inner,
            shared: Rc::new(RefCell::new(CoverageExplorerState {
                capture: state.capture,
                cost,
                mutate: state.mutate,
                finalize: state.finalize,
                global: state.global,
                coverage_frequency: state.coverage_frequency,
                corpus: state.corpus,
                errors: state.errors,
                stats: state.stats,
                mutate_depth: state.mutate_depth,
                seed_ratio: state.seed_ratio,
                seed_step: state.seed_step,
                roots_exhausted: state.roots_exhausted,
                active: state.active,
                accepted_limit: state.accepted_limit,
                next_id: state.next_id,
                rng: state.rng,
            })),
        }
    }

    /// Add a mutator used to create follow-up candidates from accepted corpus entries.
    pub fn mutate<NewMutate>(
        self,
        mutate: NewMutate,
    ) -> CoverageExplorer<Op, I, Capture, Cost, NewMutate, Finalize> {
        let state = unwrap_state(self.shared);
        CoverageExplorer {
            inner: self.inner,
            shared: Rc::new(RefCell::new(CoverageExplorerState {
                capture: state.capture,
                cost: state.cost,
                mutate,
                finalize: state.finalize,
                global: state.global,
                coverage_frequency: state.coverage_frequency,
                corpus: state.corpus,
                errors: state.errors,
                stats: state.stats,
                mutate_depth: state.mutate_depth,
                seed_ratio: state.seed_ratio,
                seed_step: state.seed_step,
                roots_exhausted: state.roots_exhausted,
                active: state.active,
                accepted_limit: state.accepted_limit,
                next_id: state.next_id,
                rng: state.rng,
            })),
        }
    }

    /// Add a finalizer that normalizes each candidate before it is yielded.
    pub fn finalize<NewFinalize>(
        self,
        finalize: NewFinalize,
    ) -> CoverageExplorer<Op, I, Capture, Cost, Mutate, NewFinalize> {
        let state = unwrap_state(self.shared);
        CoverageExplorer {
            inner: self.inner,
            shared: Rc::new(RefCell::new(CoverageExplorerState {
                capture: state.capture,
                cost: state.cost,
                mutate: state.mutate,
                finalize,
                global: state.global,
                coverage_frequency: state.coverage_frequency,
                corpus: state.corpus,
                errors: state.errors,
                stats: state.stats,
                mutate_depth: state.mutate_depth,
                seed_ratio: state.seed_ratio,
                seed_step: state.seed_step,
                roots_exhausted: state.roots_exhausted,
                active: state.active,
                accepted_limit: state.accepted_limit,
                next_id: state.next_id,
                rng: state.rng,
            })),
        }
    }

    /// Set how many mutator calls are stacked per generated candidate (libFuzzer-style
    /// `-mutate_depth`). A depth of `1` matches a single deterministic neighbourhood pick;
    /// the default of [`DEFAULT_MUTATE_DEPTH`] (5) matches libFuzzer.
    pub fn mutate_depth(self, mutate_depth: usize) -> Self {
        self.shared.borrow_mut().mutate_depth = mutate_depth.max(1);
        self
    }

    /// Set how often the explorer pulls a fresh root from the inner iterator while roots
    /// remain. A ratio of `N` means roughly one root every `N` calls; once the inner
    /// iterator is exhausted the explorer mutates corpus entries indefinitely.
    pub fn seed_ratio(self, seed_ratio: usize) -> Self {
        self.shared.borrow_mut().seed_ratio = seed_ratio.max(1);
        self
    }

    /// Seed the deterministic RNG that drives corpus selection and stacked mutation.
    pub fn rng_seed(self, seed: u64) -> Self {
        self.shared.borrow_mut().rng = SmallRng::seed_from_u64(seed);
        self
    }

    /// Stop after this many accepted corpus entries. With no limit set the explorer runs
    /// indefinitely (libFuzzer parity); callers are expected to break externally.
    pub fn accepted_limit(self, accepted_limit: usize) -> Self {
        self.shared.borrow_mut().accepted_limit = Some(accepted_limit);
        self
    }

    /// Current aggregate exploration counters.
    pub fn stats(&self) -> ExplorationStats {
        self.shared.borrow().stats
    }

    /// Coverage accumulated by accepted entries.
    pub fn global_coverage(&self) -> CoverageSet {
        self.shared.borrow().global.clone()
    }

    /// Accepted corpus entries yielded so far.
    pub fn corpus(&self) -> Vec<AcceptedCase<Op>>
    where
        Op: Clone,
    {
        self.shared.borrow().corpus.clone()
    }
}

fn unwrap_state<S>(shared: Rc<RefCell<S>>) -> S {
    match Rc::try_unwrap(shared) {
        Ok(state) => state.into_inner(),
        Err(_) => panic!("cannot reconfigure explorer while cases are alive"),
    }
}

impl<Op, Capture, Cost, Mutate, Finalize>
    CoverageExplorerState<Op, Capture, Cost, Mutate, Finalize>
where
    Op: Clone,
    Cost: CostModel<Op>,
    Mutate: SequenceMutator<Op>,
    Finalize: CaseFinalizer<Op>,
{
    fn record_coverage_frequency(&mut self, coverage: &CoverageSet) {
        for id in coverage.iter() {
            *self.coverage_frequency.entry(id).or_insert(0) += 1;
        }
    }

    /// Entropic-style energy. For each feature `f` in the case's coverage, we add
    /// `ln(executions / freq[f])` — a feature seen in 1/100 of executed cases contributes
    /// more than a feature seen in 9/10. New cases with rich `unique_coverage` therefore
    /// dominate the weighted sample until their features are seen elsewhere and `freq` rises.
    fn case_energy(&self, case: &AcceptedCase<Op>) -> f64 {
        let executions = self.stats.executed.max(1) as f64;
        let mut energy = 0.0;
        for id in case.coverage.iter() {
            let freq = (*self.coverage_frequency.get(&id).unwrap_or(&1)).max(1) as f64;
            energy += (executions / freq).ln().max(0.0);
        }
        if case.is_failure() {
            energy += 16.0;
        }
        energy.max(1.0)
    }

    fn weighted_corpus_index(&mut self) -> Option<usize> {
        if self.corpus.is_empty() {
            return None;
        }
        let weights: Vec<f64> = self
            .corpus
            .iter()
            .map(|case| self.case_energy(case))
            .collect();
        let total: f64 = weights.iter().sum();
        if !total.is_finite() || total <= 0.0 {
            let len = self.corpus.len();
            return Some(self.rng.random_range(0..len));
        }
        let mut roll = self.rng.random::<f64>() * total;
        for (index, weight) in weights.iter().enumerate() {
            roll -= weight;
            if roll <= 0.0 {
                return Some(index);
            }
        }
        Some(weights.len() - 1)
    }

    fn sample_mutation(&mut self) -> Option<InputCase<Op>> {
        let index = self.weighted_corpus_index()?;
        let (parent_id, parent_depth, mut ops) = {
            let parent = &self.corpus[index];
            (parent.id, parent.depth, parent.ops.clone())
        };
        let depth = self.mutate_depth.max(1);
        // Split-borrow `mutate` and `rng` so the reservoir-sampling closure can call
        // back into the rng while the mutator is borrowed mutably.
        let mutate = &mut self.mutate;
        let rng = &mut self.rng;
        for _ in 0..depth {
            let mut chosen: Option<Vec<Op>> = None;
            let mut count: u64 = 0;
            mutate.mutate(&ops, &mut |candidate| {
                count = count.saturating_add(1);
                if rng.random_range(0..count) == 0 {
                    chosen = Some(candidate);
                }
            });
            if let Some(c) = chosen {
                ops = c;
            }
        }
        self.finalize.finalize(&mut ops);
        self.stats.mutated += 1;
        Some(InputCase {
            seed: None,
            parent: Some(parent_id),
            depth: parent_depth.saturating_add(1),
            ops,
        })
    }

    fn accept_case(&mut self, case: InputCase<Op>, evaluation: CoverageEvaluation) {
        // Frequency tracks how often each feature has been hit across all executions, not
        // just accepts — Entropic energy needs the global hit rate so common features get
        // their weight diluted as the run progresses.
        self.record_coverage_frequency(&evaluation.coverage);

        if !is_coverage_interesting(&self.global, &evaluation.coverage, evaluation.is_failure()) {
            return;
        }

        let unique_coverage = coverage_delta(&self.global, &evaluation.coverage);
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.global.extend(evaluation.coverage.iter());
        self.stats.accepted += 1;
        if evaluation.is_failure() {
            self.stats.failures += 1;
        }
        self.stats.coverage_ids = self.global.len() as u64;

        let cost = self.cost.total_cost(&case.ops);
        let len = case.ops.len();
        let accepted = AcceptedCase {
            id,
            seed: case.seed,
            parent: case.parent,
            depth: case.depth,
            ops: case.ops,
            coverage: evaluation.coverage,
            unique_coverage,
            outcome: evaluation.outcome,
            cost,
            len,
        };
        self.corpus.push(accepted);
    }
}

impl<Op, I, Capture, Cost, Mutate, Finalize> Iterator
    for CoverageExplorer<Op, I, Capture, Cost, Mutate, Finalize>
where
    Op: Clone,
    I: Iterator<Item = InputCase<Op>>,
    Capture: CoverageCapture,
    Cost: CostModel<Op>,
    Mutate: SequenceMutator<Op>,
    Finalize: CaseFinalizer<Op>,
{
    type Item = Result<Case<Op, Capture, Cost, Mutate, Finalize>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut state = self.shared.borrow_mut();
        if let Some(error) = state.errors.pop_front() {
            return Some(Err(error));
        }
        if state.active {
            state.stats.errors += 1;
            return Some(Err(
                "cannot start another coverage case while the previous case is alive".to_string(),
            ));
        }
        if state
            .accepted_limit
            .is_some_and(|limit| state.stats.accepted as usize >= limit)
        {
            return None;
        }

        let pull_root = if state.roots_exhausted {
            false
        } else if state.corpus.is_empty() {
            true
        } else {
            state.seed_step = state.seed_step.wrapping_add(1);
            state.seed_step % state.seed_ratio.max(1) as u64 == 0
        };

        let case = if pull_root {
            match self.inner.next() {
                Some(mut case) => {
                    state.finalize.finalize(&mut case.ops);
                    state.stats.generated += 1;
                    case
                }
                None => {
                    state.roots_exhausted = true;
                    match state.sample_mutation() {
                        Some(case) => case,
                        None => return None,
                    }
                }
            }
        } else {
            match state.sample_mutation() {
                Some(case) => case,
                None => return None,
            }
        };

        let token = match state.capture.start_capture() {
            Ok(token) => token,
            Err(error) => {
                state.stats.errors += 1;
                return Some(Err(error));
            }
        };
        state.active = true;
        drop(state);

        Some(Ok(Case {
            shared: Rc::clone(&self.shared),
            case: Some(case),
            token: Some(token),
            outcome: None,
            finished: false,
        }))
    }
}

/// Active runnable coverage case. Dropping it records coverage; use [`Case::finish`] to receive
/// capture errors immediately.
pub struct Case<Op, Capture, Cost = UnitCost, Mutate = NoopSequenceMutator, Finalize = NoopFinalize>
where
    Op: Clone,
    Capture: CoverageCapture,
    Cost: CostModel<Op>,
    Mutate: SequenceMutator<Op>,
    Finalize: CaseFinalizer<Op>,
{
    shared: Rc<RefCell<CoverageExplorerState<Op, Capture, Cost, Mutate, Finalize>>>,
    case: Option<InputCase<Op>>,
    token: Option<Capture::Token>,
    outcome: Option<Result<(), String>>,
    finished: bool,
}

impl<Op, Capture, Cost, Mutate, Finalize> Case<Op, Capture, Cost, Mutate, Finalize>
where
    Op: Clone,
    Capture: CoverageCapture,
    Cost: CostModel<Op>,
    Mutate: SequenceMutator<Op>,
    Finalize: CaseFinalizer<Op>,
{
    /// Operation list to replay.
    pub fn ops(&self) -> &[Op] {
        &self
            .case
            .as_ref()
            .expect("case already finished")
            .ops
    }

    /// Source metadata for this case.
    pub fn meta(&self) -> CaseMeta {
        let case = self.case.as_ref().expect("case already finished");
        CaseMeta {
            seed: case.seed,
            parent: case.parent,
            depth: case.depth,
        }
    }

    /// Record an explicit pass/fail outcome.
    pub fn set_outcome(&mut self, outcome: Result<(), String>) {
        self.outcome = Some(outcome);
    }

    /// Mark this case as failing.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.outcome = Some(Err(error.into()));
    }

    /// Run a replay closure against this case and record its outcome.
    pub fn run<F>(&mut self, run: F) -> Result<(), String>
    where
        F: FnOnce(&[Op]) -> Result<(), String>,
    {
        let outcome = run(self.ops());
        self.outcome = Some(outcome.clone());
        outcome
    }

    /// Finish capture now and return any capture/export error.
    pub fn finish(mut self) -> Result<(), String> {
        self.finish_inner()
    }

    fn finish_inner(&mut self) -> Result<(), String> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        let case = self.case.take().expect("case already finished");
        let token = self.token.take().expect("case already finished");
        let outcome = self.outcome.take().unwrap_or_else(|| {
            if thread::panicking() {
                Err("panic while running coverage case".to_string())
            } else {
                Ok(())
            }
        });

        let mut state = self.shared.borrow_mut();
        state.active = false;
        state.stats.executed += 1;
        match state.capture.finish_capture(token, outcome) {
            Ok(evaluation) => {
                state.accept_case(case, evaluation);
                Ok(())
            }
            Err(error) => {
                state.stats.errors += 1;
                Err(error)
            }
        }
    }
}

impl<Op, Capture, Cost, Mutate, Finalize> Drop for Case<Op, Capture, Cost, Mutate, Finalize>
where
    Op: Clone,
    Capture: CoverageCapture,
    Cost: CostModel<Op>,
    Mutate: SequenceMutator<Op>,
    Finalize: CaseFinalizer<Op>,
{
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let case = match self.case.take() {
            Some(case) => case,
            None => return,
        };
        let token = match self.token.take() {
            Some(token) => token,
            None => return,
        };
        let outcome = self.outcome.take().unwrap_or_else(|| {
            if thread::panicking() {
                Err("panic while running coverage case".to_string())
            } else {
                Ok(())
            }
        });

        let mut state = self.shared.borrow_mut();
        state.active = false;
        state.stats.executed += 1;
        match state.capture.finish_capture(token, outcome) {
            Ok(evaluation) => {
                state.accept_case(case, evaluation);
            }
            Err(error) => {
                state.stats.errors += 1;
                state.errors.push_back(error);
            }
        }
    }
}
