use crate::{
    AcceptedCase, CaseFinalizer, CaseMeta, CostModel, CoverageCapture, CoverageEvaluation,
    CoverageId, CoverageSet, DEFAULT_SEED_INTERVAL, ExplorationStats, InputCase, MeasuredCase,
    NoopFinalize, NoopSequenceMutator, PendingCoverageCase, SequenceMutator, UnitCost,
    coverage_delta, is_coverage_interesting,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    rc::Rc,
    thread,
};

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
/// records coverage and schedules mutations from accepted corpus entries.
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

struct CoverageExplorerState<Op, Capture, Cost, Mutate, Finalize> {
    capture: Capture,
    cost: Cost,
    mutate: Mutate,
    finalize: Finalize,
    global: CoverageSet,
    coverage_frequency: BTreeMap<CoverageId, usize>,
    corpus: Vec<AcceptedCase<Op>>,
    pending: VecDeque<PendingCoverageCase<Op>>,
    errors: VecDeque<String>,
    stats: ExplorationStats,
    mutations_per_entry: usize,
    mutation_rounds: usize,
    seed_interval: usize,
    mutated_since_seed: usize,
    roots_exhausted: bool,
    active: bool,
    accepted_limit: Option<usize>,
    next_id: u64,
    next_pending_order: u64,
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
                pending: VecDeque::new(),
                errors: VecDeque::new(),
                stats: ExplorationStats::default(),
                mutations_per_entry: 0,
                mutation_rounds: 0,
                seed_interval: DEFAULT_SEED_INTERVAL,
                mutated_since_seed: 0,
                roots_exhausted: false,
                active: false,
                accepted_limit: None,
                next_id: 0,
                next_pending_order: 0,
            })),
        }
    }
}

impl<Op, I, Capture, Cost, Mutate, Finalize>
    CoverageExplorer<Op, I, Capture, Cost, Mutate, Finalize>
{
    /// Replace the cost model used for accepted-case metadata and mutation priority.
    pub fn cost<NewCost>(self, cost: NewCost) -> CoverageExplorer<Op, I, Capture, NewCost, Mutate, Finalize> {
        let state = match Rc::try_unwrap(self.shared) {
            Ok(state) => state.into_inner(),
            Err(_) => panic!("cannot change explorer cost while cases are alive"),
        };
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
                pending: state.pending,
                errors: state.errors,
                stats: state.stats,
                mutations_per_entry: state.mutations_per_entry,
                mutation_rounds: state.mutation_rounds,
                seed_interval: state.seed_interval,
                mutated_since_seed: state.mutated_since_seed,
                roots_exhausted: state.roots_exhausted,
                active: state.active,
                accepted_limit: state.accepted_limit,
                next_id: state.next_id,
                next_pending_order: state.next_pending_order,
            })),
        }
    }

    /// Add a mutator used to create follow-up candidates from accepted corpus entries.
    pub fn mutate<NewMutate>(
        self,
        mutate: NewMutate,
    ) -> CoverageExplorer<Op, I, Capture, Cost, NewMutate, Finalize> {
        let state = match Rc::try_unwrap(self.shared) {
            Ok(state) => state.into_inner(),
            Err(_) => panic!("cannot change explorer mutator while cases are alive"),
        };
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
                pending: state.pending,
                errors: state.errors,
                stats: state.stats,
                mutations_per_entry: state.mutations_per_entry,
                mutation_rounds: state.mutation_rounds,
                seed_interval: state.seed_interval,
                mutated_since_seed: state.mutated_since_seed,
                roots_exhausted: state.roots_exhausted,
                active: state.active,
                accepted_limit: state.accepted_limit,
                next_id: state.next_id,
                next_pending_order: state.next_pending_order,
            })),
        }
    }

    /// Add a finalizer that normalizes each candidate before it is yielded.
    pub fn finalize<NewFinalize>(
        self,
        finalize: NewFinalize,
    ) -> CoverageExplorer<Op, I, Capture, Cost, Mutate, NewFinalize> {
        let state = match Rc::try_unwrap(self.shared) {
            Ok(state) => state.into_inner(),
            Err(_) => panic!("cannot change explorer finalizer while cases are alive"),
        };
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
                pending: state.pending,
                errors: state.errors,
                stats: state.stats,
                mutations_per_entry: state.mutations_per_entry,
                mutation_rounds: state.mutation_rounds,
                seed_interval: state.seed_interval,
                mutated_since_seed: state.mutated_since_seed,
                roots_exhausted: state.roots_exhausted,
                active: state.active,
                accepted_limit: state.accepted_limit,
                next_id: state.next_id,
                next_pending_order: state.next_pending_order,
            })),
        }
    }

    /// Set the maximum number of mutation candidates enqueued per accepted entry.
    pub fn mutations_per_entry(self, mutations_per_entry: usize) -> Self {
        self.shared.borrow_mut().mutations_per_entry = mutations_per_entry;
        self
    }

    /// Set how many mutation generations to explore from each generated root case.
    pub fn rounds(self, rounds: usize) -> Self {
        self.shared.borrow_mut().mutation_rounds = rounds;
        self
    }

    /// Stop after this many accepted corpus entries.
    pub fn accepted_limit(self, accepted_limit: usize) -> Self {
        self.shared.borrow_mut().accepted_limit = Some(accepted_limit);
        self
    }

    /// Set how many queued mutation candidates may run before trying another root case.
    pub fn seed_interval(self, seed_interval: usize) -> Self {
        self.shared.borrow_mut().seed_interval = seed_interval;
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

impl<Op, Capture, Cost, Mutate, Finalize>
    CoverageExplorerState<Op, Capture, Cost, Mutate, Finalize>
where
    Op: Clone,
    Cost: CostModel<Op>,
    Mutate: SequenceMutator<Op>,
    Finalize: CaseFinalizer<Op>,
{
    fn should_try_root(&self) -> bool {
        !self.roots_exhausted
            && (self.pending.is_empty()
                || (self.seed_interval > 0 && self.mutated_since_seed >= self.seed_interval))
    }

    fn pop_scheduled_pending(&mut self) -> Option<PendingCoverageCase<Op>> {
        let index = self
            .pending
            .iter()
            .enumerate()
            .max_by(|(_, left), (_, right)| {
                left.priority
                    .cmp(&right.priority)
                    .then_with(|| right.order.cmp(&left.order))
            })
            .map(|(index, _)| index)?;
        let pending = self.pending.remove(index)?;
        self.mutated_since_seed = self.mutated_since_seed.saturating_add(1);
        Some(pending)
    }

    fn next_pending_order(&mut self) -> u64 {
        let order = self.next_pending_order;
        self.next_pending_order = self.next_pending_order.wrapping_add(1);
        order
    }

    fn record_coverage_frequency(&mut self, coverage: &CoverageSet) {
        for id in coverage.iter() {
            *self.coverage_frequency.entry(id).or_insert(0) += 1;
        }
    }

    fn rare_coverage_count(&self, case: &AcceptedCase<Op>) -> usize {
        case.coverage
            .iter()
            .filter(|id| self.coverage_frequency.get(id).copied().unwrap_or(0) <= 1)
            .count()
    }

    fn mutation_energy(&self, case: &AcceptedCase<Op>) -> usize {
        if self.mutations_per_entry == 0 || case.depth >= self.mutation_rounds {
            return 0;
        }

        let mut energy = 1usize;
        let extra_unique = case.unique_coverage.len();
        let remaining = self.mutations_per_entry.saturating_sub(energy);
        energy += extra_unique.min(remaining);

        if self.rare_coverage_count(case) > 0 && energy < self.mutations_per_entry {
            energy += 1;
        }

        energy
    }

    fn mutation_priority(&self, case: &AcceptedCase<Op>) -> u64 {
        let rarity_score = case
            .coverage
            .iter()
            .map(|id| {
                let hits = self
                    .coverage_frequency
                    .get(&id)
                    .copied()
                    .unwrap_or(1)
                    .max(1) as u64;
                1024 / hits.min(1024)
            })
            .sum::<u64>();
        let unique_score = case.unique_coverage.len() as u64 * 4096;
        let failure_score = if case.is_failure() { 1 << 30 } else { 0 };
        let size_penalty = (case.cost / 16)
            .saturating_add(case.len as u64 / 8)
            .min(8192);
        let depth_penalty = case.depth as u64 * 256;

        1 + failure_score
            + unique_score
            + rarity_score.saturating_sub(size_penalty.saturating_add(depth_penalty))
    }

    fn enqueue_mutations(&mut self, case: &AcceptedCase<Op>) {
        let energy = self.mutation_energy(case);
        if energy == 0 {
            return;
        }

        let mut candidates = Vec::new();
        self.mutate.mutate(&case.ops, &mut |candidate| {
            if candidates.len() < energy {
                candidates.push(candidate);
            }
        });

        let priority = self.mutation_priority(case);
        for mut ops in candidates {
            self.finalize.finalize(&mut ops);
            let order = self.next_pending_order();
            self.pending.push_back(PendingCoverageCase {
                case: InputCase {
                    seed: None,
                    parent: Some(case.id),
                    depth: case.depth + 1,
                    ops,
                },
                priority,
                order,
            });
            self.stats.mutated += 1;
        }
    }

    fn accept_case(&mut self, case: InputCase<Op>, evaluation: CoverageEvaluation) {
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
        self.record_coverage_frequency(&evaluation.coverage);

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
        self.enqueue_mutations(&accepted);
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

        let pending = if state.should_try_root() {
            match self.inner.next() {
                Some(mut case) => {
                    state.finalize.finalize(&mut case.ops);
                    state.stats.generated += 1;
                    state.mutated_since_seed = 0;
                    Some(PendingCoverageCase {
                        case,
                        priority: u64::MAX,
                        order: 0,
                    })
                }
                None => {
                    state.roots_exhausted = true;
                    state.pop_scheduled_pending()
                }
            }
        } else {
            match state.pop_scheduled_pending() {
                Some(pending) => Some(pending),
                None => {
                    let mut case = self.inner.next()?;
                    state.finalize.finalize(&mut case.ops);
                    state.stats.generated += 1;
                    state.mutated_since_seed = 0;
                    Some(PendingCoverageCase {
                        case,
                        priority: u64::MAX,
                        order: 0,
                    })
                }
            }
        }?;

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
            case: Some(pending.case),
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
