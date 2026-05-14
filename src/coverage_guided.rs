
/// Iterator that yields only cases that expand coverage or fail.
pub struct CoverageGuided<Op, I, Evaluate, Cost, Mutate, Shrink, Finalize> {
    inner: I,
    evaluate: Evaluate,
    cost: Cost,
    mutate: Mutate,
    shrink: Shrink,
    finalize: Finalize,
    global: CoverageSet,
    coverage_frequency: BTreeMap<CoverageId, usize>,
    corpus: Vec<CoveredCase<Op>>,
    initial_cases: VecDeque<Vec<Op>>,
    pending: VecDeque<PendingCoverageCase<Op>>,
    stats: ExplorationStats,
    mutations_per_entry: usize,
    mutation_rounds: usize,
    max_shrink_steps: usize,
    seed_interval: usize,
    mutated_since_seed: usize,
    seeds_exhausted: bool,
    next_id: u64,
    next_pending_order: u64,
}

impl<Op, I, Evaluate>
    CoverageGuided<
        Op,
        I,
        Evaluate,
        UnitCost,
        NoopSequenceMutator,
        NoopSequenceMutator,
        NoopFinalize,
    >
{
    /// Create a coverage-guided iterator from generated cases and an evaluator.
    pub fn new(inner: I, evaluate: Evaluate) -> Self {
        Self {
            inner,
            evaluate,
            cost: UnitCost,
            mutate: NoopSequenceMutator,
            shrink: NoopSequenceMutator,
            finalize: NoopFinalize,
            global: CoverageSet::new(),
            coverage_frequency: BTreeMap::new(),
            corpus: Vec::new(),
            initial_cases: VecDeque::new(),
            pending: VecDeque::new(),
            stats: ExplorationStats::default(),
            mutations_per_entry: 0,
            mutation_rounds: 0,
            max_shrink_steps: 64,
            seed_interval: DEFAULT_SEED_INTERVAL,
            mutated_since_seed: 0,
            seeds_exhausted: false,
            next_id: 0,
            next_pending_order: 0,
        }
    }
}

impl<Op, I, Evaluate, Cost, Mutate, Shrink, Finalize>
    CoverageGuided<Op, I, Evaluate, Cost, Mutate, Shrink, Finalize>
{
    /// Replace the cost model used for shrinking and accepted-case metadata.
    pub fn cost<NewCost>(
        self,
        cost: NewCost,
    ) -> CoverageGuided<Op, I, Evaluate, NewCost, Mutate, Shrink, Finalize> {
        CoverageGuided {
            inner: self.inner,
            evaluate: self.evaluate,
            cost,
            mutate: self.mutate,
            shrink: self.shrink,
            finalize: self.finalize,
            global: self.global,
            coverage_frequency: self.coverage_frequency,
            corpus: self.corpus,
            initial_cases: self.initial_cases,
            pending: self.pending,
            stats: self.stats,
            mutations_per_entry: self.mutations_per_entry,
            mutation_rounds: self.mutation_rounds,
            max_shrink_steps: self.max_shrink_steps,
            seed_interval: self.seed_interval,
            mutated_since_seed: self.mutated_since_seed,
            seeds_exhausted: self.seeds_exhausted,
            next_id: self.next_id,
            next_pending_order: self.next_pending_order,
        }
    }

    /// Add a mutator used to create follow-up candidates from accepted corpus entries.
    pub fn mutate<NewMutate>(
        self,
        mutate: NewMutate,
    ) -> CoverageGuided<Op, I, Evaluate, Cost, NewMutate, Shrink, Finalize> {
        CoverageGuided {
            inner: self.inner,
            evaluate: self.evaluate,
            cost: self.cost,
            mutate,
            shrink: self.shrink,
            finalize: self.finalize,
            global: self.global,
            coverage_frequency: self.coverage_frequency,
            corpus: self.corpus,
            initial_cases: self.initial_cases,
            pending: self.pending,
            stats: self.stats,
            mutations_per_entry: self.mutations_per_entry,
            mutation_rounds: self.mutation_rounds,
            max_shrink_steps: self.max_shrink_steps,
            seed_interval: self.seed_interval,
            mutated_since_seed: self.mutated_since_seed,
            seeds_exhausted: self.seeds_exhausted,
            next_id: self.next_id,
            next_pending_order: self.next_pending_order,
        }
    }

    /// Add a domain-aware shrinker tried after the built-in deletion pass.
    pub fn shrink<NewShrink>(
        self,
        shrink: NewShrink,
    ) -> CoverageGuided<Op, I, Evaluate, Cost, Mutate, NewShrink, Finalize> {
        CoverageGuided {
            inner: self.inner,
            evaluate: self.evaluate,
            cost: self.cost,
            mutate: self.mutate,
            shrink,
            finalize: self.finalize,
            global: self.global,
            coverage_frequency: self.coverage_frequency,
            corpus: self.corpus,
            initial_cases: self.initial_cases,
            pending: self.pending,
            stats: self.stats,
            mutations_per_entry: self.mutations_per_entry,
            mutation_rounds: self.mutation_rounds,
            max_shrink_steps: self.max_shrink_steps,
            seed_interval: self.seed_interval,
            mutated_since_seed: self.mutated_since_seed,
            seeds_exhausted: self.seeds_exhausted,
            next_id: self.next_id,
            next_pending_order: self.next_pending_order,
        }
    }

    /// Add a finalizer that normalizes each candidate before evaluation.
    pub fn finalize<NewFinalize>(
        self,
        finalize: NewFinalize,
    ) -> CoverageGuided<Op, I, Evaluate, Cost, Mutate, Shrink, NewFinalize> {
        CoverageGuided {
            inner: self.inner,
            evaluate: self.evaluate,
            cost: self.cost,
            mutate: self.mutate,
            shrink: self.shrink,
            finalize,
            global: self.global,
            coverage_frequency: self.coverage_frequency,
            corpus: self.corpus,
            initial_cases: self.initial_cases,
            pending: self.pending,
            stats: self.stats,
            mutations_per_entry: self.mutations_per_entry,
            mutation_rounds: self.mutation_rounds,
            max_shrink_steps: self.max_shrink_steps,
            seed_interval: self.seed_interval,
            mutated_since_seed: self.mutated_since_seed,
            seeds_exhausted: self.seeds_exhausted,
            next_id: self.next_id,
            next_pending_order: self.next_pending_order,
        }
    }

    /// Set the maximum number of mutation candidates enqueued per accepted entry.
    pub fn mutations_per_entry(mut self, mutations_per_entry: usize) -> Self {
        self.mutations_per_entry = mutations_per_entry;
        self
    }

    /// Set how many mutation generations to explore from each generated seed case.
    pub fn rounds(mut self, rounds: usize) -> Self {
        self.mutation_rounds = rounds;
        self
    }

    /// Set the maximum accepted shrink steps per interesting case.
    pub fn max_shrink_steps(mut self, max_shrink_steps: usize) -> Self {
        self.max_shrink_steps = max_shrink_steps;
        self
    }

    /// Add exact root cases to evaluate before generated seed cases.
    ///
    /// These cases are useful for domain-specific coverage targets that random generation is
    /// unlikely to assemble in a small number of steps. They are finalized, evaluated, shrunk, and
    /// accepted or rejected with the same rules as generated root cases. Accepted entries have no
    /// random seed and no parent.
    pub fn initial_cases<Cases>(mut self, cases: Cases) -> Self
    where
        Cases: IntoIterator<Item = Vec<Op>>,
    {
        self.initial_cases.extend(cases);
        self
    }

    /// Set how many queued mutation candidates may run before trying another fresh seed.
    ///
    /// The default is `1`, which alternates fresh seed exploration with corpus mutation when both
    /// are available. Set this to `0` to drain scheduled mutation candidates before asking the
    /// seed iterator for more cases.
    pub fn seed_interval(mut self, seed_interval: usize) -> Self {
        self.seed_interval = seed_interval;
        self
    }

    /// Current aggregate exploration counters.
    pub fn stats(&self) -> ExplorationStats {
        self.stats
    }

    /// Coverage accumulated by accepted entries.
    pub fn global_coverage(&self) -> &CoverageSet {
        &self.global
    }

    /// Accepted corpus entries yielded so far.
    pub fn corpus(&self) -> &[CoveredCase<Op>] {
        &self.corpus
    }
}

impl<Op, I, Evaluate, Cost, Mutate, Shrink, Finalize>
    CoverageGuided<Op, I, Evaluate, Cost, Mutate, Shrink, Finalize>
where
    Op: Clone,
    Evaluate: CaseEvaluator<Op>,
    Cost: CostModel<Op>,
    Mutate: SequenceMutator<Op>,
    Shrink: SequenceMutator<Op>,
    Finalize: CaseFinalizer<Op>,
{
    fn shrink_interesting(
        &mut self,
        mut ops: Vec<Op>,
        mut evaluation: CoverageEvaluation,
        required_coverage: &CoverageSet,
    ) -> (Vec<Op>, CoverageEvaluation) {
        let must_fail = evaluation.is_failure();
        let mut best_score = score(&ops, &self.cost);
        let mut accepted_steps = 0usize;

        while accepted_steps < self.max_shrink_steps {
            let mut candidates = Vec::new();
            emit_deletion_candidates(&ops, &mut |candidate| candidates.push(candidate));
            self.shrink
                .mutate(&ops, &mut |candidate| candidates.push(candidate));

            let mut accepted = None;
            for mut candidate in candidates {
                self.finalize.finalize(&mut candidate);
                let candidate_score = score(&candidate, &self.cost);
                if candidate_score >= best_score {
                    continue;
                }

                let candidate_evaluation = self.evaluate.evaluate(&candidate);
                self.stats.executed += 1;
                if must_fail && !candidate_evaluation.is_failure() {
                    continue;
                }
                if !candidate_evaluation.coverage.is_superset(required_coverage) {
                    continue;
                }

                accepted = Some((candidate, candidate_evaluation, candidate_score));
                break;
            }

            let Some((candidate, candidate_evaluation, candidate_score)) = accepted else {
                break;
            };
            ops = candidate;
            evaluation = candidate_evaluation;
            best_score = candidate_score;
            accepted_steps += 1;
        }

        (ops, evaluation)
    }

    fn rare_coverage_count(&self, case: &CoveredCase<Op>) -> usize {
        case.coverage
            .iter()
            .filter(|id| self.coverage_frequency.get(id).copied().unwrap_or(0) <= 1)
            .count()
    }

    fn mutation_energy(&self, case: &CoveredCase<Op>) -> usize {
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

    fn mutation_priority(&self, case: &CoveredCase<Op>) -> u64 {
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

    fn next_pending_order(&mut self) -> u64 {
        let order = self.next_pending_order;
        self.next_pending_order = self.next_pending_order.wrapping_add(1);
        order
    }

    fn enqueue_mutations(&mut self, case: &CoveredCase<Op>) {
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
                ops,
                seed: None,
                parent: Some(case.id),
                depth: case.depth + 1,
                priority,
                order,
            });
            self.stats.mutated += 1;
        }
    }

    fn pop_initial_case(&mut self) -> Option<PendingCoverageCase<Op>> {
        let mut ops = self.initial_cases.pop_front()?;
        self.finalize.finalize(&mut ops);
        self.stats.generated += 1;
        self.mutated_since_seed = 0;
        Some(PendingCoverageCase {
            ops,
            seed: None,
            parent: None,
            depth: 0,
            priority: u64::MAX,
            order: 0,
        })
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

    fn should_try_seed(&self) -> bool {
        !self.seeds_exhausted
            && (self.pending.is_empty()
                || (self.seed_interval > 0 && self.mutated_since_seed >= self.seed_interval))
    }

    fn record_coverage_frequency(&mut self, coverage: &CoverageSet) {
        for id in coverage.iter() {
            *self.coverage_frequency.entry(id).or_insert(0) += 1;
        }
    }
}

impl<Op, Dist, I, Evaluate, Cost, Mutate, Shrink, Finalize> Iterator
    for CoverageGuided<Op, I, Evaluate, Cost, Mutate, Shrink, Finalize>
where
    Op: Clone,
    I: Iterator<Item = GeneratedCase<Op, Dist>>,
    Dist: Distribution<Op>,
    Evaluate: CaseEvaluator<Op>,
    Cost: CostModel<Op>,
    Mutate: SequenceMutator<Op>,
    Shrink: SequenceMutator<Op>,
    Finalize: CaseFinalizer<Op>,
{
    type Item = CoveredCase<Op>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let pending = if let Some(pending) = self.pop_initial_case() {
                pending
            } else if self.should_try_seed() {
                match self.inner.next() {
                    Some(case) => {
                        let mut ops = case.ops();
                        self.finalize.finalize(&mut ops);
                        self.stats.generated += 1;
                        self.mutated_since_seed = 0;
                        PendingCoverageCase {
                            ops,
                            seed: Some(case.seed),
                            parent: None,
                            depth: 0,
                            priority: u64::MAX,
                            order: 0,
                        }
                    }
                    None => {
                        self.seeds_exhausted = true;
                        self.pop_scheduled_pending()?
                    }
                }
            } else {
                match self.pop_scheduled_pending() {
                    Some(pending) => pending,
                    None => {
                        let case = self.inner.next()?;
                        let mut ops = case.ops();
                        self.finalize.finalize(&mut ops);
                        self.stats.generated += 1;
                        self.mutated_since_seed = 0;
                        PendingCoverageCase {
                            ops,
                            seed: Some(case.seed),
                            parent: None,
                            depth: 0,
                            priority: u64::MAX,
                            order: 0,
                        }
                    }
                }
            };

            let evaluation = self.evaluate.evaluate(&pending.ops);
            self.stats.executed += 1;
            if !is_coverage_interesting(&self.global, &evaluation.coverage, evaluation.is_failure())
            {
                continue;
            }

            let required_coverage = coverage_delta(&self.global, &evaluation.coverage);
            let (ops, evaluation) =
                self.shrink_interesting(pending.ops, evaluation, &required_coverage);
            if !is_coverage_interesting(&self.global, &evaluation.coverage, evaluation.is_failure())
            {
                continue;
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

            let cost = self.cost.total_cost(&ops);
            let len = ops.len();
            let case = CoveredCase {
                id,
                seed: pending.seed,
                parent: pending.parent,
                depth: pending.depth,
                ops,
                coverage: evaluation.coverage,
                unique_coverage,
                outcome: evaluation.outcome,
                cost,
                len,
            };
            self.enqueue_mutations(&case);
            self.corpus.push(case.clone());
            return Some(case);
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

impl<Op, Dist, I, Evaluate, Cost, Mutate, Shrink, Finalize> std::iter::FusedIterator
    for CoverageGuided<Op, I, Evaluate, Cost, Mutate, Shrink, Finalize>
where
    Op: Clone,
    I: Iterator<Item = GeneratedCase<Op, Dist>> + std::iter::FusedIterator,
    Dist: Distribution<Op>,
    Evaluate: CaseEvaluator<Op>,
    Cost: CostModel<Op>,
    Mutate: SequenceMutator<Op>,
    Shrink: SequenceMutator<Op>,
    Finalize: CaseFinalizer<Op>,
{
}

