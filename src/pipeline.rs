struct FuzzConfig {
    base_seed: u64,
    seeds: u64,
    steps: usize,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            base_seed: 0,
            seeds: 64,
            steps: 256,
        }
    }
}

/// A single replay step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step<'a, Op> {
    /// Index of this operation in the replayed sequence.
    pub index: usize,
    /// Operation being applied.
    pub op: &'a Op,
}

/// A generated operation sequence for a single seed.
///
/// The case is lazy: it carries only the `seed`, the number of `steps`, and a clone of the
/// sampling distribution. Ops are regenerated deterministically each time you ask for them, so
/// passing cases never allocate a `Vec<Op>`.
///
/// - [`replay`](GeneratedCase::replay) streams ops through your step function with no allocation.
/// - [`iter_ops`](GeneratedCase::iter_ops) yields each `Op` lazily.
/// - [`ops`](GeneratedCase::ops) materializes the full op list as a `Vec<Op>` (needed for
///   [`reduce_with_cost`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedCase<Op, Dist> {
    /// Seed used to deterministically derive the op stream.
    pub seed: u64,
    /// Number of ops this case contains.
    pub steps: usize,
    distribution: Dist,
    _op: PhantomData<fn() -> Op>,
}

impl<Op, Dist> GeneratedCase<Op, Dist>
where
    Dist: Distribution<Op>,
{
    /// Materialize this case's full op list as a `Vec<Op>`. Allocates `steps` items.
    pub fn ops(&self) -> Vec<Op> {
        self.iter_ops().collect()
    }

    /// Stream ops lazily without allocating a `Vec`. Each call re-seeds from `seed`.
    pub fn iter_ops(&self) -> CaseOps<'_, Op, Dist> {
        CaseOps {
            rng: SmallRng::seed_from_u64(self.seed),
            distribution: &self.distribution,
            remaining: self.steps,
            _op: PhantomData,
        }
    }

    /// Replay this case lazily: stream ops through `step` (no `Vec` allocation), returning the
    /// first `Err`.
    pub fn replay<State, Init, Fold>(&self, mut init: Init, mut step: Fold) -> Result<(), String>
    where
        Init: FnMut() -> State,
        Fold: for<'a> FnMut(&mut State, Step<'a, Op>) -> Result<(), String>,
    {
        let mut state = init();
        let mut rng = SmallRng::seed_from_u64(self.seed);
        for index in 0..self.steps {
            let op = rng.sample(&self.distribution);
            step(&mut state, Step { index, op: &op })?;
        }
        Ok(())
    }
}

/// Iterator that lazily samples a [`GeneratedCase`]'s ops one at a time.
pub struct CaseOps<'a, Op, Dist> {
    rng: SmallRng,
    distribution: &'a Dist,
    remaining: usize,
    _op: PhantomData<fn() -> Op>,
}

impl<'a, Op, Dist> Iterator for CaseOps<'a, Op, Dist>
where
    Dist: Distribution<Op>,
{
    type Item = Op;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(self.rng.sample(self.distribution))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a, Op, Dist> ExactSizeIterator for CaseOps<'a, Op, Dist> where Dist: Distribution<Op> {}

/// Entry point for deterministic mutation fuzzing.
pub struct Fuzzer;

impl Fuzzer {
    /// Build an iterator of lazy [`GeneratedCase`]s, one per seed.
    ///
    /// Each case streams ops on demand via [`GeneratedCase::replay`] /
    /// [`GeneratedCase::iter_ops`] — passing cases never allocate a `Vec<Op>`. The pipeline
    /// combinators ([`CaseIteratorExt::check`], [`CaseIteratorExt::failures`], etc.) use the
    /// lazy form; failing cases materialize ops via [`GeneratedCase::ops`] for
    /// [`reduce_with_cost`]. Operations are sampled by `distribution`; use
    /// `rand::distr::StandardUniform` when you have a `Distribution<Op>` impl on it for your op
    /// type.
    pub fn sequences<Op, Dist>(distribution: Dist) -> SequencesBuilder<Op, Dist>
    where
        Dist: Distribution<Op>,
    {
        SequencesBuilder {
            config: FuzzConfig::default(),
            distribution,
            _op: PhantomData,
        }
    }
}

/// Builder for [`Fuzzer::sequences`].
pub struct SequencesBuilder<Op, Dist> {
    config: FuzzConfig,
    distribution: Dist,
    _op: PhantomData<fn() -> Op>,
}

impl<Op, Dist> SequencesBuilder<Op, Dist> {
    /// Set the first seed used for generated runs. Seed `n` uses `base_seed + n`.
    pub fn base_seed(mut self, base_seed: u64) -> Self {
        self.config.base_seed = base_seed;
        self
    }

    /// Set the number of generated sequences to produce.
    pub fn seeds(mut self, seeds: u64) -> Self {
        self.config.seeds = seeds;
        self
    }

    /// Set the number of mutations in each generated sequence.
    pub fn steps(mut self, steps: usize) -> Self {
        self.config.steps = steps;
        self
    }
}

impl<Op, Dist> IntoIterator for SequencesBuilder<Op, Dist>
where
    Dist: Distribution<Op> + Clone,
{
    type Item = GeneratedCase<Op, Dist>;
    type IntoIter = Sequences<Op, Dist>;

    fn into_iter(self) -> Self::IntoIter {
        Sequences {
            config: self.config,
            distribution: self.distribution,
            next_offset: 0,
            _op: PhantomData,
        }
    }
}

/// Iterator that yields one lazy [`GeneratedCase`] per seed.
pub struct Sequences<Op, Dist> {
    config: FuzzConfig,
    distribution: Dist,
    next_offset: u64,
    _op: PhantomData<fn() -> Op>,
}

impl<Op, Dist> Iterator for Sequences<Op, Dist>
where
    Dist: Distribution<Op> + Clone,
{
    type Item = GeneratedCase<Op, Dist>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_offset >= self.config.seeds {
            return None;
        }
        let seed = self.config.base_seed.wrapping_add(self.next_offset);
        self.next_offset += 1;
        Some(GeneratedCase {
            seed,
            steps: self.config.steps,
            distribution: self.distribution.clone(),
            _op: PhantomData,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.config.seeds.saturating_sub(self.next_offset) as usize;
        (remaining, Some(remaining))
    }
}

impl<Op, Dist> ExactSizeIterator for Sequences<Op, Dist> where Dist: Distribution<Op> + Clone {}

/// Outcome of replaying one [`GeneratedCase`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedCase<Op, Dist> {
    /// The generated case that was replayed. Still lazy — ops are not materialized.
    pub case: GeneratedCase<Op, Dist>,
    /// `Ok(())` if every step passed, `Err` with the failing step's message otherwise.
    pub outcome: Result<(), String>,
}

impl<Op, Dist> CheckedCase<Op, Dist> {
    /// Returns `true` when `outcome` is `Err`.
    pub fn is_failure(&self) -> bool {
        self.outcome.is_err()
    }
}

impl<Op, Dist> CheckedCase<Op, Dist>
where
    Dist: Distribution<Op>,
{
    /// Drop the case if it passed; otherwise materialize its ops and return a [`FailedCase`].
    pub fn into_failure(self) -> Option<FailedCase<Op>> {
        match self.outcome {
            Ok(()) => None,
            Err(error) => Some(FailedCase {
                seed: self.case.seed,
                ops: self.case.ops(),
                error,
            }),
        }
    }
}

/// A generated case whose replay returned `Err`.
///
/// Ops are materialized at failure-detection time so the value can feed [`reduce_with_cost`]
/// directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedCase<Op> {
    /// Seed that generated the failing ops.
    pub seed: u64,
    /// Materialized op list (the same `Vec<Op>` `case.ops()` would have produced).
    pub ops: Vec<Op>,
    /// Error from the first failing step.
    pub error: String,
}

/// A failing case plus its reduced reproduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimizedFailure<Op> {
    /// Seed that generated the original failing operation list.
    pub seed: u64,
    /// Full generated operation list for this seed.
    pub ops: Vec<Op>,
    /// Error from replaying `ops`.
    pub error: String,
    /// Smaller or cheaper operation list that still fails.
    pub minimized_ops: Vec<Op>,
    /// Error from replaying `minimized_ops`.
    pub minimized_error: String,
}

/// Iterator adapters on top of an `Iterator<Item = GeneratedCase<Op, Dist>>`.
///
/// The chain is `sequences.check(init, step).failures().minimize(cost)`. Each stage is optional
/// and the pipeline stays lazy, so `.take(N)`, `.inspect(..)`, `rayon::par_bridge`, etc. all
/// compose with it.
pub trait CaseIteratorExt<Op, Dist>: IntoIterator<Item = GeneratedCase<Op, Dist>> + Sized {
    /// Run replay for every case. Yields one [`CheckedCase`] per generated case (passes included).
    fn check<State, Init, Step>(self, init: Init, step: Step) -> Check<Self::IntoIter, Init, Step>
    where
        Init: FnMut() -> State,
        Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
        Dist: Distribution<Op>,
    {
        Check {
            inner: self.into_iter(),
            init,
            step,
        }
    }

    /// Run replay for every case and drop passing ones. Yields one [`FailedCase`] per failure.
    fn failures<State, Init, Step>(
        self,
        init: Init,
        step: Step,
    ) -> Failures<Self::IntoIter, Init, Step>
    where
        Init: FnMut() -> State,
        Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
        Dist: Distribution<Op>,
    {
        Failures {
            inner: self.into_iter(),
            init,
            step,
        }
    }

    /// Explore cases that add coverage to a corpus.
    ///
    /// The evaluator runs a materialized operation list and returns both the replay outcome and
    /// the coverage or semantic features observed during that replay. The iterator yields only
    /// accepted cases: failures, or passing cases that add at least one new coverage ID.
    fn coverage_guided<Evaluate>(
        self,
        evaluate: Evaluate,
    ) -> CoverageGuided<
        Op,
        Self::IntoIter,
        Evaluate,
        UnitCost,
        NoopSequenceMutator,
        NoopSequenceMutator,
        NoopFinalize,
    >
    where
        Op: Clone,
        Dist: Distribution<Op>,
        Evaluate: CaseEvaluator<Op>,
    {
        CoverageGuided::new(self.into_iter(), evaluate)
    }
}

impl<T, Op, Dist> CaseIteratorExt<Op, Dist> for T where
    T: IntoIterator<Item = GeneratedCase<Op, Dist>>
{
}

/// Iterator from [`CaseIteratorExt::check`], yielding one [`CheckedCase`] per inner case.
pub struct Check<I, Init, Step> {
    inner: I,
    init: Init,
    step: Step,
}

impl<I, Init, Step> Check<I, Init, Step> {
    /// Drop passing cases; keep failures only. Reuses the held `init`/`step`.
    pub fn failures(self) -> Failures<I, Init, Step> {
        Failures {
            inner: self.inner,
            init: self.init,
            step: self.step,
        }
    }
}

impl<I, Op, Dist, State, Init, Step> Iterator for Check<I, Init, Step>
where
    I: Iterator<Item = GeneratedCase<Op, Dist>>,
    Dist: Distribution<Op>,
    Init: FnMut() -> State,
    Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
{
    type Item = CheckedCase<Op, Dist>;

    fn next(&mut self) -> Option<Self::Item> {
        let case = self.inner.next()?;
        let outcome = case.replay(&mut self.init, &mut self.step);
        Some(CheckedCase { case, outcome })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<I, Op, Dist, State, Init, Step> std::iter::FusedIterator for Check<I, Init, Step>
where
    I: Iterator<Item = GeneratedCase<Op, Dist>> + std::iter::FusedIterator,
    Dist: Distribution<Op>,
    Init: FnMut() -> State,
    Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
{
}

/// Iterator from [`CaseIteratorExt::failures`] or [`Check::failures`], yielding one
/// [`FailedCase`] per failing inner case.
pub struct Failures<I, Init, Step> {
    inner: I,
    init: Init,
    step: Step,
}

impl<I, Init, Step> Failures<I, Init, Step> {
    /// For each failing case, reduce it to a minimal repro under `cost`. Reuses the held
    /// `init`/`step`.
    pub fn minimize<Cost>(self, cost: Cost) -> Minimize<I, Init, Step, Cost> {
        Minimize {
            inner: self.inner,
            init: self.init,
            step: self.step,
            cost,
        }
    }

    /// For each failing case, reduce it under `cost` and caller-provided transforms.
    ///
    /// Transforms are tried only after the default deletion pass. They must emit valid candidate
    /// operation sequences for the caller's domain.
    pub fn minimize_with_transforms<Cost, Transforms>(
        self,
        cost: Cost,
        transforms: Transforms,
    ) -> MinimizeWithTransforms<I, Init, Step, Cost, Transforms> {
        MinimizeWithTransforms {
            inner: self.inner,
            init: self.init,
            step: self.step,
            cost,
            transforms,
        }
    }
}

impl<I, Op, Dist, State, Init, Step> Iterator for Failures<I, Init, Step>
where
    I: Iterator<Item = GeneratedCase<Op, Dist>>,
    Dist: Distribution<Op>,
    Init: FnMut() -> State,
    Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
{
    type Item = FailedCase<Op>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let case = self.inner.next()?;
            if let Err(error) = case.replay(&mut self.init, &mut self.step) {
                return Some(FailedCase {
                    seed: case.seed,
                    ops: case.ops(),
                    error,
                });
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, self.inner.size_hint().1)
    }
}

impl<I, Op, Dist, State, Init, Step> std::iter::FusedIterator for Failures<I, Init, Step>
where
    I: Iterator<Item = GeneratedCase<Op, Dist>> + std::iter::FusedIterator,
    Dist: Distribution<Op>,
    Init: FnMut() -> State,
    Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
{
}

/// Iterator from [`Failures::minimize`], yielding a [`MinimizedFailure`] per failing inner case.
pub struct Minimize<I, Init, Step, Cost> {
    inner: I,
    init: Init,
    step: Step,
    cost: Cost,
}

impl<I, Op, Dist, State, Init, Step, Cost> Iterator for Minimize<I, Init, Step, Cost>
where
    Op: Clone,
    I: Iterator<Item = GeneratedCase<Op, Dist>>,
    Dist: Distribution<Op>,
    Init: FnMut() -> State,
    Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
    Cost: CostModel<Op>,
{
    type Item = MinimizedFailure<Op>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let case = self.inner.next()?;
            if let Err(error) = case.replay(&mut self.init, &mut self.step) {
                let ops = case.ops();
                let seed = case.seed;
                let minimized_ops = reduce_with_cost(&ops, &self.cost, |c| {
                    replay_ops(c, &mut self.init, &mut self.step).is_err()
                });
                let minimized_error = replay_ops(&minimized_ops, &mut self.init, &mut self.step)
                    .expect_err("reducer must preserve the failing invariant");
                return Some(MinimizedFailure {
                    seed,
                    ops,
                    error,
                    minimized_ops,
                    minimized_error,
                });
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, self.inner.size_hint().1)
    }
}

impl<I, Op, Dist, State, Init, Step, Cost> std::iter::FusedIterator
    for Minimize<I, Init, Step, Cost>
where
    Op: Clone,
    I: Iterator<Item = GeneratedCase<Op, Dist>> + std::iter::FusedIterator,
    Dist: Distribution<Op>,
    Init: FnMut() -> State,
    Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
    Cost: CostModel<Op>,
{
}

/// Iterator from [`Failures::minimize_with_transforms`], yielding a [`MinimizedFailure`] per
/// failing inner case.
pub struct MinimizeWithTransforms<I, Init, Step, Cost, Transforms> {
    inner: I,
    init: Init,
    step: Step,
    cost: Cost,
    transforms: Transforms,
}

impl<I, Op, Dist, State, Init, Step, Cost, Transforms> Iterator
    for MinimizeWithTransforms<I, Init, Step, Cost, Transforms>
where
    Op: Clone,
    I: Iterator<Item = GeneratedCase<Op, Dist>>,
    Dist: Distribution<Op>,
    Init: FnMut() -> State,
    Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
    Cost: CostModel<Op>,
    Transforms: SequenceMutator<Op>,
{
    type Item = MinimizedFailure<Op>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let case = self.inner.next()?;
            if let Err(error) = case.replay(&mut self.init, &mut self.step) {
                let ops = case.ops();
                let seed = case.seed;
                // Wrap the transforms in a fresh FnMut closure with explicit
                // higher-rank lifetimes so the compiler can satisfy the
                // `SequenceMutator` blanket impl on the closure type.
                let transforms = &mut self.transforms;
                let minimized_ops = reduce_with_cost_and_transforms(
                    &ops,
                    &self.cost,
                    |c| replay_ops(c, &mut self.init, &mut self.step).is_err(),
                    |c: &[Op], emit: &mut dyn FnMut(Vec<Op>)| transforms.mutate(c, emit),
                );
                let minimized_error = replay_ops(&minimized_ops, &mut self.init, &mut self.step)
                    .expect_err("reducer must preserve the failing invariant");
                return Some(MinimizedFailure {
                    seed,
                    ops,
                    error,
                    minimized_ops,
                    minimized_error,
                });
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, self.inner.size_hint().1)
    }
}

impl<I, Op, Dist, State, Init, Step, Cost, Transforms> std::iter::FusedIterator
    for MinimizeWithTransforms<I, Init, Step, Cost, Transforms>
where
    Op: Clone,
    I: Iterator<Item = GeneratedCase<Op, Dist>> + std::iter::FusedIterator,
    Dist: Distribution<Op>,
    Init: FnMut() -> State,
    Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
    Cost: CostModel<Op>,
    Transforms: SequenceMutator<Op>,
{
}

