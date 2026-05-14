//! Deterministic mutation-sequence fuzzing with invariant replay and cost-aware reduction.
//!
//! The core workflow is:
//! 1. Sample printable mutations with `rand`'s [`Distribution`] trait.
//! 2. Replay each mutation list from a clean state and check invariants after each step.
//! 3. If replay fails, reduce the operation list using a caller-provided cost model.
//!
//! This is meant for state-machine bugs where normal unit tests miss ordering edge cases, but the
//! whole failure can be reproduced from a list of small operations.

use rand::{Rng, SeedableRng, distr::Distribution, rngs::SmallRng};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::Debug,
    fs::{self, File},
    io::{self, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy)]
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

/// Replay a materialized slice of ops from a fresh state.
///
/// For the lazy version that streams ops directly from a [`GeneratedCase`] without allocating
/// a `Vec`, use [`GeneratedCase::replay`]. This slice-based helper exists for the reducer's
/// inner predicate, which operates on shrunk `&[Op]` candidates.
pub fn replay_ops<Op, State, Init, Fold>(
    ops: &[Op],
    mut init: Init,
    mut step: Fold,
) -> Result<(), String>
where
    Init: FnMut() -> State,
    Fold: for<'a> FnMut(&mut State, Step<'a, Op>) -> Result<(), String>,
{
    let mut state = init();
    for (index, op) in ops.iter().enumerate() {
        step(&mut state, Step { index, op })?;
    }
    Ok(())
}

/// Cost model used by the reducer.
pub trait CostModel<Op> {
    /// Cost for a single operation. Lower is better.
    fn cost(&self, op: &Op) -> u64;

    /// Cost for a whole operation list.
    fn total_cost(&self, ops: &[Op]) -> u64 {
        ops.iter().map(|op| self.cost(op)).sum()
    }
}

/// Domain-aware sequence mutator used by reducers and coverage-guided exploration.
///
/// Implementations receive the current operation sequence and emit valid replacement sequences.
/// The caller decides whether each emitted candidate is interesting: a reducer may require the
/// same failure, while the coverage explorer may require new coverage.
pub trait SequenceMutator<Op> {
    /// Emit zero or more candidate operation sequences derived from `ops`.
    fn mutate(&mut self, ops: &[Op], emit: &mut dyn FnMut(Vec<Op>));
}

impl<Op, F> SequenceMutator<Op> for F
where
    F: FnMut(&[Op], &mut dyn FnMut(Vec<Op>)),
{
    fn mutate(&mut self, ops: &[Op], emit: &mut dyn FnMut(Vec<Op>)) {
        self(ops, emit);
    }
}

impl<Op, F> CostModel<Op> for F
where
    F: Fn(&Op) -> u64,
{
    fn cost(&self, op: &Op) -> u64 {
        self(op)
    }
}

/// Every operation has cost `1`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnitCost;

impl<Op> CostModel<Op> for UnitCost {
    fn cost(&self, _op: &Op) -> u64 {
        1
    }
}

/// Stable identifier for one coverage feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoverageId(pub u64);

/// Set of coverage IDs observed by one case or the global corpus.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoverageSet {
    ids: BTreeSet<CoverageId>,
}

impl CoverageSet {
    /// Create an empty coverage set.
    pub fn new() -> Self {
        Self {
            ids: BTreeSet::new(),
        }
    }

    /// Insert one ID. Returns `true` if it was not already present.
    pub fn insert(&mut self, id: CoverageId) -> bool {
        self.ids.insert(id)
    }

    /// Extend this set from an iterator of IDs.
    pub fn extend(&mut self, ids: impl IntoIterator<Item = CoverageId>) {
        self.ids.extend(ids);
    }

    /// Number of unique IDs in this set.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Returns `true` if this set has no coverage IDs.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Returns `true` if `id` is in this set.
    pub fn contains(&self, id: &CoverageId) -> bool {
        self.ids.contains(id)
    }

    /// Return IDs present in `self` but absent from `other`.
    pub fn difference(&self, other: &Self) -> Self {
        Self {
            ids: self.ids.difference(&other.ids).copied().collect(),
        }
    }

    /// Returns `true` if every ID in `self` is also in `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.ids.is_subset(&other.ids)
    }

    /// Returns `true` if every ID in `other` is also in `self`.
    pub fn is_superset(&self, other: &Self) -> bool {
        self.ids.is_superset(&other.ids)
    }

    /// Iterate over coverage IDs in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = CoverageId> + '_ {
        self.ids.iter().copied()
    }
}

impl FromIterator<CoverageId> for CoverageSet {
    fn from_iter<T: IntoIterator<Item = CoverageId>>(iter: T) -> Self {
        Self {
            ids: iter.into_iter().collect(),
        }
    }
}

/// Manifest metadata for an accepted corpus entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusEntry<Id = String> {
    /// Stable corpus entry ID.
    pub id: Id,
    /// Parent corpus entry ID, if this case came from mutation.
    pub parent: Option<Id>,
    /// Full coverage observed while replaying this entry.
    pub coverage: CoverageSet,
    /// Coverage this entry added to the corpus when accepted.
    pub unique_coverage: CoverageSet,
    /// Whether replay failed.
    pub is_failure: bool,
    /// Caller-defined case cost, usually file size or op count.
    pub cost: u64,
    /// Operation count when known.
    pub len: usize,
}

/// Result of testing a candidate against a corpus coverage set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterestingCase<Id = String> {
    /// Candidate ID.
    pub id: Id,
    /// Coverage IDs not yet present in the corpus.
    pub new_coverage: CoverageSet,
    /// Whether replay failed.
    pub is_failure: bool,
}

/// Aggregate counters for a coverage-guided exploration run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExplorationStats {
    /// Cases generated directly from seeds.
    pub generated: u64,
    /// Cases generated by mutating corpus entries.
    pub mutated: u64,
    /// Cases executed in the target harness.
    pub executed: u64,
    /// Cases accepted into the corpus.
    pub accepted: u64,
    /// Accepted cases that failed the harness.
    pub failures: u64,
    /// Unique coverage IDs in the accepted corpus.
    pub coverage_ids: u64,
}

/// Result from evaluating one materialized operation sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageEvaluation {
    /// `Ok(())` if replay passed, `Err` with the failure message otherwise.
    pub outcome: Result<(), String>,
    /// Coverage or semantic features observed while replaying the case.
    pub coverage: CoverageSet,
}

impl CoverageEvaluation {
    /// Construct a passing evaluation.
    pub fn pass(coverage: CoverageSet) -> Self {
        Self {
            outcome: Ok(()),
            coverage,
        }
    }

    /// Construct a failing evaluation.
    pub fn fail(error: impl Into<String>, coverage: CoverageSet) -> Self {
        Self {
            outcome: Err(error.into()),
            coverage,
        }
    }

    /// Construct an evaluation from an existing pass/fail outcome.
    pub fn from_outcome(outcome: Result<(), String>, coverage: CoverageSet) -> Self {
        Self { outcome, coverage }
    }

    /// Returns `true` when `outcome` is `Err`.
    pub fn is_failure(&self) -> bool {
        self.outcome.is_err()
    }
}

/// A case accepted into a coverage-guided corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveredCase<Op> {
    /// Monotonic ID assigned by the coverage-guided iterator.
    pub id: u64,
    /// Seed that generated the case, if it came directly from [`Fuzzer::sequences`].
    pub seed: Option<u64>,
    /// Parent corpus entry, if this case came from mutation.
    pub parent: Option<u64>,
    /// Mutation depth from the original generated seed case.
    pub depth: usize,
    /// Materialized operation list for replay or reproduction.
    pub ops: Vec<Op>,
    /// Full coverage observed while replaying this entry.
    pub coverage: CoverageSet,
    /// Coverage this entry added to the corpus when accepted.
    pub unique_coverage: CoverageSet,
    /// `Ok(())` if replay passed, `Err` with the failure message otherwise.
    pub outcome: Result<(), String>,
    /// Caller-defined case cost.
    pub cost: u64,
    /// Operation count.
    pub len: usize,
}

impl<Op> CoveredCase<Op> {
    /// Returns `true` when `outcome` is `Err`.
    pub fn is_failure(&self) -> bool {
        self.outcome.is_err()
    }
}

/// Return the directory used for coverage/fuzzing artifacts.
///
/// `FUZZ_OUT_DIR` wins when present. Otherwise this uses the parent directory of
/// `LLVM_PROFILE_FILE`, which keeps accepted cases beside the generated `.profraw` files.
pub fn fuzz_output_dir_from_env(default: impl Into<PathBuf>) -> PathBuf {
    if let Some(path) = std::env::var_os("FUZZ_OUT_DIR") {
        return PathBuf::from(path);
    }

    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        let profile = PathBuf::from(profile);
        if let Some(parent) = profile.parent() {
            return parent.to_path_buf();
        }
    }

    default.into()
}

/// Writes accepted coverage-guided cases as `Debug`-formatted operation lists.
///
/// This exporter is intentionally format-light: the files are meant to be durable artifacts for
/// inspection and later conversion into domain-specific replay tests.
pub struct DebugCaseExporter {
    cases_dir: PathBuf,
    manifest: File,
}

impl DebugCaseExporter {
    /// Create an exporter rooted at `out_dir/cases`.
    pub fn new(out_dir: impl AsRef<Path>) -> io::Result<Self> {
        let cases_dir = out_dir.as_ref().join("cases");
        fs::create_dir_all(&cases_dir)?;
        let mut manifest = File::create(cases_dir.join("manifest.tsv"))?;
        writeln!(
            manifest,
            "accepted\tid\tseed\tparent\tdepth\tlen\tcost\tnew_coverage\toutcome\tfile"
        )?;
        Ok(Self {
            cases_dir,
            manifest,
        })
    }

    /// Directory containing the manifest and exported case files.
    pub fn cases_dir(&self) -> &Path {
        &self.cases_dir
    }

    /// Export one accepted corpus case.
    pub fn export<Op: Debug>(&mut self, accepted: usize, case: &CoveredCase<Op>) -> io::Result<()> {
        let file_name = format!("case-{accepted:06}-id-{:06}.ops.txt", case.id);
        self.write_ops_file(
            &file_name,
            &case.ops,
            &[
                format!("accepted={accepted}"),
                format!("id={}", case.id),
                format!("seed={:?}", case.seed),
                format!("parent={:?}", case.parent),
                format!("depth={}", case.depth),
                format!("len={}", case.len),
                format!("cost={}", case.cost),
                format!("new_coverage={}", case.unique_coverage.len()),
                format!(
                    "outcome={}",
                    if case.is_failure() { "failure" } else { "pass" }
                ),
            ],
        )?;

        writeln!(
            self.manifest,
            "{accepted}\t{}\t{:?}\t{:?}\t{}\t{}\t{}\t{}\t{}\t{}",
            case.id,
            case.seed,
            case.parent,
            case.depth,
            case.len,
            case.cost,
            case.unique_coverage.len(),
            if case.is_failure() { "failure" } else { "pass" },
            file_name
        )?;
        self.manifest.flush()
    }

    /// Export a minimized failing operation list related to an accepted case.
    pub fn export_minimized_failure<Op: Debug>(
        &mut self,
        id: u64,
        ops: &[Op],
        error: &str,
        cost: u64,
    ) -> io::Result<()> {
        let file_name = format!("failure-minimized-id-{id:06}.ops.txt");
        self.write_ops_file(
            &file_name,
            ops,
            &[
                format!("id={id}"),
                format!("len={}", ops.len()),
                format!("cost={cost}"),
                "outcome=failure-minimized".to_string(),
                format!("error={}", error.replace('\n', "\\n")),
            ],
        )
    }

    fn write_ops_file<Op: Debug>(
        &self,
        file_name: &str,
        ops: &[Op],
        metadata: &[String],
    ) -> io::Result<()> {
        let mut file = File::create(self.cases_dir.join(file_name))?;
        writeln!(file, "// iterator-fuzz coverage-guided case")?;
        for item in metadata {
            writeln!(file, "// {item}")?;
        }
        writeln!(file, "let ops = vec![")?;
        for op in ops {
            writeln!(file, "    {op:?},")?;
        }
        writeln!(file, "];")
    }
}

/// Evaluates a materialized operation sequence for coverage-guided exploration.
pub trait CaseEvaluator<Op> {
    /// Replay `ops` and return the observed outcome and coverage.
    fn evaluate(&mut self, ops: &[Op]) -> CoverageEvaluation;
}

impl<Op, F> CaseEvaluator<Op> for F
where
    F: FnMut(&[Op]) -> CoverageEvaluation,
{
    fn evaluate(&mut self, ops: &[Op]) -> CoverageEvaluation {
        self(ops)
    }
}

/// Final hook before a generated, mutated, or shrunk operation list is evaluated.
pub trait CaseFinalizer<Op> {
    /// Normalize or complete `ops` in place.
    fn finalize(&mut self, ops: &mut Vec<Op>);
}

impl<Op, F> CaseFinalizer<Op> for F
where
    F: FnMut(&mut Vec<Op>),
{
    fn finalize(&mut self, ops: &mut Vec<Op>) {
        self(ops);
    }
}

/// A finalizer that leaves cases unchanged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopFinalize;

impl<Op> CaseFinalizer<Op> for NoopFinalize {
    fn finalize(&mut self, _ops: &mut Vec<Op>) {}
}

/// A sequence mutator that emits no candidates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopSequenceMutator;

impl<Op> SequenceMutator<Op> for NoopSequenceMutator {
    fn mutate(&mut self, _ops: &[Op], _emit: &mut dyn FnMut(Vec<Op>)) {}
}

struct PendingCoverageCase<Op> {
    ops: Vec<Op>,
    seed: Option<u64>,
    parent: Option<u64>,
    depth: usize,
    priority: u64,
    order: u64,
}

const DEFAULT_SEED_INTERVAL: usize = 1;

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

/// Return coverage in `candidate` that is absent from `global`.
pub fn coverage_delta(global: &CoverageSet, candidate: &CoverageSet) -> CoverageSet {
    candidate.difference(global)
}

/// Returns `true` when a case should be added to the corpus.
///
/// Failing cases are always interesting. Passing cases are interesting only when they add at least
/// one coverage ID not yet present in `global`.
pub fn is_coverage_interesting(
    global: &CoverageSet,
    candidate: &CoverageSet,
    is_failure: bool,
) -> bool {
    is_failure || !coverage_delta(global, candidate).is_empty()
}

/// Greedily shrink a failing operation list by deleting contiguous chunks with unit cost.
pub fn reduce<Op, Fails>(ops: &[Op], fails: Fails) -> Vec<Op>
where
    Op: Clone,
    Fails: FnMut(&[Op]) -> bool,
{
    reduce_with_cost(ops, &UnitCost, fails)
}

/// Greedily shrink a failing operation list with a caller-provided cost model.
///
/// The reducer preserves operation order and only removes operations. It accepts a candidate when
/// it still fails and has a lower `(total_cost, len)` score than the current best reproduction.
pub fn reduce_with_cost<Op, Cost, Fails>(ops: &[Op], cost: &Cost, mut fails: Fails) -> Vec<Op>
where
    Op: Clone,
    Cost: CostModel<Op>,
    Fails: FnMut(&[Op]) -> bool,
{
    reduce_by_deletion(ops.to_vec(), cost, &mut fails)
}

/// Greedily shrink a failing operation list with caller-provided sequence transforms.
///
/// The built-in reducer only assumes deletion is valid. `transforms` is the caller's hook for
/// domain-valid rewrites over the existing operation type: simplify an op's fields, replace a batch
/// op with a smaller batch, reorder operations only when that is valid for the domain, and so on.
///
/// Each emitted candidate is deletion-reduced again, then accepted only if it still fails and has a
/// lower `(total_cost, len)` score than the current best. This lets neutral transforms help when
/// they make later deletion possible without making swaps or other rewrites globally implicit.
pub fn reduce_with_cost_and_transforms<Op, Cost, Fails, Transforms>(
    ops: &[Op],
    cost: &Cost,
    mut fails: Fails,
    mut transforms: Transforms,
) -> Vec<Op>
where
    Op: Clone,
    Cost: CostModel<Op>,
    Fails: FnMut(&[Op]) -> bool,
    Transforms: SequenceMutator<Op>,
{
    let mut minimized = reduce_by_deletion(ops.to_vec(), cost, &mut fails);
    let mut best_score = score(&minimized, cost);

    loop {
        let mut accepted = None;
        transforms.mutate(&minimized, &mut |candidate| {
            if accepted.is_some() {
                return;
            }
            let reduced = reduce_by_deletion(candidate, cost, &mut fails);
            let candidate_score = score(&reduced, cost);
            if candidate_score < best_score && fails(&reduced) {
                accepted = Some((reduced, candidate_score));
            }
        });

        let Some((candidate, candidate_score)) = accepted else {
            break;
        };
        minimized = candidate;
        best_score = candidate_score;
    }

    minimized
}

/// Greedily shrink an operation list while preserving an arbitrary predicate.
///
/// This is the coverage-preserving sibling of [`reduce_with_cost_and_transforms`]. A caller can
/// require that the candidate keeps a set of coverage IDs, keeps a failure, or both. The same
/// [`SequenceMutator`] hook is used here so domain-aware rewrites can simplify cases beyond
/// deletion.
pub fn reduce_preserving_with_transforms<Op, Cost, Preserves, Transforms>(
    ops: &[Op],
    cost: &Cost,
    mut preserves: Preserves,
    mut transforms: Transforms,
) -> Vec<Op>
where
    Op: Clone,
    Cost: CostModel<Op>,
    Preserves: FnMut(&[Op]) -> bool,
    Transforms: SequenceMutator<Op>,
{
    let mut minimized = reduce_by_deletion(ops.to_vec(), cost, &mut preserves);
    let mut best_score = score(&minimized, cost);

    loop {
        let mut accepted = None;
        transforms.mutate(&minimized, &mut |candidate| {
            if accepted.is_some() {
                return;
            }
            let reduced = reduce_by_deletion(candidate, cost, &mut preserves);
            let candidate_score = score(&reduced, cost);
            if candidate_score < best_score && preserves(&reduced) {
                accepted = Some((reduced, candidate_score));
            }
        });

        let Some((candidate, candidate_score)) = accepted else {
            break;
        };
        minimized = candidate;
        best_score = candidate_score;
    }

    minimized
}

/// Emit deletion candidates for a sequence.
///
/// Protocol targets can use this as their generic shrink pass before adding domain-specific
/// rewrites. Candidates include progressively smaller contiguous chunk deletions and then
/// single-operation deletions.
pub fn emit_deletion_candidates<Op: Clone>(ops: &[Op], emit: &mut dyn FnMut(Vec<Op>)) {
    if ops.is_empty() {
        return;
    }

    let mut chunk_len = ops.len().max(1).next_power_of_two() / 2;
    while chunk_len > 1 {
        let mut index = 0;
        while index + chunk_len <= ops.len() {
            let mut candidate = ops.to_vec();
            candidate.drain(index..index + chunk_len);
            emit(candidate);
            index += chunk_len;
        }
        chunk_len /= 2;
    }

    for index in 0..ops.len() {
        let mut candidate = ops.to_vec();
        candidate.remove(index);
        emit(candidate);
    }
}

fn reduce_by_deletion<Op, Cost, Fails>(
    mut minimized: Vec<Op>,
    cost: &Cost,
    fails: &mut Fails,
) -> Vec<Op>
where
    Op: Clone,
    Cost: CostModel<Op>,
    Fails: FnMut(&[Op]) -> bool,
{
    let mut best_score = score(&minimized, cost);
    let mut chunk_len = minimized.len().max(1).next_power_of_two() / 2;

    while chunk_len > 0 {
        let mut index = 0;
        let mut accepted_candidate = false;

        while index + chunk_len <= minimized.len() {
            let mut candidate = minimized.clone();
            candidate.drain(index..index + chunk_len);
            let candidate_score = score(&candidate, cost);

            if candidate_score < best_score && fails(&candidate) {
                minimized = candidate;
                best_score = candidate_score;
                accepted_candidate = true;
            } else {
                index += chunk_len;
            }
        }

        if !accepted_candidate {
            chunk_len /= 2;
        }
    }

    minimized
}

fn score<Op, Cost>(ops: &[Op], cost: &Cost) -> (u64, usize)
where
    Cost: CostModel<Op>,
{
    (cost.total_cost(ops), ops.len())
}

/// LLVM source coverage collection for in-process coverage-guided fuzzing.
///
/// Build the harness with `RUSTFLAGS="-Cinstrument-coverage"` and use
/// [`LlvmCoverage::evaluate`](llvm_coverage::LlvmCoverage::evaluate) from a
/// [`CaseIteratorExt::coverage_guided`] evaluator. The collector resets LLVM counters before each
/// case, writes a per-case profile, exports source coverage with `llvm-cov`, and returns covered
/// source regions as [`CoverageId`]s.
#[cfg(feature = "llvm-coverage")]
pub mod llvm_coverage {
    use super::{CoverageEvaluation, CoverageId, CoverageSet};
    use serde_json::Value;
    use std::{
        ffi::CString,
        fs,
        os::raw::{c_char, c_int},
        panic::{AssertUnwindSafe, catch_unwind},
        path::{Path, PathBuf},
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_PROFILE_ID: AtomicU64 = AtomicU64::new(0);

    /// In-process LLVM coverage collector.
    pub struct LlvmCoverage {
        object: PathBuf,
        sources: Vec<PathBuf>,
        profiles: PathBuf,
        profdata: PathBuf,
        llvm_profdata: PathBuf,
        llvm_cov: PathBuf,
        runtime: LlvmProfileRuntime,
    }

    impl LlvmCoverage {
        /// Create a collector for `object`, limiting exported coverage to `sources`.
        ///
        /// `workdir` receives per-case `.profraw` and `.profdata` files.
        pub fn new<P, Sources>(
            object: impl Into<PathBuf>,
            sources: Sources,
            workdir: impl Into<PathBuf>,
        ) -> Result<Self, String>
        where
            P: Into<PathBuf>,
            Sources: IntoIterator<Item = P>,
        {
            let workdir = workdir.into();
            let profiles = workdir.join("profiles");
            let profdata = workdir.join("profdata");
            fs::create_dir_all(&profiles)
                .map_err(|error| format!("failed to create {}: {error}", profiles.display()))?;
            fs::create_dir_all(&profdata)
                .map_err(|error| format!("failed to create {}: {error}", profdata.display()))?;

            Ok(Self {
                object: object.into(),
                sources: sources.into_iter().map(Into::into).collect(),
                profiles,
                profdata,
                llvm_profdata: PathBuf::from("llvm-profdata"),
                llvm_cov: PathBuf::from("llvm-cov"),
                runtime: LlvmProfileRuntime::new(),
            })
        }

        /// Override the `llvm-profdata` executable.
        pub fn llvm_profdata(mut self, path: impl Into<PathBuf>) -> Self {
            self.llvm_profdata = path.into();
            self
        }

        /// Override the `llvm-cov` executable.
        pub fn llvm_cov(mut self, path: impl Into<PathBuf>) -> Self {
            self.llvm_cov = path.into();
            self
        }

        /// Evaluate one case and return its replay result plus real source coverage.
        pub fn evaluate<F>(&mut self, run: F) -> Result<CoverageEvaluation, String>
        where
            F: FnOnce() -> Result<(), String>,
        {
            let id = NEXT_PROFILE_ID.fetch_add(1, Ordering::Relaxed);
            let raw = self.profiles.join(format!("case-{id:016x}.profraw"));
            let indexed = self.profdata.join(format!("case-{id:016x}.profdata"));

            self.runtime.set_filename(&raw)?;
            self.runtime.reset_counters();
            let outcome = match catch_unwind(AssertUnwindSafe(run)) {
                Ok(outcome) => outcome,
                Err(payload) => Err(panic_message(payload)),
            };
            self.runtime.write_file(&raw)?;
            let coverage = self.export_coverage(&raw, &indexed)?;
            Ok(CoverageEvaluation::from_outcome(outcome, coverage))
        }

        fn export_coverage(&self, raw: &Path, indexed: &Path) -> Result<CoverageSet, String> {
            let output = Command::new(&self.llvm_profdata)
                .arg("merge")
                .arg("-sparse")
                .arg(raw)
                .arg("-o")
                .arg(indexed)
                .output()
                .map_err(|error| {
                    format!(
                        "failed to run {} merge: {error}",
                        self.llvm_profdata.display()
                    )
                })?;
            ensure_success(&self.llvm_profdata, "merge", output)?;

            let mut command = Command::new(&self.llvm_cov);
            command
                .arg("export")
                .arg(&self.object)
                .arg(format!("-instr-profile={}", indexed.display()))
                .arg("--format=text");
            for source in &self.sources {
                command.arg(source);
            }

            let output = command.output().map_err(|error| {
                format!("failed to run {} export: {error}", self.llvm_cov.display())
            })?;
            let stdout = ensure_success(&self.llvm_cov, "export", output)?;
            coverage_from_export(&stdout)
        }
    }

    /// In-process LLVM counter collector for fast coverage-guided exploration.
    ///
    /// This collector reads LLVM's raw coverage counter array directly after each replay. It is
    /// cheaper than exporting source regions for every case, and the resulting IDs are suitable as
    /// greybox search features.
    pub struct LlvmCounterCoverage {
        counter_count: usize,
    }

    impl LlvmCounterCoverage {
        /// Initialize counter collection from the current instrumented binary.
        pub fn new() -> Result<Self, String> {
            let (begin, end) = counter_bounds()?;
            let counter_count = unsafe { end.offset_from(begin) };
            if counter_count <= 0 {
                return Err("LLVM coverage runtime reported no counters".to_string());
            }
            Ok(Self {
                counter_count: counter_count as usize,
            })
        }

        /// Reset counters, run one case, and return its outcome plus covered counter IDs.
        pub fn evaluate<F>(&mut self, run: F) -> Result<CoverageEvaluation, String>
        where
            F: FnOnce() -> Result<(), String>,
        {
            reset_counters();
            let outcome = match catch_unwind(AssertUnwindSafe(run)) {
                Ok(outcome) => outcome,
                Err(payload) => Err(panic_message(payload)),
            };
            let coverage = counter_coverage(self.counter_count)?;
            Ok(CoverageEvaluation::from_outcome(outcome, coverage))
        }
    }

    /// Reset the process-wide LLVM coverage counters.
    ///
    /// This is useful when a coverage-guided runner isolates probe coverage during search, then
    /// replays an accepted corpus at the end so the process-exit `.profraw` contains cumulative
    /// coverage for `llvm-cov` reports.
    pub fn reset_process_counters() {
        reset_counters();
    }

    struct LlvmProfileRuntime {
        filename: Option<CString>,
    }

    impl LlvmProfileRuntime {
        fn new() -> Self {
            Self { filename: None }
        }

        fn reset_counters(&self) {
            reset_counters();
        }

        fn set_filename(&mut self, path: &Path) -> Result<(), String> {
            let filename = CString::new(path.to_string_lossy().as_bytes()).map_err(|_| {
                format!("profile path contains an interior NUL: {}", path.display())
            })?;
            self.filename = Some(filename);
            unsafe {
                __llvm_profile_set_filename(
                    self.filename
                        .as_ref()
                        .expect("filename was just initialized")
                        .as_ptr(),
                );
            }
            Ok(())
        }

        fn write_file(&self, path: &Path) -> Result<(), String> {
            let status = unsafe { __llvm_profile_write_file() };
            if status == 0 {
                Ok(())
            } else {
                Err(format!(
                    "__llvm_profile_write_file failed with status {status} for {}",
                    path.display()
                ))
            }
        }
    }

    unsafe extern "C" {
        fn __llvm_profile_reset_counters();
        fn __llvm_profile_set_filename(filename: *const c_char);
        fn __llvm_profile_write_file() -> c_int;
        fn __llvm_profile_begin_counters() -> *const u64;
        fn __llvm_profile_end_counters() -> *const u64;
    }

    fn reset_counters() {
        unsafe {
            __llvm_profile_reset_counters();
        }
    }

    fn counter_bounds() -> Result<(*const u64, *const u64), String> {
        let begin = unsafe { __llvm_profile_begin_counters() };
        let end = unsafe { __llvm_profile_end_counters() };
        if begin.is_null() || end.is_null() {
            return Err("LLVM coverage runtime returned null counter bounds".to_string());
        }
        Ok((begin, end))
    }

    fn counter_coverage(counter_count: usize) -> Result<CoverageSet, String> {
        let (begin, end) = counter_bounds()?;
        let current_count = unsafe { end.offset_from(begin) };
        if current_count < 0 || current_count as usize != counter_count {
            return Err(format!(
                "LLVM coverage counter count changed from {counter_count} to {current_count}"
            ));
        }

        let mut coverage = CoverageSet::new();
        for index in 0..counter_count {
            let counter = unsafe { std::ptr::read_volatile(begin.add(index)) };
            if counter != 0 {
                coverage.insert(CoverageId(index as u64));
            }
        }
        Ok(coverage)
    }

    fn ensure_success(
        program: &Path,
        subcommand: &str,
        output: std::process::Output,
    ) -> Result<Vec<u8>, String> {
        if output.status.success() {
            return Ok(output.stdout);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "{} {subcommand} failed with status {}: {stderr}",
            program.display(),
            output.status
        ))
    }

    fn coverage_from_export(bytes: &[u8]) -> Result<CoverageSet, String> {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|error| format!("failed to parse llvm-cov export JSON: {error}"))?;
        let mut coverage = CoverageSet::new();
        let data = value
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| "llvm-cov export JSON missing data array".to_string())?;

        for export in data {
            let Some(files) = export.get("files").and_then(Value::as_array) else {
                continue;
            };
            for file in files {
                let filename = file
                    .get("filename")
                    .and_then(Value::as_str)
                    .unwrap_or("<unknown>");
                let Some(segments) = file.get("segments").and_then(Value::as_array) else {
                    continue;
                };
                for segment in segments {
                    let Some(segment) = segment.as_array() else {
                        continue;
                    };
                    let line = segment.first().and_then(Value::as_u64).unwrap_or(0);
                    let column = segment.get(1).and_then(Value::as_u64).unwrap_or(0);
                    let count = segment.get(2).and_then(Value::as_u64).unwrap_or(0);
                    let has_count = segment.get(3).and_then(Value::as_bool).unwrap_or(true);
                    let is_region_entry = segment.get(4).and_then(Value::as_bool).unwrap_or(true);
                    if count > 0 && has_count && is_region_entry {
                        coverage.insert(region_id(filename, line, column));
                    }
                }
            }
        }

        Ok(coverage)
    }

    fn region_id(filename: &str, line: u64, column: u64) -> CoverageId {
        let mut hash = 0xcbf29ce484222325u64;
        for byte in filename.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        for byte in line.to_le_bytes().into_iter().chain(column.to_le_bytes()) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        CoverageId(hash)
    }

    fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
        if let Some(message) = payload.downcast_ref::<&str>() {
            format!("panic: {message}")
        } else if let Some(message) = payload.downcast_ref::<String>() {
            format!("panic: {message}")
        } else {
            "panic with non-string payload".to_string()
        }
    }
}

/// Parallel counterparts to the serial combinators, powered by [`rayon`].
///
/// Each seed is generated and processed independently, so failure detection and minimization
/// scale across cores. Pipeline order is not preserved — use `find_any` for "first" failure or
/// `collect` to gather all failures.
///
/// Closures must be `Fn + Send + Sync` (not `FnMut`) since each thread invokes them.
#[cfg(feature = "rayon")]
pub mod parallel {
    use super::*;
    use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

    impl<Op, Dist> SequencesBuilder<Op, Dist>
    where
        Op: Send,
        Dist: Distribution<Op> + Clone + Sync + Send,
    {
        /// Convert this builder into a rayon parallel iterator of generated cases.
        ///
        /// Each seed yields a lazy [`GeneratedCase`] on the worker thread that processes it.
        /// Use [`ParCaseIteratorExt::failures`] or [`ParCaseIteratorExt::minimized_failures`]
        /// to continue the pipeline.
        pub fn par(self) -> impl IndexedParallelIterator<Item = GeneratedCase<Op, Dist>> {
            let config = self.config;
            let distribution = self.distribution;
            let count = usize::try_from(config.seeds).expect("seeds must fit in usize");
            (0..count).into_par_iter().map(move |offset| {
                let seed = config.base_seed.wrapping_add(offset as u64);
                GeneratedCase {
                    seed,
                    steps: config.steps,
                    distribution: distribution.clone(),
                    _op: PhantomData,
                }
            })
        }
    }

    /// Parallel counterparts to the serial pipeline stages.
    pub trait ParCaseIteratorExt<Op, Dist>:
        ParallelIterator<Item = GeneratedCase<Op, Dist>> + Sized
    where
        Op: Send,
        Dist: Distribution<Op> + Send,
    {
        /// Drop passing cases; keep failures only. Each worker thread builds its own `State`
        /// via `init`.
        fn failures<State, Init, Step>(
            self,
            init: Init,
            step: Step,
        ) -> impl ParallelIterator<Item = FailedCase<Op>>
        where
            // No `State: Send` bound — `State` is created via `init()` and consumed
            // entirely on the worker thread that processes the case. It never crosses
            // a thread boundary, so even `!Send` state (e.g. `dioxus_core::VirtualDom`)
            // is safe to use here.
            Init: Fn() -> State + Sync + Send,
            Step: for<'a> Fn(&mut State, crate::Step<'a, Op>) -> Result<(), String> + Sync + Send,
        {
            self.filter_map(move |case| match case.replay(&init, &step) {
                Ok(()) => None,
                Err(error) => Some(FailedCase {
                    seed: case.seed,
                    ops: case.ops(),
                    error,
                }),
            })
        }

        /// For each failing case, reduce it to a minimal repro under `cost`. Each worker thread
        /// builds its own `State` via `init`. Reduction stays per-case (not parallelized
        /// inside a case), so this scales by spreading distinct failing seeds across cores.
        fn minimized_failures<State, Init, Step, Cost>(
            self,
            init: Init,
            step: Step,
            cost: Cost,
        ) -> impl ParallelIterator<Item = MinimizedFailure<Op>>
        where
            Op: Clone,
            // No `State: Send` bound — `State` is created via `init()` and consumed
            // entirely on the worker thread that processes the case. It never crosses
            // a thread boundary, so even `!Send` state (e.g. `dioxus_core::VirtualDom`)
            // is safe to use here.
            Init: Fn() -> State + Sync + Send,
            Step: for<'a> Fn(&mut State, crate::Step<'a, Op>) -> Result<(), String> + Sync + Send,
            Cost: CostModel<Op> + Sync + Send,
        {
            self.filter_map(move |case| {
                if let Err(error) = case.replay(&init, &step) {
                    let seed = case.seed;
                    let ops = case.ops();
                    let minimized_ops =
                        reduce_with_cost(&ops, &cost, |c| replay_ops(c, &init, &step).is_err());
                    let minimized_error = replay_ops(&minimized_ops, &init, &step)
                        .expect_err("reducer must preserve the failing invariant");
                    Some(MinimizedFailure {
                        seed,
                        ops,
                        error,
                        minimized_ops,
                        minimized_error,
                    })
                } else {
                    None
                }
            })
        }

        /// For each failing case, reduce it under `cost` and caller-provided transforms. Each
        /// worker thread builds its own `State` via `init`, and transforms must be valid for the
        /// caller's domain.
        fn minimized_failures_with_transforms<State, Init, Step, Cost, Transforms>(
            self,
            init: Init,
            step: Step,
            cost: Cost,
            transforms: Transforms,
        ) -> impl ParallelIterator<Item = MinimizedFailure<Op>>
        where
            Op: Clone,
            Init: Fn() -> State + Sync + Send,
            Step: for<'a> Fn(&mut State, crate::Step<'a, Op>) -> Result<(), String> + Sync + Send,
            Cost: CostModel<Op> + Sync + Send,
            Transforms: Fn(&[Op], &mut dyn FnMut(Vec<Op>)) + Sync + Send,
        {
            self.filter_map(move |case| {
                if let Err(error) = case.replay(&init, &step) {
                    let seed = case.seed;
                    let ops = case.ops();
                    let minimized_ops = reduce_with_cost_and_transforms(
                        &ops,
                        &cost,
                        |c| replay_ops(c, &init, &step).is_err(),
                        |c: &[Op], emit: &mut dyn FnMut(Vec<Op>)| transforms(c, emit),
                    );
                    let minimized_error = replay_ops(&minimized_ops, &init, &step)
                        .expect_err("reducer must preserve the failing invariant");
                    Some(MinimizedFailure {
                        seed,
                        ops,
                        error,
                        minimized_ops,
                        minimized_error,
                    })
                } else {
                    None
                }
            })
        }
    }

    impl<I, Op, Dist> ParCaseIteratorExt<Op, Dist> for I
    where
        I: ParallelIterator<Item = GeneratedCase<Op, Dist>>,
        Op: Send,
        Dist: Distribution<Op> + Send,
    {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{
        Rng,
        distr::{Distribution, StandardUniform},
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Op {
        Read(usize),
        Subscribe(usize),
        Reset(usize),
        PointTo(usize),
        Write(usize),
        Peek,
    }

    impl Distribution<Op> for StandardUniform {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Op {
            match rng.random_range(0..6) {
                0 => Op::Read(rng.random_range(0..CONTEXTS)),
                1 => Op::Subscribe(rng.random_range(0..CONTEXTS)),
                2 => Op::Reset(rng.random_range(0..CONTEXTS)),
                3 => Op::PointTo(rng.random_range(0..SIGNALS)),
                4 => Op::Write(rng.random_range(0..SIGNALS)),
                _ => Op::Peek,
            }
        }
    }

    const SIGNALS: usize = 3;
    const CONTEXTS: usize = 3;

    #[derive(Debug, Clone)]
    struct ForwardingModel {
        current_signal: usize,
        signal_values: [i32; SIGNALS],
        wrapper_subscribers: [bool; CONTEXTS],
        dirty_counts: [usize; CONTEXTS],
    }

    impl ForwardingModel {
        fn new() -> Self {
            Self {
                current_signal: 0,
                signal_values: [0, 10, 20],
                wrapper_subscribers: [false; CONTEXTS],
                dirty_counts: [0; CONTEXTS],
            }
        }

        fn read(&mut self, context: usize) -> i32 {
            self.wrapper_subscribers[context] = true;
            self.peek()
        }

        fn subscribe(&mut self, context: usize) {
            self.wrapper_subscribers[context] = true;
        }

        fn reset(&mut self, context: usize) {
            self.wrapper_subscribers[context] = false;
        }

        fn point_to(&mut self, signal: usize) {
            self.current_signal = signal;
        }

        fn write(&mut self, signal: usize) {
            self.signal_values[signal] += 1;
            if signal == self.current_signal {
                for context in 0..CONTEXTS {
                    if self.wrapper_subscribers[context] {
                        self.dirty_counts[context] += 1;
                    }
                }
            }
        }

        fn peek(&self) -> i32 {
            self.signal_values[self.current_signal]
        }
    }

    #[derive(Debug, Clone)]
    struct BuggyForwardingImpl {
        current_signal: usize,
        forwarding_signal: usize,
        signal_values: [i32; SIGNALS],
        wrapper_subscribers: [bool; CONTEXTS],
        dirty_counts: [usize; CONTEXTS],
    }

    impl BuggyForwardingImpl {
        fn new() -> Self {
            Self {
                current_signal: 0,
                forwarding_signal: 0,
                signal_values: [0, 10, 20],
                wrapper_subscribers: [false; CONTEXTS],
                dirty_counts: [0; CONTEXTS],
            }
        }

        fn read(&mut self, context: usize) -> i32 {
            self.forwarding_signal = self.current_signal;
            self.wrapper_subscribers[context] = true;
            self.peek()
        }

        fn subscribe(&mut self, context: usize) {
            self.forwarding_signal = self.current_signal;
            self.wrapper_subscribers[context] = true;
        }

        fn reset(&mut self, context: usize) {
            self.wrapper_subscribers[context] = false;
        }

        fn point_to(&mut self, signal: usize) {
            self.current_signal = signal;
            // Bug: retargeting should also clear/repoint forwarding state.
        }

        fn write(&mut self, signal: usize) {
            self.signal_values[signal] += 1;
            if signal == self.forwarding_signal {
                for context in 0..CONTEXTS {
                    if self.wrapper_subscribers[context] {
                        self.dirty_counts[context] += 1;
                    }
                }
            }
        }

        fn peek(&self) -> i32 {
            self.signal_values[self.current_signal]
        }
    }

    #[derive(Debug, Clone)]
    struct ForwardingHarness {
        model: ForwardingModel,
        implementation: BuggyForwardingImpl,
    }

    impl ForwardingHarness {
        fn new() -> Self {
            Self {
                model: ForwardingModel::new(),
                implementation: BuggyForwardingImpl::new(),
            }
        }
    }

    fn apply_forwarding_step(
        state: &mut ForwardingHarness,
        step: Step<'_, Op>,
    ) -> Result<(), String> {
        let index = step.index;
        let op = *step.op;

        match op {
            Op::Read(context) => {
                let expected = state.model.read(context);
                let actual = state.implementation.read(context);
                if actual != expected {
                    return Err(format!(
                        "step {index}, op {op:?}: read {actual}, expected {expected}"
                    ));
                }
            }
            Op::Subscribe(context) => {
                state.model.subscribe(context);
                state.implementation.subscribe(context);
            }
            Op::Reset(context) => {
                state.model.reset(context);
                state.implementation.reset(context);
            }
            Op::PointTo(signal) => {
                state.model.point_to(signal);
                state.implementation.point_to(signal);
            }
            Op::Write(signal) => {
                state.model.write(signal);
                state.implementation.write(signal);
            }
            Op::Peek => {
                let expected = state.model.peek();
                let actual = state.implementation.peek();
                if actual != expected {
                    return Err(format!(
                        "step {index}, op {op:?}: peeked {actual}, expected {expected}"
                    ));
                }
            }
        }

        if state.implementation.dirty_counts != state.model.dirty_counts {
            return Err(format!(
                "step {index}, op {op:?}: dirty {:?}, expected {:?}",
                state.implementation.dirty_counts, state.model.dirty_counts
            ));
        }

        Ok(())
    }

    fn check_forwarding_model(ops: &[Op]) -> Result<(), String> {
        replay_ops(ops, ForwardingHarness::new, apply_forwarding_step)
    }

    fn op_cost(op: &Op) -> u64 {
        match op {
            Op::Peek => 10,
            Op::Reset(_) => 3,
            Op::Read(_) | Op::Subscribe(_) | Op::PointTo(_) | Op::Write(_) => 1,
        }
    }

    #[test]
    fn reducer_removes_unnecessary_mutations() {
        let ops = [
            Op::Peek,
            Op::Read(0),
            Op::PointTo(1),
            Op::Reset(1),
            Op::Write(0),
            Op::Write(1),
        ];

        let minimized = reduce_with_cost(&ops, &op_cost, |candidate| {
            check_forwarding_model(candidate).is_err()
        });

        assert_eq!(minimized, [Op::Read(0), Op::PointTo(1), Op::Write(1)]);
    }

    #[test]
    fn reducer_accepts_user_provided_transforms() {
        let ops = [Op::Read(2), Op::Write(2)];

        let minimized = reduce_with_cost_and_transforms(
            &ops,
            &|op: &Op| match op {
                Op::Read(index) | Op::Write(index) => 1 + *index as u64,
                _ => 10,
            },
            |candidate| matches!(candidate, [Op::Read(a), Op::Write(b)] if a == b),
            |candidate: &[Op], emit: &mut dyn FnMut(Vec<Op>)| {
                if matches!(candidate, [Op::Read(a), Op::Write(b)] if a == b && *a != 0) {
                    emit(vec![Op::Read(0), Op::Write(0)]);
                }
            },
        );

        assert_eq!(minimized, [Op::Read(0), Op::Write(0)]);
    }

    #[test]
    fn coverage_delta_tracks_new_ids() {
        let mut global = CoverageSet::new();
        global.insert(CoverageId(1));

        let mut candidate = CoverageSet::new();
        candidate.insert(CoverageId(1));
        candidate.insert(CoverageId(2));

        let delta = coverage_delta(&global, &candidate);
        assert_eq!(delta.iter().collect::<Vec<_>>(), [CoverageId(2)]);
        assert!(is_coverage_interesting(&global, &candidate, false));
        assert!(is_coverage_interesting(&global, &global, true));
        assert!(!is_coverage_interesting(&global, &global, false));
    }

    #[test]
    fn reducer_preserves_arbitrary_predicate_with_transforms() {
        let ops = [Op::Read(2), Op::Write(2)];

        let minimized = reduce_preserving_with_transforms(
            &ops,
            &|op: &Op| match op {
                Op::Read(index) | Op::Write(index) => 1 + *index as u64,
                _ => 10,
            },
            |candidate| matches!(candidate, [Op::Read(a), Op::Write(b)] if a == b),
            |candidate: &[Op], emit: &mut dyn FnMut(Vec<Op>)| {
                if matches!(candidate, [Op::Read(a), Op::Write(b)] if a == b && *a != 0) {
                    emit(vec![Op::Read(0), Op::Write(0)]);
                }
            },
        );

        assert_eq!(minimized, [Op::Read(0), Op::Write(0)]);
    }

    #[test]
    fn lazy_case_regenerates_same_ops() {
        let case = Fuzzer::sequences::<Op, _>(StandardUniform)
            .base_seed(123)
            .seeds(1)
            .steps(5)
            .into_iter()
            .next()
            .expect("one case requested");

        assert_eq!(case.steps, 5);
        let first = case.ops();
        let second = case.ops();
        assert_eq!(
            first, second,
            "ops() must be deterministic for the same seed"
        );
        assert_eq!(first.len(), 5);

        let streamed: Vec<Op> = case.iter_ops().collect();
        assert_eq!(streamed, first);
    }

    #[test]
    fn iterator_driven_failure_minimizes() {
        let mut minimized: Option<Vec<Op>> = None;

        for case in Fuzzer::sequences(StandardUniform)
            .base_seed(7)
            .seeds(128)
            .steps(64)
        {
            if case
                .replay(ForwardingHarness::new, apply_forwarding_step)
                .is_err()
            {
                let ops = case.ops();
                let reduced = reduce_with_cost(&ops, &op_cost, |candidate| {
                    replay_ops(candidate, ForwardingHarness::new, apply_forwarding_step).is_err()
                });
                minimized = Some(reduced);
                break;
            }
        }

        let minimized = minimized.expect("the stale model should fail within these seeds");
        assert!(!minimized.is_empty());
        assert!(check_forwarding_model(&minimized).is_err());
    }

    #[test]
    fn check_yields_one_per_case_in_order() {
        let base_seed = 100;
        let seeds: u64 = 5;
        let steps = 8;

        let checked: Vec<_> = Fuzzer::sequences(StandardUniform)
            .base_seed(base_seed)
            .seeds(seeds)
            .steps(steps)
            .check(|| (), |_: &mut (), _: Step<'_, Op>| Ok(()))
            .collect();

        assert_eq!(checked.len() as u64, seeds);
        for (i, c) in checked.iter().enumerate() {
            assert_eq!(c.case.seed, base_seed + i as u64);
            assert_eq!(c.case.steps, steps);
            assert!(c.outcome.is_ok());
        }
    }

    #[test]
    fn failures_filters_to_failing_cases() {
        let failures: Vec<_> = Fuzzer::sequences(StandardUniform)
            .base_seed(7)
            .seeds(128)
            .steps(64)
            .failures(ForwardingHarness::new, apply_forwarding_step)
            .collect();

        assert!(
            !failures.is_empty(),
            "the stale model should fail within these seeds"
        );
        for failed in &failures {
            assert!(!failed.error.is_empty());
            assert!(check_forwarding_model(&failed.ops).is_err());
        }
    }

    #[test]
    fn minimize_produces_smaller_failing_repro() {
        let minimized = Fuzzer::sequences(StandardUniform)
            .base_seed(7)
            .seeds(128)
            .steps(64)
            .failures(ForwardingHarness::new, apply_forwarding_step)
            .minimize(op_cost)
            .next()
            .expect("the stale model should fail within these seeds");

        assert!(minimized.minimized_ops.len() <= minimized.ops.len());
        assert!(!minimized.minimized_ops.is_empty());
        assert!(check_forwarding_model(&minimized.minimized_ops).is_err());
        assert_eq!(minimized.minimized_error, {
            replay_ops(
                &minimized.minimized_ops,
                ForwardingHarness::new,
                apply_forwarding_step,
            )
            .unwrap_err()
        });
    }

    #[test]
    fn pipeline_is_lazy() {
        let mut produced = 0usize;
        let one = Fuzzer::sequences(StandardUniform)
            .base_seed(7)
            .seeds(10_000)
            .steps(64)
            .into_iter()
            .inspect(|_| produced += 1)
            .failures(ForwardingHarness::new, apply_forwarding_step)
            .minimize(op_cost)
            .next();

        assert!(one.is_some(), "expected at least one failure");
        assert!(
            produced < 10_000,
            "pipeline materialized {produced} cases; should short-circuit far earlier"
        );
    }

    #[test]
    fn check_to_failures_threads_closures() {
        let via_check: Vec<_> = Fuzzer::sequences(StandardUniform)
            .base_seed(7)
            .seeds(32)
            .steps(64)
            .check(ForwardingHarness::new, apply_forwarding_step)
            .failures()
            .map(|f| (f.seed, f.error))
            .collect();

        let direct: Vec<_> = Fuzzer::sequences(StandardUniform)
            .base_seed(7)
            .seeds(32)
            .steps(64)
            .failures(ForwardingHarness::new, apply_forwarding_step)
            .map(|f| (f.seed, f.error))
            .collect();

        assert_eq!(via_check, direct);
        assert!(!via_check.is_empty());
    }

    #[test]
    fn coverage_guided_yields_new_coverage() {
        let accepted: Vec<_> = Fuzzer::sequences(StandardUniform)
            .base_seed(0)
            .seeds(32)
            .steps(8)
            .coverage_guided(|ops: &[Op]| {
                let mut coverage = CoverageSet::new();
                for op in ops {
                    let id = match op {
                        Op::Read(_) => 1,
                        Op::Subscribe(_) => 2,
                        Op::Reset(_) => 3,
                        Op::PointTo(_) => 4,
                        Op::Write(_) => 5,
                        Op::Peek => 6,
                    };
                    coverage.insert(CoverageId(id));
                }
                CoverageEvaluation::pass(coverage)
            })
            .take(6)
            .collect();

        assert!(!accepted.is_empty());
        let mut seen = CoverageSet::new();
        for case in accepted {
            assert!(!case.unique_coverage.is_empty());
            assert!(case.unique_coverage.is_subset(&case.coverage));
            for id in case.unique_coverage.iter() {
                assert!(!seen.contains(&id));
            }
            seen.extend(case.coverage.iter());
        }
    }

    #[test]
    fn coverage_guided_evaluates_initial_cases_before_generated_seeds() {
        let mut explorer = Fuzzer::sequences(StandardUniform)
            .base_seed(0)
            .seeds(1)
            .steps(1)
            .coverage_guided(|ops: &[Op]| {
                let mut coverage = CoverageSet::new();
                coverage.insert(CoverageId(ops.len() as u64));
                CoverageEvaluation::pass(coverage)
            })
            .initial_cases(vec![vec![Op::Peek], vec![Op::Read(0), Op::Write(0)]]);

        let accepted: Vec<_> = (&mut explorer).take(2).collect();

        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted[0].ops, vec![Op::Peek]);
        assert_eq!(accepted[1].ops, vec![Op::Read(0), Op::Write(0)]);
        assert_eq!(accepted[0].seed, None);
        assert_eq!(accepted[1].seed, None);
        assert_eq!(accepted[0].parent, None);
        assert_eq!(accepted[1].parent, None);
        assert_eq!(explorer.stats().generated, 2);
    }

    #[test]
    fn coverage_guided_mutates_accepted_cases() {
        let accepted: Vec<_> = Fuzzer::sequences(StandardUniform)
            .base_seed(0)
            .seeds(1)
            .steps(1)
            .coverage_guided(|ops: &[Op]| {
                let mut coverage = CoverageSet::new();
                coverage.insert(CoverageId(ops.len() as u64));
                CoverageEvaluation::pass(coverage)
            })
            .mutate(|ops: &[Op], emit: &mut dyn FnMut(Vec<Op>)| {
                let mut candidate = ops.to_vec();
                candidate.push(Op::Peek);
                emit(candidate);
            })
            .rounds(1)
            .mutations_per_entry(1)
            .take(2)
            .collect();

        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted[1].parent, Some(accepted[0].id));
        assert_eq!(accepted[1].depth, 1);
    }

    #[test]
    fn coverage_guided_returns_to_seed_stream_between_mutations() {
        let mut root_cases = 0u64;
        let accepted: Vec<_> = Fuzzer::sequences(StandardUniform)
            .base_seed(0)
            .seeds(2)
            .steps(1)
            .coverage_guided(move |ops: &[Op]| {
                let mut coverage = CoverageSet::new();
                if ops.len() == 1 {
                    root_cases += 1;
                    coverage.insert(CoverageId(100 + root_cases));
                } else {
                    coverage.insert(CoverageId(ops.len() as u64));
                }
                CoverageEvaluation::pass(coverage)
            })
            .mutate(|ops: &[Op], emit: &mut dyn FnMut(Vec<Op>)| {
                let mut candidate = ops.to_vec();
                candidate.push(Op::Peek);
                emit(candidate);
            })
            .rounds(4)
            .mutations_per_entry(1)
            .max_shrink_steps(0)
            .take(3)
            .collect();

        assert_eq!(accepted.len(), 3);
        assert_eq!(accepted[0].seed, Some(0));
        assert_eq!(accepted[1].parent, Some(accepted[0].id));
        assert_eq!(accepted[2].seed, Some(1));
    }

    #[test]
    fn coverage_guided_prioritizes_queued_mutations() {
        let mut explorer = CoverageGuided::new(
            std::iter::empty::<GeneratedCase<Op, StandardUniform>>(),
            |_: &[Op]| CoverageEvaluation::pass(CoverageSet::new()),
        );

        explorer.pending.push_back(PendingCoverageCase {
            ops: vec![Op::Peek],
            seed: None,
            parent: Some(1),
            depth: 1,
            priority: 10,
            order: 0,
        });
        explorer.pending.push_back(PendingCoverageCase {
            ops: vec![Op::Peek],
            seed: None,
            parent: Some(2),
            depth: 1,
            priority: 50,
            order: 1,
        });
        explorer.pending.push_back(PendingCoverageCase {
            ops: vec![Op::Peek],
            seed: None,
            parent: Some(3),
            depth: 1,
            priority: 50,
            order: 2,
        });

        let first = explorer.pop_scheduled_pending().expect("queued case");
        assert_eq!(first.parent, Some(2));

        let second = explorer.pop_scheduled_pending().expect("queued case");
        assert_eq!(second.parent, Some(3));
    }

    #[test]
    fn coverage_guided_scores_rare_coverage_higher() {
        let mut explorer = CoverageGuided::new(
            std::iter::empty::<GeneratedCase<Op, StandardUniform>>(),
            |_: &[Op]| CoverageEvaluation::pass(CoverageSet::new()),
        );
        explorer.coverage_frequency.insert(CoverageId(1), 20);
        explorer.coverage_frequency.insert(CoverageId(2), 1);

        let common = CoveredCase {
            id: 0,
            seed: Some(0),
            parent: None,
            depth: 0,
            ops: vec![Op::Peek],
            coverage: [CoverageId(1)].into_iter().collect(),
            unique_coverage: CoverageSet::new(),
            outcome: Ok(()),
            cost: 1,
            len: 1,
        };
        let rare = CoveredCase {
            id: 1,
            seed: Some(1),
            parent: None,
            depth: 0,
            ops: vec![Op::Peek],
            coverage: [CoverageId(2)].into_iter().collect(),
            unique_coverage: CoverageSet::new(),
            outcome: Ok(()),
            cost: 1,
            len: 1,
        };

        assert!(explorer.mutation_priority(&rare) > explorer.mutation_priority(&common));
    }

    #[cfg(feature = "rayon")]
    mod parallel_tests {
        use super::*;
        use crate::parallel::ParCaseIteratorExt;
        use rayon::iter::ParallelIterator;

        #[test]
        fn par_finds_a_failure() {
            let bug = Fuzzer::sequences(StandardUniform)
                .base_seed(7)
                .seeds(128)
                .steps(64)
                .par()
                .minimized_failures(ForwardingHarness::new, apply_forwarding_step, op_cost)
                .find_any(|_| true)
                .expect("the stale model should fail within these seeds");

            assert!(bug.minimized_ops.len() <= bug.ops.len());
            assert!(!bug.minimized_ops.is_empty());
            assert!(check_forwarding_model(&bug.minimized_ops).is_err());
        }

        #[test]
        fn par_failures_set_matches_serial() {
            let serial: std::collections::BTreeSet<u64> = Fuzzer::sequences(StandardUniform)
                .base_seed(7)
                .seeds(64)
                .steps(64)
                .failures(ForwardingHarness::new, apply_forwarding_step)
                .map(|f| f.seed)
                .collect();

            let parallel: std::collections::BTreeSet<u64> = Fuzzer::sequences(StandardUniform)
                .base_seed(7)
                .seeds(64)
                .steps(64)
                .par()
                .failures(ForwardingHarness::new, apply_forwarding_step)
                .map(|f| f.seed)
                .collect();

            assert!(!serial.is_empty());
            assert_eq!(serial, parallel);
        }
    }
}
