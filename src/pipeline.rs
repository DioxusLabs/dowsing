use crate::{
    CostModel, InputCase, SequenceMutator, replay_ops, reduce_with_cost,
    reduce_with_cost_and_transforms,
};
use rand::{Rng, SeedableRng, distr::Distribution, rngs::SmallRng};

pub(crate) struct FuzzConfig {
    pub(crate) base_seed: u64,
    pub(crate) seeds: u64,
    pub(crate) steps: usize,
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
    pub(crate) index: usize,
    pub(crate) op: &'a Op,
}

impl<'a, Op> Step<'a, Op> {
    /// Index of this operation in the replayed sequence.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Operation being applied.
    pub fn op(&self) -> &'a Op {
        self.op
    }
}

/// A generated operation sequence for a single seed.
///
/// The case is lazy: it carries only the `seed`, the number of `steps`, and a clone of the
/// sampling distribution. Ops are regenerated deterministically each time you ask for them, so
/// passing cases never allocate a `Vec<Op>`. The op type is determined by the caller's
/// `Distribution<Op>` impl when ops are produced — `GeneratedCase` itself does not carry it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedCase<Dist> {
    pub(crate) seed: u64,
    pub(crate) steps: usize,
    pub(crate) distribution: Dist,
}

impl<Dist> GeneratedCase<Dist> {
    /// Seed used to deterministically derive the op stream.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Number of ops this case contains.
    pub fn steps(&self) -> usize {
        self.steps
    }

    /// Materialize this case's full op list as a `Vec<Op>`. Allocates `steps` items.
    pub fn ops<Op>(&self) -> Vec<Op>
    where
        Dist: Distribution<Op>,
    {
        self.iter_ops().collect()
    }

    /// Stream ops lazily without allocating a `Vec`. Each call re-seeds from `seed`.
    pub fn iter_ops<Op>(&self) -> impl ExactSizeIterator<Item = Op> + '_
    where
        Dist: Distribution<Op>,
    {
        let mut rng = SmallRng::seed_from_u64(self.seed);
        let dist = &self.distribution;
        (0..self.steps).map(move |_| rng.sample(dist))
    }

    /// Replay this case lazily: stream ops through `step` (no `Vec` allocation), returning the
    /// first `Err`.
    pub fn replay<Op, State, Init, Fold>(
        &self,
        mut init: Init,
        mut step: Fold,
    ) -> Result<(), String>
    where
        Dist: Distribution<Op>,
        Init: FnMut() -> State,
        Fold: for<'a> FnMut(&mut State, Step<'a, Op>) -> Result<(), String>,
    {
        let mut state = init();
        let mut rng = SmallRng::seed_from_u64(self.seed);
        for index in 0..self.steps {
            let op: Op = rng.sample(&self.distribution);
            step(&mut state, Step { index, op: &op })?;
        }
        Ok(())
    }
}

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
    pub fn sequences<Dist>(distribution: Dist) -> SequencesBuilder<Dist> {
        SequencesBuilder {
            config: FuzzConfig::default(),
            distribution,
        }
    }
}

/// Builder for [`Fuzzer::sequences`].
pub struct SequencesBuilder<Dist> {
    pub(crate) config: FuzzConfig,
    pub(crate) distribution: Dist,
}

impl<Dist> SequencesBuilder<Dist> {
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

impl<Dist: Clone> IntoIterator for SequencesBuilder<Dist> {
    type Item = GeneratedCase<Dist>;
    type IntoIter = Sequences<Dist>;

    fn into_iter(self) -> Self::IntoIter {
        Sequences {
            config: self.config,
            distribution: self.distribution,
            next_offset: 0,
        }
    }
}

/// Iterator that yields one lazy [`GeneratedCase`] per seed.
pub struct Sequences<Dist> {
    config: FuzzConfig,
    distribution: Dist,
    next_offset: u64,
}

impl<Dist: Clone> Iterator for Sequences<Dist> {
    type Item = GeneratedCase<Dist>;

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
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.config.seeds.saturating_sub(self.next_offset) as usize;
        (remaining, Some(remaining))
    }
}

impl<Dist: Clone> ExactSizeIterator for Sequences<Dist> {}

/// Outcome of replaying one [`GeneratedCase`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedCase<Dist> {
    pub(crate) case: GeneratedCase<Dist>,
    pub(crate) outcome: Result<(), String>,
}

impl<Dist> CheckedCase<Dist> {
    /// The generated case that was replayed. Still lazy — ops are not materialized.
    pub fn case(&self) -> &GeneratedCase<Dist> {
        &self.case
    }

    /// `Ok(())` if every step passed, `Err` with the failing step's message otherwise.
    pub fn outcome(&self) -> &Result<(), String> {
        &self.outcome
    }

    /// Returns `true` when `outcome` is `Err`.
    pub fn is_failure(&self) -> bool {
        self.outcome.is_err()
    }

    /// Drop the case if it passed; otherwise materialize its ops and return a [`FailedCase`].
    pub fn into_failure<Op>(self) -> Option<FailedCase<Op>>
    where
        Dist: Distribution<Op>,
    {
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
    pub(crate) seed: u64,
    pub(crate) ops: Vec<Op>,
    pub(crate) error: String,
}

impl<Op> FailedCase<Op> {
    /// Seed that generated the failing ops.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Materialized op list (the same `Vec<Op>` `case.ops()` would have produced).
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    /// Error from the first failing step.
    pub fn error(&self) -> &str {
        &self.error
    }

    /// Consume this failure and return its `(seed, ops, error)` parts.
    pub fn into_parts(self) -> (u64, Vec<Op>, String) {
        (self.seed, self.ops, self.error)
    }
}

/// A failing case plus its reduced reproduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimizedFailure<Op> {
    pub(crate) seed: u64,
    pub(crate) ops: Vec<Op>,
    pub(crate) error: String,
    pub(crate) minimized_ops: Vec<Op>,
    pub(crate) minimized_error: String,
}

impl<Op> MinimizedFailure<Op> {
    /// Seed that generated the original failing operation list.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Full generated operation list for this seed.
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    /// Error from replaying `ops`.
    pub fn error(&self) -> &str {
        &self.error
    }

    /// Smaller or cheaper operation list that still fails.
    pub fn minimized_ops(&self) -> &[Op] {
        &self.minimized_ops
    }

    /// Error from replaying `minimized_ops`.
    pub fn minimized_error(&self) -> &str {
        &self.minimized_error
    }
}

/// Iterator adapters on top of an `Iterator<Item = GeneratedCase<Dist>>`.
///
/// Each stage is optional and the pipeline stays lazy, so `.take(N)`, `.inspect(..)`,
/// `rayon::par_bridge`, etc. all compose with it.
pub trait CaseIteratorExt<Dist>: IntoIterator<Item = GeneratedCase<Dist>> + Sized {
    /// Run replay for every case. Yields one [`CheckedCase`] per generated case (passes included).
    fn check<Op, State, Init, Step>(
        self,
        mut init: Init,
        mut step: Step,
    ) -> impl Iterator<Item = CheckedCase<Dist>>
    where
        Dist: Distribution<Op>,
        Init: FnMut() -> State,
        Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
    {
        self.into_iter().map(move |case| {
            let outcome = case.replay::<Op, _, _, _>(&mut init, &mut step);
            CheckedCase { case, outcome }
        })
    }

    /// Run replay for every case and drop passing ones. Yields one [`FailedCase`] per failure.
    fn failures<Op, State, Init, Step>(
        self,
        mut init: Init,
        mut step: Step,
    ) -> impl Iterator<Item = FailedCase<Op>>
    where
        Dist: Distribution<Op>,
        Init: FnMut() -> State,
        Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
    {
        self.into_iter().filter_map(move |case| {
            match case.replay::<Op, _, _, _>(&mut init, &mut step) {
                Ok(()) => None,
                Err(error) => Some(FailedCase {
                    seed: case.seed,
                    ops: case.ops(),
                    error,
                }),
            }
        })
    }

    /// For each failing case, reduce it to a minimal repro under `cost`.
    fn minimized_failures<Op, State, Init, Step, Cost>(
        self,
        mut init: Init,
        mut step: Step,
        cost: Cost,
    ) -> impl Iterator<Item = MinimizedFailure<Op>>
    where
        Op: Clone,
        Dist: Distribution<Op>,
        Init: FnMut() -> State,
        Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
        Cost: CostModel<Op>,
    {
        self.into_iter().filter_map(move |case| {
            match case.replay::<Op, _, _, _>(&mut init, &mut step) {
                Ok(()) => None,
                Err(error) => {
                    let seed = case.seed;
                    let ops: Vec<Op> = case.ops();
                    let minimized_ops = reduce_with_cost(&ops, &cost, |c| {
                        replay_ops(c, &mut init, &mut step).is_err()
                    });
                    let minimized_error = replay_ops(&minimized_ops, &mut init, &mut step)
                        .expect_err("reducer must preserve the failing invariant");
                    Some(MinimizedFailure {
                        seed,
                        ops,
                        error,
                        minimized_ops,
                        minimized_error,
                    })
                }
            }
        })
    }

    /// For each failing case, reduce it under `cost` and caller-provided transforms.
    ///
    /// Transforms are tried only after the default deletion pass. They must emit valid candidate
    /// operation sequences for the caller's domain.
    fn minimized_failures_with_transforms<Op, State, Init, Step, Cost, Transforms>(
        self,
        mut init: Init,
        mut step: Step,
        cost: Cost,
        mut transforms: Transforms,
    ) -> impl Iterator<Item = MinimizedFailure<Op>>
    where
        Op: Clone,
        Dist: Distribution<Op>,
        Init: FnMut() -> State,
        Step: for<'a> FnMut(&mut State, crate::Step<'a, Op>) -> Result<(), String>,
        Cost: CostModel<Op>,
        Transforms: SequenceMutator<Op>,
    {
        self.into_iter().filter_map(move |case| {
            match case.replay::<Op, _, _, _>(&mut init, &mut step) {
                Ok(()) => None,
                Err(error) => {
                    let seed = case.seed;
                    let ops: Vec<Op> = case.ops();
                    let minimized_ops = reduce_with_cost_and_transforms(
                        &ops,
                        &cost,
                        |c| replay_ops(c, &mut init, &mut step).is_err(),
                        |c: &[Op], emit: &mut dyn FnMut(Vec<Op>)| transforms.mutate(c, emit),
                    );
                    let minimized_error = replay_ops(&minimized_ops, &mut init, &mut step)
                        .expect_err("reducer must preserve the failing invariant");
                    Some(MinimizedFailure {
                        seed,
                        ops,
                        error,
                        minimized_ops,
                        minimized_error,
                    })
                }
            }
        })
    }

    /// Materialize generated cases into operation vectors with coverage metadata fields.
    fn materialize<Op>(self) -> impl Iterator<Item = InputCase<Op>>
    where
        Dist: Distribution<Op>,
    {
        self.into_iter()
            .map(|case| InputCase::root(Some(case.seed), case.ops::<Op>()))
    }

    /// Backwards-compatible name for [`CaseIteratorExt::materialize`].
    fn materialize_cases<Op>(self) -> impl Iterator<Item = InputCase<Op>>
    where
        Dist: Distribution<Op>,
    {
        self.materialize()
    }
}

impl<T, Dist> CaseIteratorExt<Dist> for T where T: IntoIterator<Item = GeneratedCase<Dist>> {}

/// Iterator adapters on top of an `Iterator<Item = CheckedCase<Dist>>`.
pub trait CheckedCaseIteratorExt<Dist>: Iterator<Item = CheckedCase<Dist>> + Sized {
    /// Drop passing cases; keep failures only.
    fn failures<Op>(self) -> impl Iterator<Item = FailedCase<Op>>
    where
        Dist: Distribution<Op>,
    {
        self.filter_map(CheckedCase::into_failure)
    }
}

impl<I, Dist> CheckedCaseIteratorExt<Dist> for I where I: Iterator<Item = CheckedCase<Dist>> {}
