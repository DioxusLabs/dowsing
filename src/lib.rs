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
use std::marker::PhantomData;

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
    let mut minimized = ops.to_vec();
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
