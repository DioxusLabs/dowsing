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
