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
