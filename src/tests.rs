use crate::*;
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
struct TestCapture {
    next_id: u64,
    fail_finish: bool,
}

impl TestCapture {
    fn new() -> Self {
        Self {
            next_id: 1,
            fail_finish: false,
        }
    }

    fn failing() -> Self {
        Self {
            next_id: 1,
            fail_finish: true,
        }
    }
}

impl CoverageCapture for TestCapture {
    type Token = u64;

    fn start_capture(&mut self) -> Result<Self::Token, String> {
        let id = self.next_id;
        self.next_id += 1;
        Ok(id)
    }

    fn finish_capture(
        &mut self,
        token: Self::Token,
        outcome: Result<(), String>,
    ) -> Result<CoverageEvaluation, String> {
        if self.fail_finish {
            return Err("coverage failed".to_string());
        }
        Ok(CoverageEvaluation::from_outcome(
            outcome,
            [CoverageId(token)].into_iter().collect(),
        ))
    }
}

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
fn materialize_cases_preserves_seed_and_ops() {
    let case: InputCase<Op> = Fuzzer::sequences(StandardUniform)
        .base_seed(42)
        .seeds(1)
        .steps(4)
        .materialize_cases()
        .next()
        .expect("one materialized case");

    assert_eq!(case.seed, Some(42));
    assert_eq!(case.parent, None);
    assert_eq!(case.depth, 0);
    assert_eq!(case.ops.len(), 4);
}

#[test]
fn measure_coverage_yields_measured_cases_in_order() {
    let measured: Vec<_> = Fuzzer::sequences(StandardUniform)
        .base_seed(10)
        .seeds(2)
        .steps(1)
        .materialize_cases()
        .measure_coverage(|ops: &[Op]| {
            let mut coverage = CoverageSet::new();
            coverage.insert(CoverageId(ops.len() as u64));
            Ok(CoverageEvaluation::pass(coverage))
        })
        .collect::<Result<_, _>>()
        .expect("coverage evaluation should pass");

    assert_eq!(measured.len(), 2);
    assert_eq!(measured[0].case.seed, Some(10));
    assert_eq!(measured[1].case.seed, Some(11));
    assert_eq!(measured[0].evaluation.coverage.len(), 1);
}

#[test]
fn maximize_coverage_filters_duplicates_and_accepts_failures() {
    let cases = vec![
        Ok(MeasuredCase {
            case: CoverageCase::root(Some(0), vec![Op::Peek]),
            evaluation: CoverageEvaluation::pass([CoverageId(1)].into_iter().collect()),
        }),
        Ok(MeasuredCase {
            case: CoverageCase::root(Some(1), vec![Op::Peek]),
            evaluation: CoverageEvaluation::pass([CoverageId(1)].into_iter().collect()),
        }),
        Ok(MeasuredCase {
            case: CoverageCase::root(Some(2), vec![Op::Peek]),
            evaluation: CoverageEvaluation::fail("boom", CoverageSet::new()),
        }),
    ];

    let accepted: Vec<_> = cases
        .into_iter()
        .maximize_coverage()
        .collect::<Result<_, _>>()
        .expect("maximizer should not error");

    assert_eq!(accepted.len(), 2);
    assert_eq!(accepted[0].seed, Some(0));
    assert_eq!(accepted[0].unique_coverage.len(), 1);
    assert_eq!(accepted[1].seed, Some(2));
    assert!(accepted[1].is_failure());
}

#[test]
fn coverage_guided_reports_measurement_errors() {
    let mut explorer = Fuzzer::sequences(StandardUniform)
        .base_seed(0)
        .seeds(1)
        .steps(1)
        .materialize::<Op>()
        .explore_coverage(TestCapture::failing());

    let case = explorer
        .next()
        .expect("one generated case")
        .expect("case should start");
    let error = case.finish().expect_err("measurement should fail");

    assert_eq!(error, "coverage failed");
    assert_eq!(explorer.stats().executed, 1);
    assert_eq!(explorer.stats().errors, 1);
    assert_eq!(explorer.stats().accepted, 0);
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
    let case = Fuzzer::sequences(StandardUniform)
        .base_seed(123)
        .seeds(1)
        .steps(5)
        .into_iter()
        .next()
        .expect("one case requested");

    assert_eq!(case.steps, 5);
    let first: Vec<Op> = case.ops();
    let second: Vec<Op> = case.ops();
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
        .minimized_failures(ForwardingHarness::new, apply_forwarding_step, op_cost)
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
        .minimized_failures(ForwardingHarness::new, apply_forwarding_step, op_cost)
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
        .failures::<Op>()
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
    let mut explorer = Fuzzer::sequences(StandardUniform)
        .base_seed(0)
        .seeds(32)
        .steps(8)
        .materialize::<Op>()
        .explore_coverage(TestCapture::new());

    for _ in 0..6 {
        let case = explorer
            .next()
            .expect("case")
            .expect("coverage case should start");
        case.finish().expect("coverage evaluation should pass");
    }
    let accepted = explorer.corpus();

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
    let roots = vec![
        InputCase::root(None, vec![Op::Peek]),
        InputCase::root(None, vec![Op::Read(0), Op::Write(0)]),
    ];
    let mut explorer = roots
        .into_iter()
        .chain(
            Fuzzer::sequences(StandardUniform)
                .base_seed(0)
                .seeds(1)
                .steps(1)
                .materialize(),
        )
        .explore_coverage(TestCapture::new());

    for _ in 0..2 {
        let case = explorer
            .next()
            .expect("case")
            .expect("coverage case should start");
        case.finish().expect("coverage evaluation should pass");
    }
    let accepted = explorer.corpus();

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
    let mut explorer = Fuzzer::sequences(StandardUniform)
        .base_seed(0)
        .seeds(1)
        .steps(1)
        .materialize::<Op>()
        .explore_coverage(TestCapture::new())
        .mutate(|ops: &[Op], emit: &mut dyn FnMut(Vec<Op>)| {
            let mut candidate = ops.to_vec();
            candidate.push(Op::Peek);
            emit(candidate);
        })
        .rounds(1)
        .mutations_per_entry(1);

    for _ in 0..2 {
        let case = explorer
            .next()
            .expect("case")
            .expect("coverage case should start");
        case.finish().expect("coverage evaluation should pass");
    }
    let accepted = explorer.corpus();

    assert_eq!(accepted.len(), 2);
    assert_eq!(accepted[1].parent, Some(accepted[0].id));
    assert_eq!(accepted[1].depth, 1);
}

#[test]
fn coverage_guided_returns_to_seed_stream_between_mutations() {
    let mut explorer = Fuzzer::sequences(StandardUniform)
        .base_seed(0)
        .seeds(2)
        .steps(1)
        .materialize::<Op>()
        .explore_coverage(TestCapture::new())
        .mutate(|ops: &[Op], emit: &mut dyn FnMut(Vec<Op>)| {
            let mut candidate = ops.to_vec();
            candidate.push(Op::Peek);
            emit(candidate);
        })
        .rounds(4)
        .mutations_per_entry(1);

    for _ in 0..3 {
        let case = explorer
            .next()
            .expect("case")
            .expect("coverage case should start");
        case.finish().expect("coverage evaluation should pass");
    }
    let accepted = explorer.corpus();

    assert_eq!(accepted.len(), 3);
    assert_eq!(accepted[0].seed, Some(0));
    assert_eq!(accepted[1].parent, Some(accepted[0].id));
    assert_eq!(accepted[2].seed, Some(1));
}

#[test]
fn coverage_guided_rejects_overlapping_active_cases() {
    let mut explorer = Fuzzer::sequences(StandardUniform)
        .base_seed(0)
        .seeds(2)
        .steps(1)
        .materialize::<Op>()
        .explore_coverage(TestCapture::new());

    let case = explorer
        .next()
        .expect("case")
        .expect("first case should start");
    let error = match explorer.next().expect("overlap error") {
        Ok(_) => panic!("second case should be rejected while first is alive"),
        Err(error) => error,
    };
    assert!(error.contains("previous case is alive"));
    drop(case);

    let case = explorer
        .next()
        .expect("case after drop")
        .expect("case should start after previous drop");
    case.finish().expect("coverage evaluation should pass");
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
