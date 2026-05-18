use crate::*;
use crate::{
    backends::SancovCoverage,
    coverage::{CoverageCapture, CoverageId, ExecutionFeedback, ParallelCoverageCapture},
};
use rand::{Rng, RngCore};
use std::{
    cell::RefCell,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
};

mod sancov;

#[derive(Debug, Clone)]
struct TestCapture {
    next_id: u64,
}

impl TestCapture {
    fn new() -> Self {
        Self { next_id: 1 }
    }
}

impl CoverageCapture for TestCapture {
    type Token = u64;

    fn start_capture(&mut self) -> Result<Self::Token, String> {
        let id = self.next_id;
        self.next_id += 1;
        Ok(id)
    }

    fn finish_capture(&mut self, token: Self::Token) -> Result<ExecutionFeedback, String> {
        Ok(ExecutionFeedback::from_features(
            [CoverageId::new(token)].into_iter().collect(),
        ))
    }
}

#[derive(Debug, Clone)]
struct ScriptedCapture {
    next_token: usize,
    coverages: Vec<Vec<u64>>,
    hit_count_weights: Vec<u64>,
    dictionary: Vec<Vec<u8>>,
    finished: Rc<RefCell<Vec<usize>>>,
    discarded: Rc<RefCell<Vec<usize>>>,
}

#[derive(Debug)]
struct ParallelScriptedCapture {
    next_instance: std::sync::Arc<std::sync::atomic::AtomicU64>,
    instance: u64,
    finished: std::sync::Arc<std::sync::Mutex<Vec<u64>>>,
}

impl ParallelScriptedCapture {
    fn new() -> Self {
        Self {
            next_instance: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
            instance: 0,
            finished: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn finished(&self) -> std::sync::Arc<std::sync::Mutex<Vec<u64>>> {
        std::sync::Arc::clone(&self.finished)
    }
}

impl Clone for ParallelScriptedCapture {
    fn clone(&self) -> Self {
        Self {
            next_instance: std::sync::Arc::clone(&self.next_instance),
            instance: self
                .next_instance
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            finished: std::sync::Arc::clone(&self.finished),
        }
    }
}

impl CoverageCapture for ParallelScriptedCapture {
    type Token = u64;

    fn start_capture(&mut self) -> Result<Self::Token, String> {
        Ok(self.instance)
    }

    fn finish_capture(&mut self, token: Self::Token) -> Result<ExecutionFeedback, String> {
        self.finished.lock().expect("finished lock").push(token);
        Ok(ExecutionFeedback::from_features(
            [CoverageId::new(token)].into_iter().collect(),
        ))
    }
}

impl ParallelCoverageCapture for ParallelScriptedCapture {}

impl ScriptedCapture {
    fn new(coverages: impl IntoIterator<Item = impl IntoIterator<Item = u64>>) -> Self {
        Self {
            next_token: 0,
            coverages: coverages
                .into_iter()
                .map(|coverage| coverage.into_iter().collect())
                .collect(),
            hit_count_weights: Vec::new(),
            dictionary: Vec::new(),
            finished: Rc::new(RefCell::new(Vec::new())),
            discarded: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn with_hit_count_weights(mut self, weights: impl IntoIterator<Item = u64>) -> Self {
        self.hit_count_weights = weights.into_iter().collect();
        self
    }

    fn with_dictionary(mut self, dictionary: impl IntoIterator<Item = impl Into<Vec<u8>>>) -> Self {
        self.dictionary = dictionary.into_iter().map(Into::into).collect();
        self
    }

    fn finished(&self) -> Rc<RefCell<Vec<usize>>> {
        Rc::clone(&self.finished)
    }

    fn discarded(&self) -> Rc<RefCell<Vec<usize>>> {
        Rc::clone(&self.discarded)
    }
}

impl CoverageCapture for ScriptedCapture {
    type Token = usize;

    fn start_capture(&mut self) -> Result<Self::Token, String> {
        let token = self.next_token;
        self.next_token += 1;
        Ok(token)
    }

    fn finish_capture(&mut self, token: Self::Token) -> Result<ExecutionFeedback, String> {
        self.finished.borrow_mut().push(token);
        let coverage = self
            .coverages
            .get(token)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(CoverageId::new)
            .collect();
        let mut feedback =
            ExecutionFeedback::from_features(coverage).with_dictionary(self.dictionary.clone());
        if let Some(weight) = self.hit_count_weights.get(token) {
            feedback = feedback.with_hit_count_weight(*weight);
        }
        Ok(feedback)
    }

    fn discard_capture(&mut self, token: Self::Token) -> Result<(), String> {
        self.discarded.borrow_mut().push(token);
        Ok(())
    }
}

fn sample_byte(mut rng: impl Rng) -> u8 {
    rng.random()
}

fn assert_byte(_sample: u8) {}

fn fork_case_with_trace_len(len: usize) -> Case {
    let mut runner = curious().with_coverage(ScriptedCapture::new([[1]]));
    let mut rng = runner.next().expect("case source rng");
    let mut bytes = vec![0; len];
    rng.fill_bytes(&mut bytes);
    rng.fork_case()
}

#[test]
fn curious_yields_rng_and_records_on_drop() {
    let mut curious = curious().with_coverage(TestCapture::new());

    {
        let mut rng = curious.next().expect("first rng");
        let _ = rng.random::<u64>();
    }

    let stats = curious.stats();
    assert_eq!(stats.generated(), 1);
    assert_eq!(stats.executed(), 1);
    assert_eq!(stats.accepted(), 1);
    assert_eq!(stats.coverage_ids(), 1);
}

#[test]
fn cautious_accepts_first_seed_then_smaller_code_paths() {
    let case = fork_case_with_trace_len(8);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new([
            vec![1, 2, 3],
            vec![1, 2, 3, 4],
            vec![1, 2],
        ]))
        .with_case(case);

    for _ in 0..3 {
        let mut rng = cautious.next().expect("cautious rng");
        let mut bytes = [0; 8];
        rng.fill_bytes(&mut bytes);
    }

    let stats = cautious.stats();
    assert_eq!(stats.generated(), 3);
    assert_eq!(stats.executed(), 3);
    assert_eq!(stats.accepted(), 3);
    assert_eq!(stats.coverage_ids(), 2);
    assert_eq!(cautious.test_best_path_score(), Some((2, 2, 8)));
}

#[test]
fn fuzzing_style_map_sample_for_each_assert_records_each_iteration() {
    let mut curious = curious().with_coverage(ScriptedCapture::new([[1], [2], [3]]));

    curious
        .by_ref()
        .take(3)
        .map(sample_byte)
        .for_each(assert_byte);

    let stats = curious.stats();
    assert_eq!(stats.generated(), 3);
    assert_eq!(stats.executed(), 3);
    assert_eq!(stats.accepted(), 3);
    assert_eq!(stats.coverage_ids(), 3);
    assert_eq!(stats.mutated(), 2);
}

#[test]
#[allow(clippy::never_loop)]
fn fuzzing_style_assert_panic_still_finishes_capture_in_default_mode() {
    let capture = ScriptedCapture::new([[1]]);
    let finished = capture.finished();

    let result = catch_unwind(AssertUnwindSafe(|| {
        curious()
            .with_coverage(capture)
            .take(1)
            .map(sample_byte)
            .for_each(|_| panic!("invariant failed"));
    }));

    assert!(result.is_err());
    assert_eq!(*finished.borrow(), [0]);
}

#[test]
fn rng_discard_consumes_and_excludes_coverage() {
    let capture = ScriptedCapture::new([[1], [2]]);
    let finished = capture.finished();
    let discarded = capture.discarded();
    let mut curious = curious().with_coverage(capture);

    {
        let rng = curious.next().expect("first rng");
        rng.discard();
    }
    drop(curious.next().expect("second rng"));

    let stats = curious.stats();
    assert_eq!(stats.generated(), 2);
    assert_eq!(stats.executed(), 2);
    assert_eq!(stats.accepted(), 1);
    assert_eq!(*finished.borrow(), [1]);
    assert_eq!(*discarded.borrow(), [0]);
}

#[test]
fn rng_coverage_consumes_and_reports_feature_and_byte_counts() {
    let capture = ScriptedCapture::new([vec![1, 2, 3]]);
    let finished = capture.finished();
    let mut curious = curious().with_coverage(capture);

    let coverage = {
        let mut rng = curious.next().expect("first rng");
        let mut bytes = [0; 5];
        rng.fill_bytes(&mut bytes);
        rng.coverage().expect("finish coverage")
    };

    assert_eq!(coverage.feature_count(), 3);
    assert_eq!(coverage.hit_count_weight(), 3);
    assert_eq!(coverage.bytes_consumed(), 5);
    assert_eq!(*finished.borrow(), [0]);

    let stats = curious.stats();
    assert_eq!(stats.generated(), 1);
    assert_eq!(stats.executed(), 1);
    assert_eq!(stats.accepted(), 1);
    assert_eq!(stats.coverage_ids(), 3);
}

#[test]
fn fork_case_replays_consumed_rng_path() {
    let mut discovery = curious().with_coverage(ScriptedCapture::new([[1]]));
    let (case, original) = {
        let mut rng = discovery.next().expect("discovery rng");
        let bytes = [rng.random::<u8>(), rng.random::<u8>(), rng.random::<u8>()];
        (rng.fork_case(), bytes)
    };

    let mut replay = cautious().with_coverage(NoCoverage).with_case(case);
    let mut rng = replay.next().expect("replay rng");
    let replayed = [rng.random::<u8>(), rng.random::<u8>(), rng.random::<u8>()];

    assert_eq!(replayed, original);
}

#[test]
fn fork_case_replays_consumed_rng_paths_longer_than_mutation_prefix_limit() {
    let len = 5000;
    let mut discovery = curious()
        .with_coverage(ScriptedCapture::new([[1]]))
        .with_seed(99);
    let (case, original) = {
        let mut rng = discovery.next().expect("discovery rng");
        let mut bytes = vec![0; len];
        rng.fill_bytes(&mut bytes);
        (rng.fork_case(), bytes)
    };

    let mut replay = cautious()
        .with_coverage(ScriptedCapture::new([[1]]))
        .with_case(case);
    let replayed = {
        let mut rng = replay.next().expect("cautious replay rng");
        let mut bytes = vec![0; len];
        rng.fill_bytes(&mut bytes);
        bytes
    };

    assert_eq!(replayed, original);
}

#[test]
fn cautious_with_case_replays_word_rng_path() {
    let mut discovery = curious()
        .with_coverage(ScriptedCapture::new([[1]]))
        .with_seed(99);
    let (case, original) = {
        let mut rng = discovery.next().expect("discovery rng");
        let mut bytes = [0; 7];
        rng.fill_bytes(&mut bytes);
        let values = (
            bytes,
            rng.random::<u16>(),
            rng.random::<u32>(),
            rng.random::<u64>(),
            rng.random_range(0..1000u32),
        );
        (rng.fork_case(), values)
    };

    let mut replay = cautious()
        .with_coverage(ScriptedCapture::new([[1]]))
        .with_case(case);
    let replayed = {
        let mut rng = replay.next().expect("cautious replay rng");
        let mut bytes = [0; 7];
        rng.fill_bytes(&mut bytes);
        (
            bytes,
            rng.random::<u16>(),
            rng.random::<u32>(),
            rng.random::<u64>(),
            rng.random_range(0..1000u32),
        )
    };

    assert_eq!(replayed, original);
}

#[test]
fn seeded_cases_run_before_fresh_roots() {
    let mut source = curious()
        .with_seed(123)
        .with_coverage(ScriptedCapture::new([[1]]));
    let (case, seeded_bytes) = {
        let mut rng = source.next().expect("source rng");
        let bytes = [rng.random::<u8>(), rng.random::<u8>()];
        (rng.fork_case(), bytes)
    };
    let fresh_bytes = {
        let mut fresh = curious()
            .with_seed(5)
            .with_coverage(ScriptedCapture::new([[1]]));
        let mut rng = fresh.next().expect("fresh rng");
        [rng.random::<u8>(), rng.random::<u8>()]
    };

    let mut curious = curious()
        .with_seed(5)
        .with_coverage(ScriptedCapture::new([[1], [2]]))
        .with_case(case);

    let first = {
        let mut rng = curious.next().expect("seeded rng");
        let bytes = [rng.random::<u8>(), rng.random::<u8>()];
        rng.discard();
        bytes
    };
    let second = {
        let mut rng = curious.next().expect("fresh rng");
        [rng.random::<u8>(), rng.random::<u8>()]
    };

    assert_eq!(first, seeded_bytes);
    assert_eq!(second, fresh_bytes);
}

#[test]
fn cautious_without_case_yields_no_variants() {
    let mut cautious = cautious().with_coverage(ScriptedCapture::new([[1]]));

    assert!(cautious.next().is_none());
    assert_eq!(cautious.stats().generated(), 0);
}

#[test]
fn fuzzing_style_maximize_accepts_only_new_coverage() {
    let mut curious = curious().with_coverage(ScriptedCapture::new([vec![1], vec![1], vec![1, 2]]));

    curious
        .by_ref()
        .take(3)
        .map(sample_byte)
        .for_each(assert_byte);

    let stats = curious.stats();
    assert_eq!(stats.generated(), 3);
    assert_eq!(stats.executed(), 3);
    assert_eq!(stats.accepted(), 2);
    assert_eq!(stats.coverage_ids(), 2);
    assert_eq!(stats.mutated(), 2);
}

#[test]
fn cautious_accepts_smaller_code_paths() {
    let case = fork_case_with_trace_len(8);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new([
            vec![1, 2, 3],
            vec![1, 2, 3, 4],
            vec![1, 2],
            vec![1],
        ]))
        .with_case(case);

    for mut rng in cautious.by_ref().take(4) {
        let _ = sample_byte(&mut rng);
    }

    let stats = cautious.stats();
    assert_eq!(stats.generated(), 4);
    assert_eq!(stats.executed(), 4);
    assert_eq!(stats.accepted(), 4);
    assert_eq!(stats.coverage_ids(), 1);
    assert_eq!(stats.mutated(), 3);
    assert_eq!(cautious.test_best_path_score(), Some((1, 1, 4)));
}

#[test]
fn cautious_rejects_discarded_smaller_paths() {
    let capture = ScriptedCapture::new([vec![1, 2, 3], vec![1]]);
    let finished = capture.finished();
    let discarded = capture.discarded();
    let case = fork_case_with_trace_len(8);
    let mut cautious = cautious().with_coverage(capture).with_case(case);

    {
        let mut rng = cautious.next().expect("first rng");
        let _ = sample_byte(&mut rng);
    }
    {
        let mut rng = cautious.next().expect("second rng");
        let _ = sample_byte(&mut rng);
        rng.discard();
    }

    let stats = cautious.stats();
    assert_eq!(stats.generated(), 2);
    assert_eq!(stats.executed(), 2);
    assert_eq!(stats.accepted(), 1);
    assert_eq!(stats.coverage_ids(), 3);
    assert_eq!(*finished.borrow(), [0]);
    assert_eq!(*discarded.borrow(), [1]);
}

#[test]
fn cautious_havoc_keeps_generating_byte_variants() {
    let case = fork_case_with_trace_len(4);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new((0..32).map(|_| vec![1])))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("seed rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
    }

    let mut variants = 0;
    for mut rng in cautious.by_ref().take(64) {
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
        rng.discard();
        variants += 1;
    }

    assert_eq!(variants, 64, "cautious should keep producing byte variants");
    let stats = cautious.stats();
    assert_eq!(stats.generated(), variants + 1);
    assert_eq!(stats.executed(), variants + 1);
    assert_eq!(stats.accepted(), 1);
}

#[test]
fn cautious_best_neighbors_try_structural_shrinks_before_byte_budget_is_exhausted() {
    let case = Case::from_raw_parts(0, vec![255; 80], true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new((0..16).map(|_| vec![1])))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("seed rng");
        let mut bytes = [0; 80];
        rng.fill_bytes(&mut bytes);
        rng.coverage().expect("finish seed coverage");
    }

    let mut saw_structural_shrink = false;
    for mut rng in cautious.by_ref().take(8) {
        let mut bytes = [0; 80];
        rng.fill_bytes(&mut bytes);
        saw_structural_shrink |= bytes[79] == 0;
        rng.discard();
    }

    assert!(
        saw_structural_shrink,
        "best-neighbor queue should try prefix deletion/truncation before byte shrinks can exhaust it"
    );
}

#[test]
fn cautious_best_neighbors_try_small_word_targets() {
    let case = Case::from_raw_parts(0, vec![44, 1, 0, 0], true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new((0..64).map(|_| vec![1])))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("seed rng");
        let len = rng.random::<u16>() % 512;
        assert_eq!(len, 300);
        rng.coverage().expect("finish seed coverage");
    }

    let mut found = false;
    for mut rng in cautious.by_ref().take(64) {
        let len = rng.random::<u16>() % 512;
        if len == 11 {
            rng.coverage().expect("finish word-shrunk coverage");
            found = true;
            break;
        }
        rng.discard();
    }

    assert!(
        found,
        "best-neighbor queue should try small little-endian word targets directly"
    );
}

#[test]
fn cautious_entropic_scheduler_raises_energy_for_rare_removed_coverage() {
    let initial = fork_case_with_trace_len(8);
    let smaller = fork_case_with_trace_len(4);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new([vec![1, 2, 3]]))
        .with_case(initial);

    {
        let mut rng = cautious.next().expect("initial failing rng");
        let mut bytes = [0; 8];
        rng.fill_bytes(&mut bytes);
    }

    for _ in 0..64 {
        let mut rng = cautious.next().expect("scheduled variant");
        let mut bytes = [0; 8];
        rng.fill_bytes(&mut bytes);
        rng.discard();
    }

    cautious = cautious.with_case(smaller);
    {
        let mut rng = cautious.next().expect("smaller failing rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
    }

    let energies = cautious.test_corpus_energies();
    assert_eq!(energies.len(), 2);
    assert!(
        energies[1] > energies[0] * 2.0,
        "candidate that removes previously sticky coverage should have higher schedule energy: {energies:?}"
    );
}

#[test]
fn cautious_gives_rare_removed_coverage_more_energy_than_common_removed_coverage() {
    let case = fork_case_with_trace_len(8);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new([
            vec![1, 2, 3, 4],
            vec![1, 2, 3],
            vec![1, 2, 3],
            vec![1, 2, 3],
            vec![1, 3, 4],
        ]))
        .with_case(case);

    for _ in 0..5 {
        let mut rng = cautious.next().expect("cautious rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
    }

    let energies = cautious.test_corpus_energies();
    assert_eq!(energies.len(), 5);
    assert!(
        energies[4] > energies[3] * 2.0,
        "rare removed feature should have more energy than repeatedly removed feature: {energies:?}"
    );
}

#[test]
fn cautious_minimizes_feature_count_before_rng_bytes() {
    let case = fork_case_with_trace_len(8);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new([vec![1, 2], vec![1, 2, 3]]))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("first rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
    }
    {
        let mut rng = cautious.next().expect("second rng");
        let mut bytes = [0; 1];
        rng.fill_bytes(&mut bytes);
    }

    let stats = cautious.stats();
    assert_eq!(stats.generated(), 2);
    assert_eq!(stats.executed(), 2);
    assert_eq!(stats.accepted(), 2);
    assert_eq!(cautious.test_best_path_score(), Some((2, 2, 4)));
    assert_eq!(cautious.test_corpus_path_lens(), [4, 1]);
}

#[test]
fn cautious_minimizes_case_cost_before_coverage_features() {
    let larger_coverage = Case::from_raw_parts(0, vec![1, 2, 3, 4], true);
    let smaller_coverage = Case::from_raw_parts(0, vec![1], true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new([vec![1, 2, 3], vec![1]]))
        .with_cases([larger_coverage, smaller_coverage]);

    {
        let mut rng = cautious.next().expect("first rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
        let coverage = rng.coverage_with_cost(1).expect("finish first case");
        assert_eq!(coverage.case_cost(), 1.into());
    }
    {
        let mut rng = cautious.next().expect("second rng");
        let mut bytes = [0; 1];
        rng.fill_bytes(&mut bytes);
        rng.coverage_with_cost(2).expect("finish second case");
    }

    assert_eq!(cautious.test_best_case_cost(), Some(1.into()));
    assert_eq!(cautious.test_best_path_score(), Some((3, 3, 4)));
}

#[test]
fn case_cost_orders_lower_values_first() {
    assert!(CaseCost::from(2) < CaseCost::from(3));
}

#[test]
fn cautious_minimizes_hit_count_weight_before_rng_bytes() {
    let first = Case::from_raw_parts(0, vec![1], true);
    let second = Case::from_raw_parts(0, vec![1, 2, 3, 4], true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new([vec![1], vec![1]]).with_hit_count_weights([10, 1]))
        .with_case(first)
        .with_case(second);

    {
        let mut rng = cautious.next().expect("first rng");
        let mut bytes = [0; 1];
        rng.fill_bytes(&mut bytes);
    }
    {
        let mut rng = cautious.next().expect("second rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
    }

    let stats = cautious.stats();
    assert_eq!(stats.generated(), 2);
    assert_eq!(stats.executed(), 2);
    assert_eq!(stats.accepted(), 2);
    assert_eq!(cautious.test_best_path_score(), Some((1, 1, 4)));
}

#[test]
fn cautious_uses_rng_bytes_as_feature_count_tie_breaker() {
    let case = fork_case_with_trace_len(8);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new([vec![1], vec![1]]))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("first rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
    }
    {
        let mut rng = cautious.next().expect("second rng");
        let mut bytes = [0; 2];
        rng.fill_bytes(&mut bytes);
    }

    let stats = cautious.stats();
    assert_eq!(stats.generated(), 2);
    assert_eq!(stats.executed(), 2);
    assert_eq!(stats.accepted(), 2);
    assert_eq!(cautious.test_best_path_score(), Some((1, 1, 2)));
    assert_eq!(cautious.test_corpus_path_lens(), [4, 2]);
}

#[test]
fn cautious_promotes_equal_length_simpler_rng_traces() {
    let case = Case::from_raw_parts(0, vec![255; 32], true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new([vec![1], vec![1]]))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("initial failing rng");
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        rng.coverage().expect("finish initial case");
    }
    {
        let mut rng = cautious.next().expect("same-length simpler rng");
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        rng.coverage().expect("finish simpler case");
    }

    assert_eq!(cautious.test_best_path_score(), Some((1, 1, 32)));
    assert!(
        cautious
            .test_best_nonzero_bytes()
            .is_some_and(|count| count < 32),
        "equal public score variants with simpler traces should become the cautious shrink frontier"
    );
}

#[test]
fn cautious_draw_spans_prioritize_length_like_first_draw() {
    let mut prefix = 200_u32.to_le_bytes().to_vec();
    prefix.extend(std::iter::repeat_n(255, 32));
    let draws = (0..9).map(|index| (index * 4, 4, true));
    let case = Case::from_raw_parts_with_draws(0, prefix, true, draws);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new((0..8).map(|_| vec![1])))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("seed rng");
        assert_eq!(rng.next_u32(), 200);
        rng.coverage().expect("finish seed coverage");
    }

    let mut observed = Vec::new();
    for mut rng in cautious.by_ref().take(4) {
        observed.push(rng.next_u32());
        rng.discard();
    }

    assert_eq!(
        observed,
        [0, 1, 2, 3],
        "draw-aware cautious shrinking should try small length-like values before generic byte havoc"
    );
}

#[test]
fn cautious_discard_updates_reducer_feedback_and_keeps_shrinking() {
    let case = Case::from_raw_parts(0, vec![10, 11, 12, 13], true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new((0..16).map(|_| vec![1])))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("seed rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
        rng.coverage().expect("finish seed coverage");
    }

    let first_reduction = {
        let mut rng = cautious.next().expect("first reduction");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
        rng.discard();
        bytes
    };
    let (rejects, _, pressure, _) = cautious.test_reducer_feedback();
    assert_eq!(rejects, 1);
    assert!(pressure.iter().any(|value| *value > 1));

    let second_reduction = {
        let mut rng = cautious.next().expect("second reduction");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
        rng.discard();
        bytes
    };

    assert_eq!(first_reduction, [0, 0, 0, 0]);
    assert_ne!(second_reduction, first_reduction);
}

#[test]
fn cautious_shortlex_promotes_equal_score_lexicographically_smaller_trace() {
    let larger = Case::from_raw_parts(0, vec![2], true);
    let smaller = Case::from_raw_parts(0, vec![1], true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new([vec![1], vec![1]]))
        .with_cases([larger, smaller]);

    for _ in 0..2 {
        let mut rng = cautious.next().expect("seeded rng");
        let mut byte = [0];
        rng.fill_bytes(&mut byte);
        rng.coverage().expect("finish seeded coverage");
    }

    assert_eq!(cautious.test_best_path_score(), Some((1, 1, 1)));
    assert_eq!(cautious.test_best_nonzero_bytes(), Some(1));
    assert_eq!(cautious.test_best_prefix(), Some(vec![1]));
}

#[test]
fn cautious_block_zero_pass_can_zero_whole_trace() {
    let case = Case::from_raw_parts(0, vec![5, 6, 7, 8], true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new((0..128).map(|_| vec![1])))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("seed rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
        rng.coverage().expect("finish seed coverage");
    }

    let mut found_zero_block = false;
    for mut rng in cautious.by_ref().take(128) {
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
        if bytes == [0, 0, 0, 0] {
            rng.coverage().expect("finish zero block candidate");
            found_zero_block = true;
            break;
        }
        rng.discard();
    }

    assert!(found_zero_block);
}

#[test]
fn cautious_dictionary_repair_pass_uses_feedback_dictionary() {
    let case = Case::from_raw_parts(0, vec![9, 9, 9], true);
    let mut cautious = cautious()
        .with_coverage(
            ScriptedCapture::new((0..512).map(|_| vec![1])).with_dictionary([vec![7, 0, 7]]),
        )
        .with_case(case);

    {
        let mut rng = cautious.next().expect("seed rng");
        let mut bytes = [0; 3];
        rng.fill_bytes(&mut bytes);
        rng.coverage().expect("finish seed coverage");
    }

    let mut found_dictionary_repair = false;
    for mut rng in cautious.by_ref().take(512) {
        let mut bytes = [0; 3];
        rng.fill_bytes(&mut bytes);
        if bytes == [7, 0, 7] {
            rng.coverage().expect("finish dictionary repair candidate");
            found_dictionary_repair = true;
            break;
        }
        rng.discard();
    }

    assert!(found_dictionary_repair);
}

fn sample_modulo_len_payload(rng: &mut impl Rng) -> usize {
    let len = (rng.random::<u16>() % 64) as usize;
    let mut payload = vec![0; len];
    rng.fill_bytes(&mut payload);
    len
}

fn sample_range_len_payload<Capture: CoverageCapture>(rng: &mut CaseRng<Capture>) -> usize {
    rng.range(0..64)
        .map(|mut item| {
            let _ = item.random::<u8>();
        })
        .count()
}

fn sample_byte_sequence<Capture: CoverageCapture>(rng: &mut CaseRng<Capture>) -> Vec<u8> {
    rng.range(0..8)
        .map(|mut item| {
            let mut byte = [0];
            item.fill_bytes(&mut byte);
            byte[0]
        })
        .collect()
}

#[test]
fn range_yields_rng_like_children() {
    let mut cases = curious().with_coverage(NoCoverage);
    let mut rng = cases.next().expect("case rng");
    let values = {
        let mut items = rng.range(1..=3);
        let mut values = Vec::new();
        while let Some(mut item) = items.next() {
            values.push((item.random_range(0..4), item.random::<u8>()));
        }
        values
    };

    assert!((1..=3).contains(&values.len()));
    rng.discard();
}

#[test]
fn cautious_minimizes_word_modulo_length_prefix() {
    let mut prefix = vec![63, 0, 0, 0];
    prefix.extend(std::iter::repeat_n(0, 63));
    let case = Case::from_raw_parts(0, prefix, true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new((0..128).map(|_| vec![1])))
        .with_case(case);

    let mut best_len = usize::MAX;
    for _ in 0..128 {
        let Some(mut rng) = cautious.next() else {
            break;
        };
        let len = sample_modulo_len_payload(&mut rng);
        if len == 0 {
            rng.discard();
            continue;
        }

        rng.coverage().expect("finish cautious modulo candidate");
        best_len = best_len.min(len);
    }

    assert_eq!(best_len, 1);
}

#[test]
fn cautious_uses_range_length_before_generic_byte_shrinks() {
    let mut prefix = 20_u32.to_le_bytes().to_vec();
    prefix.extend(std::iter::repeat_n(255, 20));
    let case = Case::from_raw_parts(0, prefix, true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new((0..4).map(|_| vec![1])))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("seed rng");
        assert_eq!(sample_range_len_payload(&mut rng), 20);
        rng.coverage().expect("finish seed coverage");
    }

    let mut rng = cautious.next().expect("range length reduction");
    assert_eq!(sample_range_len_payload(&mut rng), 0);
    rng.discard();
}

#[test]
fn cautious_sequence_delete_lowers_length_and_removes_item_bytes() {
    let mut prefix = 3_u32.to_le_bytes().to_vec();
    prefix.extend([10, 20, 30]);
    let case = Case::from_raw_parts(0, prefix, true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new((0..4).map(|_| vec![1])))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("seed rng");
        assert_eq!(sample_byte_sequence(&mut rng), [10, 20, 30]);
        rng.coverage().expect("finish seed coverage");
    }

    let mut rng = cautious.next().expect("sequence delete");
    assert_eq!(sample_byte_sequence(&mut rng), []);
    rng.discard();
}

#[test]
fn cautious_sequence_projection_can_keep_non_contiguous_items() {
    let mut prefix = 4_u32.to_le_bytes().to_vec();
    prefix.extend([10, 20, 30, 40]);
    let case = Case::from_raw_parts(0, prefix, true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new((0..64).map(|_| vec![1])))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("seed rng");
        assert_eq!(sample_byte_sequence(&mut rng), [10, 20, 30, 40]);
        rng.coverage().expect("finish seed coverage");
    }

    let mut found = false;
    for mut rng in cautious.by_ref().take(512) {
        let items = sample_byte_sequence(&mut rng);
        if items == [10, 30] || items == [20, 40] {
            found = true;
            rng.discard();
            break;
        }
        rng.discard();
    }

    assert!(
        found,
        "sequence projection should try non-contiguous item subsets"
    );
}

#[test]
fn cautious_sequence_projection_can_move_later_item_to_front() {
    let mut prefix = 3_u32.to_le_bytes().to_vec();
    prefix.extend([10, 20, 30]);
    let case = Case::from_raw_parts(0, prefix, true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new((0..64).map(|_| vec![1])))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("seed rng");
        assert_eq!(sample_byte_sequence(&mut rng), [10, 20, 30]);
        rng.coverage().expect("finish seed coverage");
    }

    let mut found = false;
    for mut rng in cautious.by_ref().take(64) {
        let items = sample_byte_sequence(&mut rng);
        if items == [30] {
            found = true;
            rng.discard();
            break;
        }
        rng.discard();
    }

    assert!(
        found,
        "sequence projection should try keeping a later item as the only item"
    );
}

#[test]
fn cautious_sequence_replace_reuses_simpler_prior_items() {
    let mut prefix = 3_u32.to_le_bytes().to_vec();
    prefix.extend([1, 99, 99]);
    let case = Case::from_raw_parts(0, prefix, true);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new((0..128).map(|_| vec![1])))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("seed rng");
        assert_eq!(sample_byte_sequence(&mut rng), [1, 99, 99]);
        rng.coverage().expect("finish seed coverage");
    }

    let mut found = false;
    for mut rng in cautious.by_ref().take(128) {
        let items = sample_byte_sequence(&mut rng);
        if items == [1, 1, 99] || items == [1, 99, 1] {
            found = true;
            rng.discard();
            break;
        }
        rng.discard();
    }

    assert!(
        found,
        "sequence replacement should reuse simpler earlier item bytes"
    );
}

#[test]
fn fuzzing_style_reuses_and_mutates_successful_rng_prefixes() {
    let mut curious = curious().with_coverage(ScriptedCapture::new([[1], [2], [3], [4]]));
    let samples: Vec<_> = curious
        .by_ref()
        .take(4)
        .map(|mut rng| [rng.random::<u8>(), rng.random::<u8>(), rng.random::<u8>()])
        .collect();

    let stats = curious.stats();
    assert_eq!(stats.executed(), 4);
    assert_eq!(stats.accepted(), 4);
    assert_eq!(stats.mutated(), 3);
    assert_ne!(
        samples[0], samples[1],
        "after the first accepted case, subsequent samples should come from mutated RNG prefixes"
    );
}

#[test]
fn entropic_scheduler_raises_energy_for_rare_coverage() {
    let mut coverages = vec![vec![1, 100], vec![1, 2]];
    coverages.extend((0..70).map(|_| vec![1, 2]));
    let mut curious = curious().with_coverage(ScriptedCapture::new(coverages));

    curious
        .by_ref()
        .take(72)
        .map(sample_byte)
        .for_each(assert_byte);

    let energies = curious.test_corpus_energies();
    assert_eq!(energies.len(), 2);
    assert!(
        energies[0] > energies[1] * 2.0,
        "rare-feature corpus entry should have higher entropic energy: {energies:?}"
    );
    assert_eq!(curious.test_feature_frequency(CoverageId::new(100)), 1);
    assert!(curious.test_feature_frequency(CoverageId::new(2)) > 60);
}

#[test]
fn mutate_depth_stacks_prefix_mutations() {
    let mut shallow = curious()
        .with_seed(7)
        .with_coverage(ScriptedCapture::new([[1], [2]]))
        .with_mutate_depth(1);
    let shallow_samples: Vec<_> = shallow
        .by_ref()
        .take(2)
        .map(|mut rng| {
            let mut bytes = [0; 16];
            rng.fill_bytes(&mut bytes);
            bytes
        })
        .collect();

    let mut deep = curious()
        .with_seed(7)
        .with_coverage(ScriptedCapture::new([[1], [2]]))
        .with_mutate_depth(5);
    let deep_samples: Vec<_> = deep
        .by_ref()
        .take(2)
        .map(|mut rng| {
            let mut bytes = [0; 16];
            rng.fill_bytes(&mut bytes);
            bytes
        })
        .collect();

    assert_eq!(shallow_samples[0], deep_samples[0]);
    assert_ne!(
        shallow_samples[1], deep_samples[1],
        "stacking more prefix mutations should change the generated neighbourhood"
    );
}

#[test]
fn dictionary_mutation_can_insert_comparison_constants() {
    let mut prefix = vec![1, 2, 3];
    crate::iter::test_dictionary_mutation(&mut prefix, &[vec![0x13, 0x37]]);

    assert!(prefix.windows(2).any(|window| window == [0x13, 0x37]));
}

#[test]
fn cautious_merges_dictionary_values_from_failing_corpus() {
    let case = fork_case_with_trace_len(4);
    let mut cautious = cautious()
        .with_coverage(ScriptedCapture::new([[1]]).with_dictionary([vec![0x13, 0x37]]))
        .with_case(case);

    {
        let mut rng = cautious.next().expect("initial cautious rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
        rng.coverage().expect("finish cautious dictionary case");
    }

    assert_eq!(cautious.test_dictionary_values(), vec![vec![0x13, 0x37]]);
}

#[test]
fn fresh_root_cadence_keeps_exploring_unmutated_roots() {
    let mut curious = curious()
        .with_coverage(ScriptedCapture::new((0..9).map(|id| vec![id + 1])))
        .with_seed_ratio(8);

    curious
        .by_ref()
        .take(9)
        .map(sample_byte)
        .for_each(assert_byte);

    let stats = curious.stats();
    assert_eq!(stats.generated(), 9);
    assert_eq!(stats.accepted(), 9);
    assert_eq!(stats.mutated(), 7);
}

#[test]
fn cases_take_can_feed_rayon_parallel_iterator() {
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    let executed: usize = curious()
        .with_coverage(NoCoverage)
        .with_seed(7)
        .take(32)
        .into_par_iter()
        .map(|mut rng| {
            let _: u8 = rng.random();
            rng.coverage().expect("finish parallel case");
            1
        })
        .sum();

    assert_eq!(executed, 32);
}

#[test]
fn parallel_iterator_uses_independent_capture_instances() {
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    let capture = ParallelScriptedCapture::new();
    let finished = capture.finished();
    let executed: usize = curious()
        .with_coverage(capture)
        .with_seed(7)
        .take(32)
        .into_par_iter()
        .map(|mut rng| {
            let _: u8 = rng.random();
            rng.coverage().expect("finish parallel case");
            1
        })
        .sum();

    assert_eq!(executed, 32);
    let mut instances = finished.lock().expect("finished lock").clone();
    instances.sort_unstable();
    instances.dedup();
    assert!(
        instances.len() > 1,
        "parallel capture should not reuse one shared capture instance"
    );
}

#[test]
fn sampling_body_runs_concurrently_through_native_parallel_iterator() {
    use rayon::{
        ThreadPoolBuilder,
        iter::{IntoParallelIterator, ParallelIterator},
    };
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let pool = ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .expect("build rayon pool");

    pool.install(|| {
        curious()
            .with_coverage(NoCoverage)
            .with_seed(7)
            .take(32)
            .into_par_iter()
            .for_each(|mut rng| {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(current, Ordering::SeqCst);

                thread::sleep(Duration::from_millis(20));
                let _: u8 = rng.random();

                active.fetch_sub(1, Ordering::SeqCst);
                rng.coverage().expect("finish parallel case");
            });
    });

    assert!(max_active.load(Ordering::SeqCst) > 1);
}

#[test]
fn cautious_seeded_case_can_feed_native_parallel_iterator() {
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    let case = fork_case_with_trace_len(4);
    let executed: usize = cautious()
        .with_coverage(ParallelScriptedCapture::new())
        .with_case(case)
        .take(32)
        .into_par_iter()
        .map(|mut rng| {
            let _: u8 = rng.random();
            rng.coverage().expect("finish parallel cautious case");
            1
        })
        .sum();

    assert_eq!(executed, 32);
}

#[test]
fn default_sancov_parallel_iterator_requires_trace_pc_guard() {
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    let validation = SancovCoverage::new().validate_parallel();
    if !crate::sancov::has_trace_pc_guards() {
        let error = validation.expect_err("non-guard Sancov coverage should reject parallel use");
        assert!(
            error.contains("trace-pc-guard"),
            "parallel validation error should mention trace-pc-guard: {error}"
        );
        return;
    }

    validation.expect("trace-pc-guard instrumentation should allow parallel Sancov coverage");
    let executed: usize = curious()
        .with_seed(7)
        .take(1)
        .into_par_iter()
        .map(|mut rng| {
            let _: u8 = rng.random();
            1
        })
        .sum();

    assert_eq!(executed, 1);
}

#[test]
fn llvm_coverage_fuzzing_style_workflow_runs_when_instrumented() {
    let Ok(coverage) = backends::LlvmCoverage::new() else {
        return;
    };
    let mut curious = curious().with_coverage(coverage);

    curious
        .by_ref()
        .take(2)
        .map(sample_byte)
        .for_each(assert_byte);

    let stats = curious.stats();
    assert_eq!(stats.generated(), 2);
    assert_eq!(stats.executed(), 2);
}
