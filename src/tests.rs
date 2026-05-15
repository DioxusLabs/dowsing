use crate::*;
use rand::{Rng, RngCore};
use std::{
    cell::RefCell,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
};

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

    fn finish_capture(&mut self, token: Self::Token) -> Result<CoverageSet, String> {
        Ok([CoverageId::new(token)].into_iter().collect())
    }
}

#[derive(Debug, Clone)]
struct ScriptedCapture {
    next_token: usize,
    coverages: Vec<Vec<u64>>,
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

    fn finish_capture(&mut self, token: Self::Token) -> Result<CoverageSet, String> {
        self.finished.lock().expect("finished lock").push(token);
        Ok([CoverageId::new(token)].into_iter().collect())
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
            finished: Rc::new(RefCell::new(Vec::new())),
            discarded: Rc::new(RefCell::new(Vec::new())),
        }
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

    fn finish_capture(&mut self, token: Self::Token) -> Result<CoverageSet, String> {
        self.finished.borrow_mut().push(token);
        let coverage = self
            .coverages
            .get(token)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(CoverageId::new)
            .collect();
        Ok(coverage)
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

fn fork_case_with_trace_len(len: usize) -> DemonicCase {
    let mut runner = curious().coverage(ScriptedCapture::new([[1]]));
    let mut rng = runner.next().expect("case source rng");
    let mut bytes = vec![0; len];
    rng.fill_bytes(&mut bytes);
    rng.fork_case()
}

#[test]
fn curious_yields_rng_and_records_on_drop() {
    let mut curious = curious().coverage(TestCapture::new());

    {
        let mut rng = curious.next().expect("first rng");
        let _ = rng.random::<u64>();
    }

    let stats = curious.stats();
    assert_eq!(stats.generated, 1);
    assert_eq!(stats.executed, 1);
    assert_eq!(stats.accepted, 1);
    assert_eq!(stats.coverage_ids, 1);
}

#[test]
fn shy_accepts_first_seed_then_smaller_code_paths() {
    let case = fork_case_with_trace_len(8);
    let mut shy = shy()
        .coverage(ScriptedCapture::new([
            vec![1, 2, 3],
            vec![1, 2, 3, 4],
            vec![1, 2],
        ]))
        .seed_case(case);

    for _ in 0..3 {
        let mut rng = shy.next().expect("shy rng");
        let mut bytes = [0; 8];
        rng.fill_bytes(&mut bytes);
    }

    let stats = shy.stats();
    assert_eq!(stats.generated, 3);
    assert_eq!(stats.executed, 3);
    assert_eq!(stats.accepted, 3);
    assert_eq!(stats.coverage_ids, 2);
    assert_eq!(shy.test_best_path_score(), Some((2, 8)));
}

#[test]
fn fuzzing_style_map_sample_for_each_assert_records_each_iteration() {
    let mut curious = curious().coverage(ScriptedCapture::new([[1], [2], [3]]));

    curious
        .by_ref()
        .take(3)
        .map(sample_byte)
        .for_each(assert_byte);

    let stats = curious.stats();
    assert_eq!(stats.generated, 3);
    assert_eq!(stats.executed, 3);
    assert_eq!(stats.accepted, 3);
    assert_eq!(stats.coverage_ids, 3);
    assert_eq!(stats.mutated, 2);
}

#[test]
#[allow(clippy::never_loop)]
fn fuzzing_style_assert_panic_still_finishes_capture_in_default_mode() {
    let capture = ScriptedCapture::new([[1]]);
    let finished = capture.finished();

    let result = catch_unwind(AssertUnwindSafe(|| {
        curious()
            .coverage(capture)
            .take(1)
            .map(sample_byte)
            .for_each(|_| panic!("invariant failed"));
    }));

    assert!(result.is_err());
    assert_eq!(*finished.borrow(), [0]);
}

#[test]
fn variant_discard_consumes_and_excludes_coverage() {
    let capture = ScriptedCapture::new([[1], [2]]);
    let finished = capture.finished();
    let discarded = capture.discarded();
    let mut curious = curious().coverage(capture);

    {
        let rng = curious.next().expect("first rng");
        rng.discard();
    }
    drop(curious.next().expect("second rng"));

    let stats = curious.stats();
    assert_eq!(stats.generated, 2);
    assert_eq!(stats.executed, 2);
    assert_eq!(stats.accepted, 1);
    assert_eq!(*finished.borrow(), [1]);
    assert_eq!(*discarded.borrow(), [0]);
}

#[test]
fn variant_coverage_consumes_and_reports_feature_and_byte_counts() {
    let capture = ScriptedCapture::new([vec![1, 2, 3]]);
    let finished = capture.finished();
    let mut curious = curious().coverage(capture);

    let coverage = {
        let mut rng = curious.next().expect("first rng");
        let mut bytes = [0; 5];
        rng.fill_bytes(&mut bytes);
        rng.coverage().expect("finish coverage")
    };

    assert_eq!(
        coverage,
        DemonicCoverage {
            feature_count: 3,
            bytes_consumed: 5,
        }
    );
    assert_eq!(*finished.borrow(), [0]);

    let stats = curious.stats();
    assert_eq!(stats.generated, 1);
    assert_eq!(stats.executed, 1);
    assert_eq!(stats.accepted, 1);
    assert_eq!(stats.coverage_ids, 3);
}

#[test]
fn fork_case_replays_consumed_rng_path() {
    let mut discovery = curious().coverage(ScriptedCapture::new([[1]]));
    let (case, original) = {
        let mut rng = discovery.next().expect("discovery rng");
        let bytes = [rng.random::<u8>(), rng.random::<u8>(), rng.random::<u8>()];
        (rng.fork_case(), bytes)
    };

    let mut replay = curious()
        .coverage(ScriptedCapture::new([[1]]))
        .seed_case(case);
    let replayed = {
        let mut rng = replay.next().expect("replay rng");
        [rng.random::<u8>(), rng.random::<u8>(), rng.random::<u8>()]
    };

    assert_eq!(replayed, original);
}

#[test]
fn seeded_cases_run_before_fresh_roots() {
    let mut source = curious().seed(123).coverage(ScriptedCapture::new([[1]]));
    let (case, seeded_bytes) = {
        let mut rng = source.next().expect("source rng");
        let bytes = [rng.random::<u8>(), rng.random::<u8>()];
        (rng.fork_case(), bytes)
    };
    let fresh_bytes = {
        let mut fresh = curious().seed(5).coverage(ScriptedCapture::new([[1]]));
        let mut rng = fresh.next().expect("fresh rng");
        [rng.random::<u8>(), rng.random::<u8>()]
    };

    let mut curious = curious()
        .seed(5)
        .coverage(ScriptedCapture::new([[1], [2]]))
        .seed_case(case);

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
fn shy_without_seed_or_corpus_yields_no_variants() {
    let mut shy = shy().coverage(ScriptedCapture::new([[1]]));

    assert!(shy.next().is_none());
    assert_eq!(shy.stats().generated, 0);
}

#[test]
fn fuzzing_style_maximize_accepts_only_new_coverage() {
    let mut curious = curious().coverage(ScriptedCapture::new([vec![1], vec![1], vec![1, 2]]));

    curious
        .by_ref()
        .take(3)
        .map(sample_byte)
        .for_each(assert_byte);

    let stats = curious.stats();
    assert_eq!(stats.generated, 3);
    assert_eq!(stats.executed, 3);
    assert_eq!(stats.accepted, 2);
    assert_eq!(stats.coverage_ids, 2);
    assert_eq!(stats.mutated, 2);
}

#[test]
fn shy_accepts_smaller_code_paths() {
    let case = fork_case_with_trace_len(8);
    let mut shy = shy()
        .coverage(ScriptedCapture::new([
            vec![1, 2, 3],
            vec![1, 2, 3, 4],
            vec![1, 2],
            vec![1],
        ]))
        .seed_case(case);

    for mut rng in shy.by_ref().take(4) {
        let _ = sample_byte(&mut rng);
    }

    let stats = shy.stats();
    assert_eq!(stats.generated, 4);
    assert_eq!(stats.executed, 4);
    assert_eq!(stats.accepted, 4);
    assert_eq!(stats.coverage_ids, 1);
    assert_eq!(stats.mutated, 3);
    assert_eq!(shy.test_best_path_score(), Some((1, 1)));
}

#[test]
fn shy_rejects_discarded_smaller_paths() {
    let capture = ScriptedCapture::new([vec![1, 2, 3], vec![1]]);
    let finished = capture.finished();
    let discarded = capture.discarded();
    let case = fork_case_with_trace_len(8);
    let mut shy = shy().coverage(capture).seed_case(case);

    {
        let mut rng = shy.next().expect("first rng");
        let _ = sample_byte(&mut rng);
    }
    {
        let mut rng = shy.next().expect("second rng");
        let _ = sample_byte(&mut rng);
        rng.discard();
    }

    let stats = shy.stats();
    assert_eq!(stats.generated, 2);
    assert_eq!(stats.executed, 2);
    assert_eq!(stats.accepted, 1);
    assert_eq!(stats.coverage_ids, 3);
    assert_eq!(*finished.borrow(), [0]);
    assert_eq!(*discarded.borrow(), [1]);
}

#[test]
fn shy_havoc_keeps_generating_byte_variants() {
    let case = fork_case_with_trace_len(4);
    let mut shy = shy()
        .coverage(ScriptedCapture::new((0..32).map(|_| vec![1])))
        .seed_case(case);

    {
        let mut rng = shy.next().expect("seed rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
    }

    let mut variants = 0;
    for mut rng in shy.by_ref().take(64) {
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
        rng.discard();
        variants += 1;
    }

    assert_eq!(variants, 64, "shy should keep producing byte variants");
    let stats = shy.stats();
    assert_eq!(stats.generated, variants + 1);
    assert_eq!(stats.executed, variants + 1);
    assert_eq!(stats.accepted, 1);
}

#[test]
fn shy_entropic_scheduler_raises_energy_for_rare_removed_coverage() {
    let initial = fork_case_with_trace_len(8);
    let smaller = fork_case_with_trace_len(4);
    let mut shy = shy()
        .coverage(ScriptedCapture::new([vec![1, 2, 3]]))
        .seed_case(initial);

    {
        let mut rng = shy.next().expect("initial failing rng");
        let mut bytes = [0; 8];
        rng.fill_bytes(&mut bytes);
    }

    for _ in 0..64 {
        let mut rng = shy.next().expect("scheduled variant");
        let mut bytes = [0; 8];
        rng.fill_bytes(&mut bytes);
        rng.discard();
    }

    shy = shy.seed_case(smaller);
    {
        let mut rng = shy.next().expect("smaller failing rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
    }

    let energies = shy.test_corpus_energies();
    assert_eq!(energies.len(), 2);
    assert!(
        energies[1] > energies[0] * 2.0,
        "candidate that removes previously sticky coverage should have higher schedule energy: {energies:?}"
    );
}

#[test]
fn shy_gives_rare_removed_coverage_more_energy_than_common_removed_coverage() {
    let case = fork_case_with_trace_len(8);
    let mut shy = shy()
        .coverage(ScriptedCapture::new([
            vec![1, 2, 3, 4],
            vec![1, 2, 3],
            vec![1, 2, 3],
            vec![1, 2, 3],
            vec![1, 3, 4],
        ]))
        .seed_case(case);

    for _ in 0..5 {
        let mut rng = shy.next().expect("shy rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
    }

    let energies = shy.test_corpus_energies();
    assert_eq!(energies.len(), 5);
    assert!(
        energies[4] > energies[3] * 2.0,
        "rare removed feature should have more energy than repeatedly removed feature: {energies:?}"
    );
}

#[test]
fn shy_minimizes_rng_bytes_before_feature_count() {
    let case = fork_case_with_trace_len(8);
    let mut shy = shy()
        .coverage(ScriptedCapture::new([vec![1, 2], vec![1, 2, 3]]))
        .seed_case(case);

    {
        let mut rng = shy.next().expect("first rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
    }
    {
        let mut rng = shy.next().expect("second rng");
        let mut bytes = [0; 1];
        rng.fill_bytes(&mut bytes);
    }

    let stats = shy.stats();
    assert_eq!(stats.generated, 2);
    assert_eq!(stats.executed, 2);
    assert_eq!(stats.accepted, 2);
    assert_eq!(shy.test_best_path_score(), Some((3, 1)));
    assert_eq!(shy.test_corpus_path_lens(), [4, 1]);
}

#[test]
fn shy_uses_feature_count_as_rng_byte_tie_breaker() {
    let case = fork_case_with_trace_len(8);
    let mut shy = shy()
        .coverage(ScriptedCapture::new([vec![1], vec![1]]))
        .seed_case(case);

    {
        let mut rng = shy.next().expect("first rng");
        let mut bytes = [0; 4];
        rng.fill_bytes(&mut bytes);
    }
    {
        let mut rng = shy.next().expect("second rng");
        let mut bytes = [0; 2];
        rng.fill_bytes(&mut bytes);
    }

    let stats = shy.stats();
    assert_eq!(stats.generated, 2);
    assert_eq!(stats.executed, 2);
    assert_eq!(stats.accepted, 2);
    assert_eq!(shy.test_best_path_score(), Some((1, 2)));
    assert_eq!(shy.test_corpus_path_lens(), [4, 2]);
}

#[test]
fn fuzzing_style_reuses_and_mutates_successful_rng_prefixes() {
    let mut curious = curious().coverage(ScriptedCapture::new([[1], [2], [3], [4]]));
    let samples: Vec<_> = curious
        .by_ref()
        .take(4)
        .map(|mut rng| [rng.random::<u8>(), rng.random::<u8>(), rng.random::<u8>()])
        .collect();

    let stats = curious.stats();
    assert_eq!(stats.executed, 4);
    assert_eq!(stats.accepted, 4);
    assert_eq!(stats.mutated, 3);
    assert_ne!(
        samples[0], samples[1],
        "after the first accepted case, subsequent samples should come from mutated RNG prefixes"
    );
}

#[test]
fn entropic_scheduler_raises_energy_for_rare_coverage() {
    let mut coverages = vec![vec![1, 100], vec![1, 2]];
    coverages.extend((0..70).map(|_| vec![1, 2]));
    let mut curious = curious().coverage(ScriptedCapture::new(coverages));

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
        .seed(7)
        .coverage(ScriptedCapture::new([[1], [2]]))
        .mutate_depth(1);
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
        .seed(7)
        .coverage(ScriptedCapture::new([[1], [2]]))
        .mutate_depth(5);
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
fn sancov_counter_feedback_records_edge_buckets() {
    let counters = Box::leak(vec![0_u8; 4].into_boxed_slice());
    unsafe {
        crate::sancov::__sanitizer_cov_8bit_counters_init(
            counters.as_mut_ptr(),
            counters.as_mut_ptr().add(counters.len()),
        );
    }

    let mut capture = SancovCoverage::new().with_cmp_feedback(false);
    let token = capture.start_capture().expect("start capture");
    counters[1] = 1;
    counters[2] = 9;
    let coverage = capture.finish_capture(token).expect("finish capture");

    assert!(
        coverage.len() >= 2,
        "two nonzero sanitizer counters should produce edge features"
    );
    assert!(
        coverage.iter().any(|id| id.raw() >> 60 == 0),
        "edge counter features should use the edge namespace"
    );
}

#[test]
fn sancov_comparison_feedback_records_features_and_dictionary_values() {
    let mut capture = SancovCoverage::new();
    let token = capture.start_capture().expect("start capture");
    crate::sancov::test_record_cmp(1, 0x41, 0x42);
    let coverage = capture.finish_capture(token).expect("finish capture");

    assert!(
        coverage.iter().any(|id| id.raw() >> 60 == 1),
        "comparison callbacks should contribute value-profile features"
    );
    crate::sancov::with_dictionary_values(|dictionary| {
        assert!(dictionary.contains(&vec![0x41]));
        assert!(dictionary.contains(&vec![0x42]));
    });
}

#[test]
fn dictionary_mutation_can_insert_comparison_constants() {
    let mut prefix = vec![1, 2, 3];
    crate::iter::test_dictionary_mutation(&mut prefix, &[vec![0x13, 0x37]]);

    assert!(prefix.windows(2).any(|window| window == [0x13, 0x37]));
}

#[test]
fn fresh_root_cadence_keeps_exploring_unmutated_roots() {
    let mut curious = curious()
        .coverage(ScriptedCapture::new((0..9).map(|id| vec![id + 1])))
        .seed_ratio(8);

    curious
        .by_ref()
        .take(9)
        .map(sample_byte)
        .for_each(assert_byte);

    let stats = curious.stats();
    assert_eq!(stats.generated, 9);
    assert_eq!(stats.accepted, 9);
    assert_eq!(stats.mutated, 7);
}

#[test]
fn demonic_take_can_feed_rayon_parallel_iterator() {
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    let executed: usize = curious()
        .coverage(NoCoverage)
        .seed(7)
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
        .coverage(capture)
        .seed(7)
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
            .coverage(NoCoverage)
            .seed(7)
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
fn shy_seeded_case_can_feed_native_parallel_iterator() {
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    let case = fork_case_with_trace_len(4);
    let executed: usize = shy()
        .coverage(ParallelScriptedCapture::new())
        .seed_case(case)
        .take(32)
        .into_par_iter()
        .map(|mut rng| {
            let _: u8 = rng.random();
            rng.coverage().expect("finish parallel shy case");
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
        .seed(7)
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
    let Ok(mut curious) = curious().llvm_coverage() else {
        return;
    };

    curious
        .by_ref()
        .take(2)
        .map(sample_byte)
        .for_each(assert_byte);

    let stats = curious.stats();
    assert_eq!(stats.generated, 2);
    assert_eq!(stats.executed, 2);
}
