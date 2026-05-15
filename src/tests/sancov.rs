use crate::*;

#[test]
fn counter_feedback_records_edge_buckets() {
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
    let feedback = capture.finish_capture(token).expect("finish capture");

    assert!(
        feedback.features().len() >= 2,
        "two nonzero sanitizer counters should produce edge features"
    );
    assert!(
        feedback.features().iter().any(|id| id.raw() >> 60 == 0),
        "edge counter features should use the edge namespace"
    );
    assert!(
        feedback.hit_count_weight() >= 6,
        "hit-count weight should include nonzero counter bucket weights"
    );
}

#[test]
fn comparison_feedback_records_features_and_dictionary_values() {
    let mut capture = SancovCoverage::new();
    let token = capture.start_capture().expect("start capture");
    crate::sancov::test_record_cmp(1, 0x41, 0x42);
    let feedback = capture.finish_capture(token).expect("finish capture");

    assert!(
        feedback.features().iter().any(|id| id.raw() >> 60 == 1),
        "comparison callbacks should contribute value-profile features"
    );
    assert!(feedback.dictionary().contains(&vec![0x41]));
    assert!(feedback.dictionary().contains(&vec![0x42]));
}

#[test]
fn switch_feedback_records_all_case_values() {
    let mut capture = SancovCoverage::new();
    let token = capture.start_capture().expect("start capture");
    let cases = [2_u64, 8, 0x41, 0x42];
    unsafe {
        crate::sancov::__sanitizer_cov_trace_switch(0x40, cases.as_ptr());
    }
    let feedback = capture.finish_capture(token).expect("finish capture");

    assert!(
        feedback.features().iter().any(|id| id.raw() >> 60 == 1),
        "switch callbacks should contribute value-profile features"
    );
    assert!(feedback.dictionary().contains(&vec![0x41]));
    assert!(feedback.dictionary().contains(&vec![0x42]));
}
