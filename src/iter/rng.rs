use super::{
    api::coverage_delta,
    mutate::{corpus_energy, refresh_corpus_energies},
    snapshot_hooks::{Boundary, BoundaryHook, BoundaryKind, DetachedExecution, FinishHook},
    prelude::{
        Active, CandidateOrigin, Case, CaseCost, CaseCoverage, CorpusSeed, DrawKind, DrawSpan,
        MAX_PREFIX_LEN, MinPathScore, Mode, SemanticKind, SemanticSpan, SequenceItemSpan,
        SequenceSpan, State,
    },
    run::min_path_schedule_energy,
    shrink::{
        energy_refresh_interval, merge_dictionary_values, prune_corpus, record_cautious_discard,
        record_cautious_preserved, reset_cautious_reducer_to_best,
    },
};
use crate::{
    coverage::{CAPTURE_BUSY, CoverageCapture, ExecutionFeedback},
    sancov::SancovCoverage,
};
use rand::{RngCore, rngs::SmallRng};
use std::{
    cell::RefCell,
    ops::{Bound, RangeBounds},
    rc::Rc,
    sync::{Arc, Mutex},
};

/// RNG yielded by [`crate::Curious`] and [`crate::Cautious`].
pub struct CaseRng<Capture: CoverageCapture = SancovCoverage> {
    pub(super) shared: Arc<Mutex<State<Capture>>>,
    pub(super) fallback: SmallRng,
    pub(super) seed: u64,
    pub(super) prefix: Vec<u8>,
    pub(super) zero_tail: bool,
    pub(super) origin: CandidateOrigin,
    pub(super) cursor: usize,
    pub(super) bytes_consumed: usize,
    pub(super) trace: Vec<u8>,
    pub(super) draws: Vec<DrawSpan>,
    pub(super) semantics: Vec<SemanticSpan>,
    pub(super) sequences: Vec<SequenceSpan>,
    pub(super) token: Option<Capture::Token>,
    pub(super) local_capture: Option<Capture>,
    pub(super) start_error: Option<String>,
    pub(super) finished: bool,
    pub(super) boundary_hook: Option<BoundaryHook<Capture>>,
    pub(super) finish_hook: Option<FinishHook>,
}

impl<Capture: CoverageCapture> CaseRng<Capture> {
    pub(super) fn fire_boundary(&mut self, kind: BoundaryKind) {
        if let Some(mut hook) = self.boundary_hook.take() {
            hook(
                self,
                Boundary {
                    kind,
                    cursor: self.cursor,
                },
            );
            if self.boundary_hook.is_none() {
                self.boundary_hook = Some(hook);
            }
        }
    }

    /// Seed backing this execution.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Fork the consumed RNG path into a replayable case.
    pub fn fork_case(&self) -> Case {
        Case {
            seed: self.seed,
            prefix: self.trace.clone(),
            zero_tail: self.zero_tail,
            draws: self.draws.clone(),
            semantics: self.semantics.clone(),
            sequences: self.sequences.clone(),
        }
    }

    fn mark_semantic<T>(&mut self, kind: SemanticKind, f: impl FnOnce(&mut Self) -> T) -> T {
        let start = self.cursor;
        let output = f(self);
        let len = self.cursor.saturating_sub(start);
        if len > 0 && start < MAX_PREFIX_LEN {
            self.semantics.push(SemanticSpan::new(
                start,
                len.min(MAX_PREFIX_LEN - start),
                kind,
            ));
        }
        output
    }

    fn length_below(&mut self, upper: usize) -> usize {
        let upper = upper.max(1).min(u16::MAX as usize) as u16;
        self.mark_semantic(SemanticKind::Length, |rng| {
            (rng.next_u32() as u16 % upper) as usize
        })
    }

    fn draw_length_in<R>(&mut self, range: R) -> usize
    where
        R: RangeBounds<usize>,
    {
        let (start, width) = normalize_range(range);
        if width == 1 {
            start
        } else {
            start + self.length_below(width)
        }
    }

    /// Generate a variant index in `0..upper`.
    pub fn variant(&mut self, upper: usize) -> usize {
        let upper = upper.max(1).min(u16::MAX as usize) as u16;
        self.fire_boundary(BoundaryKind::Variant);
        self.mark_semantic(SemanticKind::Variant, |rng| {
            (rng.next_u32() as u16 % upper) as usize
        })
    }

    /// Generate a length in `range` and return a semantic range iterator.
    pub fn range<R>(&mut self, range: R) -> RangeIter<'_, Capture>
    where
        R: RangeBounds<usize>,
    {
        RangeIter::new(Rc::new(RefCell::new(self)), range)
    }

    /// Finish this execution immediately and return its coverage stats.
    ///
    /// This consumes the RNG because coverage is only meaningful after the caller has finished
    /// executing the path being measured.
    pub fn coverage(mut self) -> Result<CaseCoverage, String> {
        self.finish(true, CaseCost::zero())
    }

    /// Finish this execution with a domain-specific value cost.
    ///
    /// Lower costs are better. In `cautious()` mode the minimizer uses this cost before coverage
    /// and RNG-path length, so a harness can prefer shorter or simpler reproducing values while
    /// still rejecting non-reproducing values with [`Self::discard`].
    pub fn coverage_with_cost(mut self, cost: impl Into<CaseCost>) -> Result<CaseCoverage, String> {
        self.finish(true, cost.into())
    }

    /// Exclude this execution from coverage feedback when the RNG is dropped.
    pub fn discard(mut self) {
        let _ = self.finish(false, CaseCost::zero());
    }
}

/// Structured range iterator returned by [`CaseRng::range`].
pub struct RangeIter<'a, Capture: CoverageCapture = SancovCoverage> {
    shared: Rc<RangeState<'a, Capture>>,
    len: usize,
    index: usize,
    order: Vec<usize>,
}

impl<'a, Capture: CoverageCapture> RangeIter<'a, Capture> {
    fn new<R>(rng: Rc<RefCell<&'a mut CaseRng<Capture>>>, range: R) -> Self
    where
        R: RangeBounds<usize>,
    {
        let (len, length_start, length_len) = {
            let mut rng = rng.borrow_mut();
            let length_start = rng.cursor;
            let len = rng.draw_length_in(range);
            let length_len = rng.cursor.saturating_sub(length_start);
            (len, length_start, length_len)
        };

        Self {
            shared: Rc::new(RangeState {
                rng,
                length_start,
                length_len,
                item_spans: RefCell::new(Vec::with_capacity(len)),
            }),
            len,
            index: 0,
            order: Vec::new(),
        }
    }

    /// Yield this range's children in `order`.
    ///
    /// The order must be a permutation of `0..self.len()` and must be selected before iteration
    /// starts. [`ChildRng::index`] returns the child index selected for the current yield.
    pub fn reorder<I>(mut self, order: I) -> Self
    where
        I: IntoIterator<Item = usize>,
    {
        assert_eq!(
            self.index, 0,
            "range children must be reordered before iteration starts"
        );

        let order: Vec<_> = order.into_iter().collect();
        assert_eq!(
            order.len(),
            self.len,
            "range child order must include every generated child"
        );

        let mut seen = vec![false; self.len];
        for index in order.iter().copied() {
            assert!(index < self.len, "range child order index out of bounds");
            assert!(!seen[index], "range child order contains a duplicate index");
            seen[index] = true;
        }

        self.order = order;
        self
    }
}

impl<'a, Capture: CoverageCapture> Iterator for RangeIter<'a, Capture> {
    type Item = ChildRng<'a, Capture>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.len {
            return None;
        }

        let position = self.index;
        let index = self.order.get(position).copied().unwrap_or(position);
        self.index += 1;
        let item_start = {
            let mut rng = self.shared.rng.borrow_mut();
            rng.fire_boundary(BoundaryKind::Item);
            rng.cursor
        };
        Some(ChildRng {
            shared: Rc::clone(&self.shared),
            index,
            position,
            item_start,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl<Capture: CoverageCapture> ExactSizeIterator for RangeIter<'_, Capture> {}

struct RangeState<'a, Capture: CoverageCapture = SancovCoverage> {
    rng: Rc<RefCell<&'a mut CaseRng<Capture>>>,
    length_start: usize,
    length_len: usize,
    item_spans: RefCell<Vec<(usize, SequenceItemSpan)>>,
}

impl<Capture: CoverageCapture> Drop for RangeState<'_, Capture> {
    fn drop(&mut self) {
        let item_spans = self.item_spans.get_mut();
        if self.length_len > 0 && self.length_start < MAX_PREFIX_LEN && !item_spans.is_empty() {
            item_spans.sort_by_key(|(position, _)| *position);
            let items = item_spans.iter().map(|(_, span)| *span).collect();
            let mut rng = self.rng.borrow_mut();
            rng.sequences.push(SequenceSpan {
                length_start: self.length_start,
                length_len: self.length_len.min(MAX_PREFIX_LEN - self.length_start),
                items,
            });
        }
    }
}

/// Child RNG for one generated element in a [`CaseRng::range`] sequence.
pub struct ChildRng<'a, Capture: CoverageCapture = SancovCoverage> {
    shared: Rc<RangeState<'a, Capture>>,
    index: usize,
    position: usize,
    item_start: usize,
}

impl<Capture: CoverageCapture> ChildRng<'_, Capture> {
    /// Zero-based logical index of this generated child.
    ///
    /// This reflects any order selected with [`RangeIter::reorder`].
    pub fn index(&self) -> usize {
        self.index
    }

    /// Generate a variant index in `0..upper`.
    pub fn variant(&mut self, upper: usize) -> usize {
        self.shared.rng.borrow_mut().variant(upper)
    }
}

impl<Capture: CoverageCapture> RngCore for ChildRng<'_, Capture> {
    fn next_u32(&mut self) -> u32 {
        self.shared.rng.borrow_mut().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.shared.rng.borrow_mut().next_u64()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.shared.rng.borrow_mut().fill_bytes(dst);
    }
}

impl<Capture: CoverageCapture> Drop for ChildRng<'_, Capture> {
    fn drop(&mut self) {
        let mut rng = self.shared.rng.borrow_mut();
        let item_len = rng.cursor.saturating_sub(self.item_start);
        if item_len > 0 && self.item_start < MAX_PREFIX_LEN {
            let len = item_len.min(MAX_PREFIX_LEN - self.item_start);
            self.shared.item_spans.borrow_mut().push((
                self.position,
                SequenceItemSpan {
                    start: self.item_start,
                    len,
                },
            ));
            rng.semantics
                .push(SemanticSpan::new(self.item_start, len, SemanticKind::Item));
        }
    }
}

fn normalize_range(range: impl RangeBounds<usize>) -> (usize, usize) {
    let start = match range.start_bound() {
        Bound::Included(value) => *value,
        Bound::Excluded(value) => value.saturating_add(1),
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(value) => value.saturating_add(1),
        Bound::Excluded(value) => *value,
        Bound::Unbounded => panic!("range requires a bounded upper limit"),
    };
    assert!(start < end, "range requires a non-empty range");
    (start, end - start)
}

impl<Capture: CoverageCapture> RngCore for CaseRng<Capture> {
    fn next_u32(&mut self) -> u32 {
        let start = self.cursor;
        let bytes = self.traced_word_bytes();
        self.record_draw(start, 4, DrawKind::Word);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let start = self.cursor;
        let bytes = self.traced_word_bytes();
        self.record_draw(start, 8, DrawKind::Word);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        let start = self.cursor;
        let len = dst.len();
        for byte in dst {
            *byte = self.next_byte();
        }
        self.record_draw(start, len, DrawKind::Bytes);
    }
}

impl<Capture: CoverageCapture> CaseRng<Capture> {
    fn traced_word_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut bytes = [0; N];
        for byte in &mut bytes {
            *byte = self.next_byte();
        }
        bytes
    }

    fn record_draw(&mut self, start: usize, len: usize, kind: DrawKind) {
        if len == 0 || start >= MAX_PREFIX_LEN {
            return;
        }
        let len = len.min(MAX_PREFIX_LEN - start);
        self.draws.push(DrawSpan::new(start, len, kind));
    }

    fn next_byte(&mut self) -> u8 {
        self.ensure_started();
        let byte = if let Some(byte) = self.prefix.get(self.cursor) {
            *byte
        } else if self.zero_tail {
            0
        } else {
            let mut byte = [0];
            self.fallback.fill_bytes(&mut byte);
            byte[0]
        };
        self.cursor = self.cursor.saturating_add(1);
        self.bytes_consumed = self.bytes_consumed.saturating_add(1);
        self.trace.push(byte);
        byte
    }

    fn ensure_started(&mut self) {
        if self.finished || self.token.is_some() || self.start_error.is_some() {
            return;
        }
        loop {
            let token = if let Some(capture) = self.local_capture.as_mut() {
                capture.start_capture()
            } else {
                self.shared
                    .lock()
                    .expect("search state poisoned")
                    .capture
                    .start_capture()
            };
            match token {
                Ok(token) => {
                    self.token = Some(token);
                    return;
                }
                Err(error) if error == CAPTURE_BUSY => {
                    std::thread::yield_now();
                }
                Err(error) => {
                    self.start_error = Some(error);
                    return;
                }
            }
        }
    }

    pub(super) fn finish(
        &mut self,
        record_coverage: bool,
        case_cost: CaseCost,
    ) -> Result<CaseCoverage, String> {
        if self.finished {
            return Err("coverage already finished".to_string());
        }
        self.ensure_started();
        self.finished = true;

        let active = Active {
            seed: self.seed,
            trace: std::mem::take(&mut self.trace),
            draws: std::mem::take(&mut self.draws),
            semantics: std::mem::take(&mut self.semantics),
            sequences: std::mem::take(&mut self.sequences),
            bytes_consumed: self.bytes_consumed,
            origin: self.origin.clone(),
        };
        let token = self.token.take();
        if self.finish_hook.is_some() {
            return self.finish_detached(active, token, record_coverage, case_cost);
        }
        if let Some(mut capture) = self.local_capture.take() {
            let outcome = finish_capture(
                &mut capture,
                token,
                self.start_error.take(),
                record_coverage,
            );
            match outcome {
                Ok(outcome) => {
                    let mut state = self.shared.lock().expect("search state poisoned");
                    merge_finished_execution(&mut state, active, outcome, case_cost)
                }
                Err(error) => {
                    let mut state = self.shared.lock().expect("search state poisoned");
                    state.stats.executed += 1;
                    state.active_cases = state.active_cases.saturating_sub(1);
                    Err(error)
                }
            }
        } else {
            let mut state = self.shared.lock().expect("search state poisoned");
            let outcome = finish_capture(
                &mut state.capture,
                token,
                self.start_error.take(),
                record_coverage,
            );
            match outcome {
                Ok(outcome) => merge_finished_execution(&mut state, active, outcome, case_cost),
                Err(error) => {
                    state.stats.executed += 1;
                    state.active_cases = state.active_cases.saturating_sub(1);
                    Err(error)
                }
            }
        }
    }
}

impl<Capture: CoverageCapture> CaseRng<Capture> {
    fn finish_detached(
        &mut self,
        active: Active,
        token: Option<Capture::Token>,
        record_coverage: bool,
        case_cost: CaseCost,
    ) -> Result<CaseCoverage, String> {
        let start_error = self.start_error.take();
        let outcome = if let Some(capture) = self.local_capture.as_mut() {
            finish_capture(capture, token, start_error, record_coverage)
        } else {
            let mut state = self.shared.lock().expect("search state poisoned");
            finish_capture(&mut state.capture, token, start_error, record_coverage)
        };
        let feedback = outcome?.feedback;
        let coverage = CaseCoverage::with_cost(
            case_cost,
            feedback.as_ref().map_or(0, |feedback| feedback.features.len()),
            feedback
                .as_ref()
                .map_or(0, |feedback| feedback.hit_count_weight),
            active.bytes_consumed,
        );
        let execution = DetachedExecution {
            trace: active.trace,
            draws: active.draws,
            semantics: active.semantics,
            sequences: active.sequences,
            bytes_consumed: active.bytes_consumed,
            feedback,
            case_cost,
        };
        if let Some(hook) = self.finish_hook.as_mut() {
            hook(&execution);
        }
        Ok(coverage)
    }

    pub(super) fn merge_detached(
        &mut self,
        execution: DetachedExecution,
    ) -> Result<CaseCoverage, String> {
        let active = Active {
            seed: self.seed,
            trace: execution.trace,
            draws: execution.draws,
            semantics: execution.semantics,
            sequences: execution.sequences,
            bytes_consumed: execution.bytes_consumed,
            origin: self.origin.clone(),
        };
        let mut state = self.shared.lock().expect("search state poisoned");
        merge_finished_execution(
            &mut state,
            active,
            FinishedCapture {
                feedback: execution.feedback,
            },
            execution.case_cost,
        )
    }
}

impl<Capture> Drop for CaseRng<Capture>
where
    Capture: CoverageCapture,
{
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish(true, CaseCost::zero());
        }
    }
}

struct FinishedCapture {
    feedback: Option<ExecutionFeedback>,
}

fn finish_capture<Capture>(
    capture: &mut Capture,
    token: Option<Capture::Token>,
    start_error: Option<String>,
    record_coverage: bool,
) -> Result<FinishedCapture, String>
where
    Capture: CoverageCapture,
{
    if !record_coverage {
        if let Some(token) = token {
            capture.discard_capture(token)?;
        }
        return Ok(FinishedCapture { feedback: None });
    }

    if let Some(error) = start_error {
        return Err(error);
    }
    let token = token.ok_or_else(|| "coverage capture never started".to_string())?;
    Ok(FinishedCapture {
        feedback: Some(capture.finish_capture(token)?),
    })
}

fn merge_finished_execution<Capture>(
    state: &mut State<Capture>,
    active: Active,
    finished: FinishedCapture,
    case_cost: CaseCost,
) -> Result<CaseCoverage, String>
where
    Capture: CoverageCapture,
{
    state.stats.executed += 1;
    state.active_cases = state.active_cases.saturating_sub(1);

    let Some(feedback) = finished.feedback else {
        if state.mode == Mode::Cautious {
            record_cautious_discard(state, &active.origin);
        }
        return Ok(CaseCoverage::with_cost(
            CaseCost::zero(),
            0,
            0,
            active.bytes_consumed,
        ));
    };
    merge_dictionary_values(state, feedback.dictionary);

    let coverage = feedback.features;
    let run_coverage = CaseCoverage::with_cost(
        case_cost,
        coverage.len(),
        feedback.hit_count_weight,
        active.bytes_consumed,
    );
    let score = run_coverage.feature_count;
    let hit_count_weight = run_coverage.hit_count_weight;
    let path_len = run_coverage.bytes_consumed;
    let nonzero_bytes = active.trace.iter().filter(|byte| **byte != 0).count();
    let removed_ids: Vec<_> = if state.mode == Mode::Cautious {
        if !state.min_path_target_initialized {
            state.min_path_target = coverage.clone();
            state.min_path_target_initialized = true;
            Vec::new()
        } else {
            state.min_path_target.difference(&coverage).iter().collect()
        }
    } else {
        Vec::new()
    };
    let interesting = if state.mode == Mode::Cautious {
        true
    } else {
        !coverage_delta(&state.global, &coverage).is_empty()
    };
    let best_cautious_score = (state.mode == Mode::Cautious)
        .then_some(state.min_path_best)
        .flatten();
    let candidate_score =
        MinPathScore::with_case_cost(case_cost, score, hit_count_weight, path_len, nonzero_bytes);
    let improves_best_cautious =
        best_cautious_score.is_none_or(|_| improves_min_path(state, candidate_score, &active));

    if state.mode == Mode::Curious {
        for id in coverage.iter() {
            *state.coverage_frequency.entry(id).or_insert(0) += 1;
        }
        state.executions_since_refresh = state.executions_since_refresh.saturating_add(1);
        if state.executions_since_refresh >= energy_refresh_interval(state.mode) {
            refresh_corpus_energies(state);
        }
    }

    if interesting {
        let coverage_ids: Vec<_> = coverage.iter().collect();
        if state.mode == Mode::Cautious {
            for id in &removed_ids {
                *state.min_path_removed_frequency.entry(*id).or_insert(0) += 1;
            }
        }
        state.stats.accepted += 1;
        let energy = match state.mode {
            Mode::Curious => corpus_energy(state, &coverage_ids),
            Mode::Cautious => {
                let best = state
                    .min_path_best
                    .map(|best| best.min(candidate_score))
                    .unwrap_or(candidate_score);
                min_path_schedule_energy(
                    &state.min_path_removed_frequency,
                    state.stats.accepted,
                    best,
                    &removed_ids,
                    candidate_score,
                )
            }
        };
        match state.mode {
            Mode::Curious => {
                state.global.extend(coverage.iter());
                state.stats.coverage_ids = state.global.len() as u64;
            }
            Mode::Cautious if improves_best_cautious => {
                state.global = coverage.clone();
                state.stats.coverage_ids = score as u64;
            }
            Mode::Cautious => {}
        }
        let mut corpus_prefix = active.trace.clone();
        if corpus_prefix.len() > MAX_PREFIX_LEN {
            corpus_prefix.truncate(MAX_PREFIX_LEN);
        }
        state.corpus.push(CorpusSeed {
            seed: active.seed,
            prefix: corpus_prefix,
            draws: active.draws,
            semantics: active.semantics,
            sequences: active.sequences,
            coverage: coverage_ids,
            removed: removed_ids,
            case_cost,
            score,
            hit_count_weight,
            path_len,
            nonzero_bytes,
            energy,
        });
        let inserted_index = state.corpus.len() - 1;
        state.energy_index.push(energy);
        if state.mode == Mode::Cautious && improves_best_cautious {
            state.min_path_best = Some(candidate_score);
            state.min_path_best_index = Some(inserted_index);
            refresh_corpus_energies(state);
            reset_cautious_reducer_to_best(state);
        } else if state.mode == Mode::Cautious {
            record_cautious_preserved(state, &active.origin);
        }
        prune_corpus(state);
    }

    Ok(run_coverage)
}

fn improves_min_path<Capture: CoverageCapture>(
    state: &State<Capture>,
    candidate_score: MinPathScore,
    active: &Active,
) -> bool {
    let Some(best_score) = state.min_path_best else {
        return true;
    };

    match candidate_score.cmp(&best_score) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => {
            let Some(best_index) = state.min_path_best_index else {
                return true;
            };
            let Some(best) = state.corpus.get(best_index) else {
                return true;
            };

            (active.draws.len(), active.trace.as_slice())
                < (best.draws.len(), best.prefix.as_slice())
        }
    }
}
