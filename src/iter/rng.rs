use super::{
    api::coverage_delta,
    mutate::{corpus_energy, refresh_corpus_energies},
    prelude::{
        Active, CandidateOrigin, Case, CaseCost, CaseCoverage, CorpusSeed, MAX_PREFIX_LEN,
        MinPathScore, Mode, State,
    },
    run::min_path_schedule_energy,
    shrink::{
        energy_refresh_interval, merge_dictionary_values, prune_corpus, record_cautious_discard,
        record_cautious_preserved, reset_cautious_reducer_to_best,
    },
};
use crate::{
    coverage::{CaptureStart, CoverageCapture, ExecutionFeedback},
    sancov::SancovCoverage,
};
use dowsing_rng::{RangeIter as SemanticRangeIter, SemanticRng, TraceHandle, TraceSnapshot};
use rand::RngCore;
use std::{
    ops::{Range, RangeBounds},
    sync::{Arc, Mutex},
};

/// RNG yielded by [`crate::Curious`] and [`crate::Cautious`].
pub struct CaseRng<Capture: CoverageCapture = SancovCoverage> {
    runtime: Arc<Mutex<CaseRuntime<Capture>>>,
    semantic: SemanticRng,
}

struct CaseRuntime<Capture: CoverageCapture = SancovCoverage> {
    pub(super) shared: Arc<Mutex<State<Capture>>>,
    pub(super) trace: TraceHandle,
    pub(super) origin: CandidateOrigin,
    pub(super) session: Option<Capture::Session>,
    pub(super) local_capture: Option<Capture>,
    pub(super) start_error: Option<String>,
    pub(super) finished: bool,
}

impl<Capture: CoverageCapture> CaseRng<Capture> {
    pub(super) fn new(
        shared: Arc<Mutex<State<Capture>>>,
        case: Case,
        origin: CandidateOrigin,
        session: Option<Capture::Session>,
        local_capture: Option<Capture>,
    ) -> Self {
        let semantic = SemanticRng::new(case);
        let trace = semantic.handle();
        Self {
            runtime: Arc::new(Mutex::new(CaseRuntime {
                shared,
                trace,
                origin,
                session,
                local_capture,
                start_error: None,
                finished: false,
            })),
            semantic,
        }
    }

    /// Seed backing this execution.
    pub fn seed(&self) -> u64 {
        self.semantic.seed()
    }

    /// Fork the consumed RNG path into a replayable case.
    pub fn fork_case(&self) -> Case {
        self.semantic.fork_trace()
    }

    /// Generate a length in `range` and return a structured range iterator.
    pub fn range<R>(&mut self, range: R) -> RangeIter<'_, Capture>
    where
        R: RangeBounds<usize>,
    {
        RangeIter::new(self, range)
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

    fn finish(
        &mut self,
        record_coverage: bool,
        case_cost: CaseCost,
    ) -> Result<CaseCoverage, String> {
        self.runtime
            .lock()
            .expect("case rng poisoned")
            .finish(record_coverage, case_cost)
    }
}

/// Range iterator returned by [`CaseRng::range`].
pub struct RangeIter<'a, Capture: CoverageCapture = SancovCoverage> {
    runtime: Arc<Mutex<CaseRuntime<Capture>>>,
    inner: SemanticRangeIter<'a>,
}

impl<'a, Capture: CoverageCapture> RangeIter<'a, Capture> {
    fn new<R>(rng: &'a mut CaseRng<Capture>, range: R) -> Self
    where
        R: RangeBounds<usize>,
    {
        rng.runtime
            .lock()
            .expect("case rng poisoned")
            .ensure_started();
        let runtime = Arc::clone(&rng.runtime);
        let inner = rng.semantic.range(range);
        Self { runtime, inner }
    }
}

impl<'a, Capture: CoverageCapture> Iterator for RangeIter<'a, Capture> {
    type Item = CaseRng<Capture>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|semantic| CaseRng {
            runtime: Arc::clone(&self.runtime),
            semantic,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<Capture: CoverageCapture> ExactSizeIterator for RangeIter<'_, Capture> {}

impl<Capture: CoverageCapture> RngCore for CaseRng<Capture> {
    fn next_u32(&mut self) -> u32 {
        self.runtime
            .lock()
            .expect("case rng poisoned")
            .ensure_started();
        self.semantic.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.runtime
            .lock()
            .expect("case rng poisoned")
            .ensure_started();
        self.semantic.next_u64()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.runtime
            .lock()
            .expect("case rng poisoned")
            .ensure_started();
        self.semantic.fill_bytes(dst);
    }
}

impl<Capture: CoverageCapture> CaseRuntime<Capture> {
    fn ensure_started(&mut self) {
        if self.finished || self.session.is_some() || self.start_error.is_some() {
            return;
        }
        loop {
            let session = if let Some(capture) = self.local_capture.as_mut() {
                capture.start_capture()
            } else {
                self.shared
                    .lock()
                    .expect("search state poisoned")
                    .capture
                    .start_capture()
            };
            match session {
                Ok(CaptureStart::Started(session)) => {
                    self.session = Some(session);
                    return;
                }
                Ok(CaptureStart::Busy) => {
                    std::thread::yield_now();
                }
                Err(error) => {
                    self.start_error = Some(error);
                    return;
                }
            }
        }
    }

    fn finish(
        &mut self,
        record_coverage: bool,
        case_cost: CaseCost,
    ) -> Result<CaseCoverage, String> {
        if self.finished {
            return Err("coverage already finished".to_string());
        }
        self.ensure_started();
        self.finished = true;
        let snapshot = self.trace.finish()?;
        let active = active_from_snapshot(snapshot, self.origin.clone());

        let session = self.session.take();
        if let Some(mut capture) = self.local_capture.take() {
            let outcome = finish_capture(
                &mut capture,
                session,
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
                session,
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

impl<Capture> Drop for CaseRuntime<Capture>
where
    Capture: CoverageCapture,
{
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish(true, CaseCost::zero());
        }
    }
}

fn active_from_snapshot(snapshot: TraceSnapshot, origin: CandidateOrigin) -> Active {
    Active {
        seed: snapshot.seed,
        case: snapshot.trace,
        trace: snapshot.prefix,
        draws: clip_draws(snapshot.draws),
        sequences: snapshot.sequences,
        bytes_consumed: snapshot.bytes_consumed,
        origin,
    }
}

fn clip_draws(draws: Vec<Range<usize>>) -> Vec<Range<usize>> {
    draws
        .into_iter()
        .filter_map(|draw| {
            if draw.is_empty() || draw.start >= MAX_PREFIX_LEN {
                return None;
            }
            Some(draw.start..draw.end.min(MAX_PREFIX_LEN))
        })
        .collect()
}

struct FinishedCapture {
    feedback: Option<ExecutionFeedback>,
}

fn finish_capture<Capture>(
    capture: &mut Capture,
    session: Option<Capture::Session>,
    start_error: Option<String>,
    record_coverage: bool,
) -> Result<FinishedCapture, String>
where
    Capture: CoverageCapture,
{
    if !record_coverage {
        if let Some(session) = session {
            capture.discard_capture(session)?;
        }
        return Ok(FinishedCapture { feedback: None });
    }

    if let Some(error) = start_error {
        return Err(error);
    }
    let session = session.ok_or_else(|| "coverage capture never started".to_string())?;
    Ok(FinishedCapture {
        feedback: Some(capture.finish_capture(session)?),
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
        let mut corpus_prefix = active.case.flatten_prefix();
        if corpus_prefix.len() > MAX_PREFIX_LEN {
            corpus_prefix.truncate(MAX_PREFIX_LEN);
        }
        state.corpus.push(CorpusSeed {
            seed: active.seed,
            prefix: corpus_prefix,
            draws: active.draws,
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
