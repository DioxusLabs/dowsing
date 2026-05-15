use super::{
    api::coverage_delta,
    mutate::{corpus_energy, refresh_corpus_energies},
    prelude::{Active, Case, CaseCoverage, CorpusSeed, MAX_PREFIX_LEN, MinPathScore, Mode, State},
    run::min_path_schedule_energy,
    shrink::{
        energy_refresh_interval, enqueue_cautious_best_neighbors, merge_dictionary_values,
        prune_corpus,
    },
};
use crate::{
    coverage::{CAPTURE_BUSY, CoverageCapture, ExecutionFeedback},
    sancov::SancovCoverage,
};
use rand::{RngCore, rngs::SmallRng};
use std::sync::{Arc, Mutex};

/// RNG yielded by [`crate::Curious`] and [`crate::Cautious`].
pub struct CaseRng<Capture: CoverageCapture = SancovCoverage> {
    pub(super) shared: Arc<Mutex<State<Capture>>>,
    pub(super) fallback: SmallRng,
    pub(super) seed: u64,
    pub(super) prefix: Vec<u8>,
    pub(super) zero_tail: bool,
    pub(super) cursor: usize,
    pub(super) bytes_consumed: usize,
    pub(super) trace: Vec<u8>,
    pub(super) token: Option<Capture::Token>,
    pub(super) local_capture: Option<Capture>,
    pub(super) start_error: Option<String>,
    pub(super) finished: bool,
}

impl<Capture: CoverageCapture> CaseRng<Capture> {
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
        }
    }

    /// Finish this execution immediately and return its coverage stats.
    ///
    /// This consumes the RNG because coverage is only meaningful after the caller has finished
    /// executing the path being measured.
    pub fn coverage(mut self) -> Result<CaseCoverage, String> {
        self.finish(true)
    }

    /// Exclude this execution from coverage feedback when the RNG is dropped.
    pub fn discard(mut self) {
        let _ = self.finish(false);
    }
}

impl<Capture: CoverageCapture> RngCore for CaseRng<Capture> {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.traced_word_bytes())
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(self.traced_word_bytes())
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for byte in dst {
            *byte = self.next_byte();
        }
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

    fn finish(&mut self, record_coverage: bool) -> Result<CaseCoverage, String> {
        if self.finished {
            return Err("coverage already finished".to_string());
        }
        self.ensure_started();
        self.finished = true;

        let active = Active {
            seed: self.seed,
            trace: std::mem::take(&mut self.trace),
            bytes_consumed: self.bytes_consumed,
        };
        let token = self.token.take();
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
                    merge_finished_execution(&mut state, active, outcome)
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
                Ok(outcome) => merge_finished_execution(&mut state, active, outcome),
                Err(error) => {
                    state.stats.executed += 1;
                    state.active_cases = state.active_cases.saturating_sub(1);
                    Err(error)
                }
            }
        }
    }
}

impl<Capture> Drop for CaseRng<Capture>
where
    Capture: CoverageCapture,
{
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish(true);
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
) -> Result<CaseCoverage, String>
where
    Capture: CoverageCapture,
{
    state.stats.executed += 1;
    state.active_cases = state.active_cases.saturating_sub(1);

    let Some(feedback) = finished.feedback else {
        return Ok(CaseCoverage {
            feature_count: 0,
            hit_count_weight: 0,
            bytes_consumed: active.bytes_consumed,
        });
    };
    merge_dictionary_values(state, feedback.dictionary);

    let coverage = feedback.features;
    let run_coverage = CaseCoverage {
        feature_count: coverage.len(),
        hit_count_weight: feedback.hit_count_weight,
        bytes_consumed: active.bytes_consumed,
    };
    let score = run_coverage.feature_count;
    let hit_count_weight = run_coverage.hit_count_weight;
    let path_len = run_coverage.bytes_consumed;
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
    let candidate_score = MinPathScore::new(score, hit_count_weight, path_len);
    let improves_best_cautious = best_cautious_score.is_none_or(|best| candidate_score < best);

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
                    score,
                    hit_count_weight,
                    path_len,
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
            coverage: coverage_ids,
            removed: removed_ids,
            score,
            hit_count_weight,
            path_len,
            energy,
        });
        let inserted_index = state.corpus.len() - 1;
        state.energy_index.push(energy);
        if state.mode == Mode::Cautious && improves_best_cautious {
            state.min_path_best = Some(candidate_score);
            state.min_path_best_index = Some(inserted_index);
            refresh_corpus_energies(state);
            enqueue_cautious_best_neighbors(state, inserted_index);
        }
        prune_corpus(state);
    }

    Ok(run_coverage)
}
