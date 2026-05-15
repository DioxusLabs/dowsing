use super::{
    mutate::{choose_corpus_index, havoc_prefix, mutate_prefix, refresh_corpus_energies},
    prelude::{
        CandidateOrigin, CaseCost, Cautious, Curious, Engine, MAX_PREFIX_LEN, MinPathScore, Mode,
        State,
    },
    rng::CaseRng,
    shrink::{energy_refresh_interval, next_cautious_reduction},
};
use crate::coverage::{CAPTURE_BUSY, CoverageCapture, CoverageId, ParallelCoverageCapture};
use rand::{Rng, SeedableRng, rngs::SmallRng};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

impl<Capture> Iterator for Engine<Capture>
where
    Capture: CoverageCapture,
{
    type Item = CaseRng<Capture>;

    fn next(&mut self) -> Option<Self::Item> {
        let plan = {
            let mut state = self.shared.lock().expect("search state poisoned");
            let plan = choose_candidate_plan(&mut state)?;
            state.active_cases = state.active_cases.saturating_add(1);
            plan
        };
        let candidate = materialize_candidate(plan);

        let token = match start_capture_retry(&self.shared) {
            Some(token) => token,
            None => {
                finish_started_case(&self.shared);
                return None;
            }
        };

        let mut state = self.shared.lock().expect("search state poisoned");
        state.stats.generated += 1;
        state.stats.mutated += u64::from(candidate.mutated);
        drop(state);

        Some(CaseRng {
            shared: Arc::clone(&self.shared),
            fallback: SmallRng::seed_from_u64(candidate.seed),
            seed: candidate.seed,
            prefix: candidate.prefix,
            zero_tail: candidate.zero_tail,
            origin: candidate.origin,
            cursor: 0,
            bytes_consumed: 0,
            trace: Vec::new(),
            draws: Vec::new(),
            semantics: Vec::new(),
            sequences: Vec::new(),
            token: Some(token),
            local_capture: None,
            start_error: None,
            finished: false,
        })
    }
}

impl<Capture> Iterator for Curious<Capture>
where
    Capture: CoverageCapture,
{
    type Item = CaseRng<Capture>;

    fn next(&mut self) -> Option<Self::Item> {
        self.engine.next()
    }
}

impl<Capture> Iterator for Cautious<Capture>
where
    Capture: CoverageCapture,
{
    type Item = CaseRng<Capture>;

    fn next(&mut self) -> Option<Self::Item> {
        self.engine.next()
    }
}

pub(super) fn next_parallel_rng<Capture>(
    shared: &Arc<Mutex<State<Capture>>>,
    mut capture: Capture,
) -> Option<CaseRng<Capture>>
where
    Capture: ParallelCoverageCapture,
    Capture::Token: Send,
{
    let plan = loop {
        let mut state = shared.lock().expect("search state poisoned");
        if let Some(plan) = choose_candidate_plan(&mut state) {
            state.active_cases = state.active_cases.saturating_add(1);
            break plan;
        }
        if state.active_cases == 0 {
            return None;
        }
        drop(state);
        std::thread::yield_now();
    };
    let candidate = materialize_candidate(plan);

    let token = match start_local_capture_retry(&mut capture) {
        Some(token) => token,
        None => {
            finish_started_case(shared);
            return None;
        }
    };

    {
        let mut state = shared.lock().expect("search state poisoned");
        state.stats.generated += 1;
        state.stats.mutated += u64::from(candidate.mutated);
    }

    Some(CaseRng {
        shared: Arc::clone(shared),
        fallback: SmallRng::seed_from_u64(candidate.seed),
        seed: candidate.seed,
        prefix: candidate.prefix,
        zero_tail: candidate.zero_tail,
        origin: candidate.origin,
        cursor: 0,
        bytes_consumed: 0,
        trace: Vec::new(),
        draws: Vec::new(),
        semantics: Vec::new(),
        sequences: Vec::new(),
        token: Some(token),
        local_capture: Some(capture),
        start_error: None,
        finished: false,
    })
}

fn start_capture_retry<Capture>(shared: &Arc<Mutex<State<Capture>>>) -> Option<Capture::Token>
where
    Capture: CoverageCapture,
{
    loop {
        let token = shared
            .lock()
            .expect("search state poisoned")
            .capture
            .start_capture();
        match token {
            Ok(token) => return Some(token),
            Err(error) if error == CAPTURE_BUSY => {
                std::thread::yield_now();
            }
            Err(_) => return None,
        }
    }
}

fn start_local_capture_retry<Capture>(capture: &mut Capture) -> Option<Capture::Token>
where
    Capture: CoverageCapture,
{
    loop {
        match capture.start_capture() {
            Ok(token) => return Some(token),
            Err(error) if error == CAPTURE_BUSY => std::thread::yield_now(),
            Err(_) => return None,
        }
    }
}

fn finish_started_case<Capture>(shared: &Arc<Mutex<State<Capture>>>)
where
    Capture: CoverageCapture,
{
    let mut state = shared.lock().expect("search state poisoned");
    state.active_cases = state.active_cases.saturating_sub(1);
}

#[derive(Debug, Clone)]
pub(super) struct Candidate {
    pub(super) seed: u64,
    pub(super) prefix: Vec<u8>,
    pub(super) mutated: bool,
    pub(super) zero_tail: bool,
    pub(super) origin: CandidateOrigin,
}

#[derive(Debug, Clone)]
enum CandidatePlan {
    Ready(Candidate),
    CuriousMutation {
        parent_seed: u64,
        parent_prefix: Vec<u8>,
        crossover_prefix: Option<Vec<u8>>,
        dictionary: Vec<Vec<u8>>,
        fallback: u64,
        rng_seed: u64,
        depth: usize,
    },
    CautiousMutation {
        parent_seed: u64,
        parent_prefix: Vec<u8>,
        dictionary: Vec<Vec<u8>>,
        fallback: u64,
        rng_seed: u64,
        depth: usize,
    },
}

fn choose_candidate_plan<Capture: CoverageCapture>(
    state: &mut State<Capture>,
) -> Option<CandidatePlan> {
    if let Some(case) = state.pending_cases.pop_front() {
        return Some(CandidatePlan::Ready(Candidate {
            seed: case.seed,
            prefix: case.prefix,
            mutated: false,
            zero_tail: state.mode == Mode::Cautious || case.zero_tail,
            origin: CandidateOrigin::SeededCase,
        }));
    }

    if state.mode == Mode::Cautious && state.corpus.is_empty() {
        return None;
    }

    if state.mode == Mode::Cautious {
        return choose_cautious_candidate_plan(state);
    }

    let fallback = state.base_seed.wrapping_add(state.next);
    state.next = state.next.wrapping_add(1);

    let pull_fresh_root = if state.corpus.is_empty() {
        true
    } else {
        state.seed_step = state.seed_step.wrapping_add(1);
        state.seed_step.is_multiple_of(state.seed_ratio)
    };
    if pull_fresh_root {
        return Some(CandidatePlan::Ready(Candidate {
            seed: fallback,
            prefix: Vec::new(),
            mutated: false,
            zero_tail: false,
            origin: CandidateOrigin::SeededCase,
        }));
    }

    let Some(index) = choose_corpus_index(state) else {
        return Some(CandidatePlan::Ready(Candidate {
            seed: fallback,
            prefix: Vec::new(),
            mutated: false,
            zero_tail: false,
            origin: CandidateOrigin::SeededCase,
        }));
    };

    let (parent_seed, parent_prefix) = {
        let parent = &state.corpus[index];
        (parent.seed, parent.prefix.clone())
    };
    let crossover_prefix = if state.corpus.len() > 1 {
        let other_index = state.scheduler.random_range(0..state.corpus.len());
        Some(state.corpus[other_index].prefix.clone())
    } else {
        None
    };
    let rng_seed = state.scheduler.random();
    Some(CandidatePlan::CuriousMutation {
        parent_seed,
        parent_prefix,
        crossover_prefix,
        dictionary: state.dictionary.clone(),
        fallback,
        rng_seed,
        depth: state.mutate_depth.max(1),
    })
}

fn choose_cautious_candidate_plan<Capture: CoverageCapture>(
    state: &mut State<Capture>,
) -> Option<CandidatePlan> {
    if let Some(candidate) = next_cautious_reduction(state) {
        return Some(CandidatePlan::Ready(candidate));
    }
    if !state.cautious_options.havoc() {
        return None;
    }

    let index = cautious_corpus_index(state)?;
    let (parent_seed, parent_prefix) = {
        let parent = &state.corpus[index];
        (parent.seed, parent.prefix.clone())
    };
    record_cautious_schedule(state);
    let fallback = state.base_seed.wrapping_add(state.next);
    state.next = state.next.wrapping_add(1);
    let rng_seed = state.scheduler.random();
    Some(CandidatePlan::CautiousMutation {
        parent_seed,
        parent_prefix,
        dictionary: state.dictionary.clone(),
        fallback,
        rng_seed,
        depth: state.mutate_depth.max(1),
    })
}

fn materialize_candidate(plan: CandidatePlan) -> Candidate {
    match plan {
        CandidatePlan::Ready(candidate) => candidate,
        CandidatePlan::CuriousMutation {
            parent_seed,
            parent_prefix,
            crossover_prefix,
            dictionary,
            fallback,
            rng_seed,
            depth,
        } => {
            let mut rng = SmallRng::seed_from_u64(rng_seed);
            let mut prefix = parent_prefix;
            for _ in 0..depth {
                mutate_prefix(
                    &mut prefix,
                    &mut rng,
                    crossover_prefix.as_deref(),
                    &dictionary,
                    fallback,
                );
            }
            if prefix.is_empty() {
                prefix.push(rng.random());
            }
            if prefix.len() > MAX_PREFIX_LEN {
                prefix.truncate(MAX_PREFIX_LEN);
            }

            Candidate {
                seed: parent_seed ^ fallback.rotate_left(17),
                prefix,
                mutated: true,
                zero_tail: false,
                origin: CandidateOrigin::CuriousMutation,
            }
        }
        CandidatePlan::CautiousMutation {
            parent_seed,
            parent_prefix,
            dictionary,
            fallback,
            rng_seed,
            depth,
        } => {
            let mut rng = SmallRng::seed_from_u64(rng_seed);
            let prefix = havoc_prefix(&parent_prefix, &mut rng, depth, &dictionary);
            Candidate {
                seed: parent_seed ^ fallback.rotate_left(17),
                prefix,
                mutated: true,
                zero_tail: true,
                origin: CandidateOrigin::CautiousHavoc,
            }
        }
    }
}

fn cautious_corpus_index<Capture: CoverageCapture>(state: &mut State<Capture>) -> Option<usize> {
    state
        .energy_index
        .sample(&mut state.scheduler)
        .or_else(|| Some(state.scheduler.random_range(0..state.corpus.len())))
}

fn record_cautious_schedule<Capture: CoverageCapture>(state: &mut State<Capture>) {
    state.executions_since_refresh = state.executions_since_refresh.saturating_add(1);
    if state.executions_since_refresh >= energy_refresh_interval(state.mode) {
        refresh_corpus_energies(state);
    }
}

pub(super) fn min_path_schedule_energy(
    removed_frequency: &HashMap<CoverageId, u64>,
    accepted: u64,
    best: MinPathScore,
    removed: &[CoverageId],
    candidate: MinPathScore,
) -> f64 {
    let accepted = accepted.max(1) as f64;
    let mut rarity = 0.0;
    for id in removed {
        let frequency = (*removed_frequency.get(id).unwrap_or(&1)).max(1) as f64;
        rarity += (accepted / frequency).ln().max(0.0);
    }

    let byte_quality = ((best.bytes + 1) as f64 / (candidate.bytes + 1) as f64)
        .min(1.0)
        .powi(3);
    let feature_quality = ((best.features + 1) as f64 / (candidate.features + 1) as f64)
        .min(1.0)
        .sqrt();
    let hit_quality = ((best.hit_count_weight + 1) as f64
        / (candidate.hit_count_weight + 1) as f64)
        .min(1.0)
        .sqrt();
    let cost_quality = case_cost_quality(best.case_cost, candidate.case_cost).powi(3);
    let simplicity_quality = ((best.nonzero_bytes + 1) as f64
        / (candidate.nonzero_bytes + 1) as f64)
        .min(1.0)
        .sqrt();
    let quality = cost_quality * byte_quality * feature_quality * hit_quality * simplicity_quality;
    ((rarity + 1.0) * quality).max(0.01)
}

fn case_cost_quality(best: CaseCost, candidate: CaseCost) -> f64 {
    (best.get().saturating_add(1) as f64 / candidate.get().saturating_add(1) as f64).min(1.0)
}
