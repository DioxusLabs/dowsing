use super::{
    mutate::{havoc_prefix, mutate_prefix},
    optimize::{
        BuiltInMutationSource, Goal, MutationContext, MutationSourceKind, Optimizer,
        builtin_source_enabled, record_mutation_scheduled, select_goal_corpus_index,
    },
    prelude::{
        CandidateOrigin, Case, Cautious, Curious, Engine, MAX_PREFIX_LEN, MutationWeights, State,
        StateCore,
    },
    rng::CaseRng,
    shrink::next_cautious_reduction,
};
use crate::coverage::{CaptureStart, CoverageCapture, ParallelCoverageCapture};
use parking_lot::Mutex;
use rand::{Rng, SeedableRng, rngs::SmallRng};
use std::sync::Arc;

impl<Capture> Iterator for Engine<Capture>
where
    Capture: CoverageCapture,
{
    type Item = CaseRng<Capture>;

    fn next(&mut self) -> Option<Self::Item> {
        let plan = {
            let mut state = self.shared.lock();
            let plan = choose_candidate_plan(&mut state.core)?;
            let plan_is_mutation = plan.is_mutation();
            state.active_cases = state.active_cases.saturating_add(1);
            state.stats.generated += 1;
            state.stats.mutated += u64::from(plan_is_mutation);
            plan
        };
        let candidate = materialize_candidate(plan);

        let session = match start_capture_retry(&self.shared) {
            Some(session) => session,
            None => {
                finish_started_case(&self.shared);
                return None;
            }
        };

        Some(CaseRng::new(
            Arc::clone(&self.shared),
            candidate.case,
            candidate.origin,
            Some(session),
            None,
        ))
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

impl<G, Capture> Iterator for Optimizer<G, Capture>
where
    G: Goal,
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
    Capture::Session: Send,
{
    let plan = loop {
        let mut state = shared.lock();
        if let Some(plan) = choose_candidate_plan(&mut state.core) {
            let plan_is_mutation = plan.is_mutation();
            state.active_cases = state.active_cases.saturating_add(1);
            state.stats.generated += 1;
            state.stats.mutated += u64::from(plan_is_mutation);
            break plan;
        }
        if state.active_cases == 0 {
            return None;
        }
        drop(state);
        std::thread::yield_now();
    };
    let candidate = materialize_candidate(plan);

    let session = match start_local_capture_retry(&mut capture) {
        Some(session) => session,
        None => {
            finish_started_case(shared);
            return None;
        }
    };

    Some(CaseRng::new(
        Arc::clone(shared),
        candidate.case,
        candidate.origin,
        Some(session),
        Some(capture),
    ))
}

fn start_capture_retry<Capture>(shared: &Arc<Mutex<State<Capture>>>) -> Option<Capture::Session>
where
    Capture: CoverageCapture,
{
    loop {
        let session = shared.lock().capture.start_capture();
        match session {
            Ok(CaptureStart::Started(session)) => return Some(session),
            Ok(CaptureStart::Busy) => {
                std::thread::yield_now();
            }
            Err(_) => return None,
        }
    }
}

fn start_local_capture_retry<Capture>(capture: &mut Capture) -> Option<Capture::Session>
where
    Capture: CoverageCapture,
{
    loop {
        match capture.start_capture() {
            Ok(CaptureStart::Started(session)) => return Some(session),
            Ok(CaptureStart::Busy) => std::thread::yield_now(),
            Err(_) => return None,
        }
    }
}

fn finish_started_case<Capture>(shared: &Arc<Mutex<State<Capture>>>)
where
    Capture: CoverageCapture,
{
    let mut state = shared.lock();
    state.active_cases = state.active_cases.saturating_sub(1);
}

#[derive(Debug, Clone)]
pub(super) struct Candidate {
    pub(super) case: Case,
    pub(super) mutated: bool,
    pub(super) origin: CandidateOrigin,
}

#[derive(Debug, Clone)]
enum CandidatePlan {
    Ready(Candidate),
    BuiltInMutation {
        source: BuiltInMutationSource,
        parent_seed: u64,
        parent_prefix: Vec<u8>,
        crossover_prefix: Option<Vec<u8>>,
        dictionary: Arc<Vec<Vec<u8>>>,
        mutation_weights: MutationWeights,
        fallback: u64,
        rng_seed: u64,
        depth: usize,
    },
}

impl CandidatePlan {
    fn is_mutation(&self) -> bool {
        match self {
            Self::Ready(candidate) => candidate.mutated,
            Self::BuiltInMutation { .. } => true,
        }
    }
}

fn choose_candidate_plan(state: &mut StateCore) -> Option<CandidatePlan> {
    if let Some(case) = state.pending_cases.pop_front() {
        return Some(CandidatePlan::Ready(Candidate {
            case,
            mutated: false,
            origin: CandidateOrigin::SeededCase,
        }));
    }

    if state.corpus.is_empty() {
        return state.fresh_roots.then(|| {
            CandidatePlan::Ready(Candidate {
                case: Case::empty(next_fallback_seed(state)),
                mutated: false,
                origin: CandidateOrigin::SeededCase,
            })
        });
    }

    if state.fresh_roots {
        state.seed_step = state.seed_step.wrapping_add(1);
        if state.seed_step.is_multiple_of(state.seed_ratio) {
            return Some(CandidatePlan::Ready(Candidate {
                case: Case::empty(next_fallback_seed(state)),
                mutated: false,
                origin: CandidateOrigin::SeededCase,
            }));
        }
    }

    choose_source_candidate_plan(state)
}

fn choose_source_candidate_plan(state: &mut StateCore) -> Option<CandidatePlan> {
    let mut index = 0;
    while index < state.candidate_sources.len() {
        let mut source = state.candidate_sources.remove(index);
        let plan = match &mut source.kind {
            MutationSourceKind::BuiltIn(source) => choose_builtin_source_plan(state, *source),
            MutationSourceKind::Custom(source) => choose_custom_source_plan(state, index, source),
        };
        state.candidate_sources.insert(index, source);
        if plan.is_some() {
            return plan;
        }
        index += 1;
    }
    None
}

fn choose_builtin_source_plan(
    state: &mut StateCore,
    source: BuiltInMutationSource,
) -> Option<CandidatePlan> {
    if !builtin_source_enabled(state, source) {
        return None;
    }

    match source {
        BuiltInMutationSource::SemanticReductions => {
            next_cautious_reduction(state).map(CandidatePlan::Ready)
        }
        BuiltInMutationSource::CoverageHavoc => choose_havoc_source_plan(state, source),
        BuiltInMutationSource::MinimizingHavoc => choose_havoc_source_plan(state, source),
    }
}

fn choose_havoc_source_plan(
    state: &mut StateCore,
    source: BuiltInMutationSource,
) -> Option<CandidatePlan> {
    let index = scheduled_corpus_index(state)?;
    let (parent_seed, parent_prefix) = {
        let parent = &state.corpus[index];
        (parent.seed, parent.prefix.clone())
    };
    let crossover_prefix =
        if source == BuiltInMutationSource::CoverageHavoc && state.corpus.len() > 1 {
            let other_index = state.scheduler.random_range(0..state.corpus.len());
            Some(state.corpus[other_index].prefix.clone())
        } else {
            None
        };
    record_mutation_schedule(state);
    let fallback = next_fallback_seed(state);
    let rng_seed = state.scheduler.random();
    Some(CandidatePlan::BuiltInMutation {
        source,
        parent_seed,
        parent_prefix,
        crossover_prefix,
        dictionary: Arc::clone(&state.dictionary),
        mutation_weights: state.mutation_weights.clone(),
        fallback,
        rng_seed,
        depth: state.mutate_depth.max(1),
    })
}

fn choose_custom_source_plan(
    state: &mut StateCore,
    source_index: usize,
    source: &mut Box<dyn super::optimize::CandidateSource>,
) -> Option<CandidatePlan> {
    let index = scheduled_corpus_index(state)?;
    let (parent_case, parent_seed, parent_prefix, draws, scalars, sequences) = {
        let parent = &state.corpus[index];
        (
            parent.case.clone(),
            parent.seed,
            parent.prefix.clone(),
            parent.draws.clone(),
            parent.scalars.clone(),
            parent.sequences.clone(),
        )
    };
    let fallback = state.base_seed.wrapping_add(state.next);
    let rng_seed = state.scheduler.random();
    let dictionary = Arc::clone(&state.dictionary);
    let mut rng = SmallRng::seed_from_u64(rng_seed);
    let mut context = MutationContext::new(
        &parent_case,
        &parent_prefix,
        &draws,
        &scalars,
        &sequences,
        &dictionary,
        &mut rng,
        fallback,
    );
    let candidate = source.next_candidate(&mut context)?;
    record_mutation_schedule(state);
    state.next = state.next.wrapping_add(1);
    let (case, mutations) = candidate.materialize(parent_seed, fallback, &mut rng);
    Some(CandidatePlan::Ready(Candidate {
        case,
        mutated: true,
        origin: CandidateOrigin::CustomMutation {
            source: source_index,
            mutations,
        },
    }))
}

fn materialize_candidate(plan: CandidatePlan) -> Candidate {
    match plan {
        CandidatePlan::Ready(candidate) => candidate,
        CandidatePlan::BuiltInMutation {
            source,
            parent_seed,
            parent_prefix,
            crossover_prefix,
            dictionary,
            mutation_weights,
            fallback,
            rng_seed,
            depth,
        } => {
            let mut rng = SmallRng::seed_from_u64(rng_seed);
            match source {
                BuiltInMutationSource::CoverageHavoc => {
                    let mut prefix = parent_prefix;
                    let mut kinds = Vec::new();
                    for _ in 0..depth {
                        if let Some(kind) = mutate_prefix(
                            &mut prefix,
                            &mut rng,
                            crossover_prefix.as_deref(),
                            &dictionary,
                            fallback,
                            &mutation_weights,
                        ) {
                            kinds.push(kind);
                        }
                    }
                    if prefix.is_empty() {
                        prefix.push(rng.random());
                    }
                    if prefix.len() > MAX_PREFIX_LEN {
                        prefix.truncate(MAX_PREFIX_LEN);
                    }

                    Candidate {
                        case: Case::from_flat_prefix(
                            parent_seed ^ fallback.rotate_left(17),
                            prefix,
                        ),
                        mutated: true,
                        origin: CandidateOrigin::CuriousMutation(kinds),
                    }
                }
                BuiltInMutationSource::MinimizingHavoc => {
                    let (prefix, kinds) = havoc_prefix(
                        &parent_prefix,
                        &mut rng,
                        depth,
                        &dictionary,
                        &mutation_weights,
                    );
                    Candidate {
                        case: Case::from_flat_prefix(
                            parent_seed ^ fallback.rotate_left(17),
                            prefix,
                        ),
                        mutated: true,
                        origin: CandidateOrigin::CautiousHavoc(kinds),
                    }
                }
                BuiltInMutationSource::SemanticReductions => unreachable!("reduction is ready"),
            }
        }
    }
}

fn scheduled_corpus_index(state: &mut StateCore) -> Option<usize> {
    select_goal_corpus_index(state)
}

fn record_mutation_schedule(state: &mut StateCore) {
    record_mutation_scheduled(state);
}

fn next_fallback_seed(state: &mut StateCore) -> u64 {
    let fallback = state.base_seed.wrapping_add(state.next);
    state.next = state.next.wrapping_add(1);
    fallback
}
