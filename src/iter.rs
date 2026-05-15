use crate::{
    coverage::{CAPTURE_BUSY, CoverageCapture, CoverageId, CoverageSet, ParallelCoverageCapture},
    llvm::LlvmCoverage,
    sancov::SancovCoverage,
};
use rand::{Rng, RngCore, SeedableRng, rngs::SmallRng};
use rayon::iter::{IntoParallelIterator, ParallelIterator, plumbing::UnindexedConsumer};
use std::{
    cmp::Ordering,
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

const DEFAULT_MUTATE_DEPTH: usize = 5;
const DEFAULT_SHY_MUTATE_DEPTH: usize = 4;
const DEFAULT_SEED_RATIO: u64 = 8;
const CURIOUS_ENERGY_REFRESH_INTERVAL: u64 = 64;
const SHY_ENERGY_REFRESH_INTERVAL: u64 = 1024;
const MAX_PREFIX_LEN: usize = 4096;
const MAX_CORPUS_LEN: usize = 4096;
const MAX_PENDING_CANDIDATES: usize = 128;
const MAX_SHY_BEST_NEIGHBORS: usize = 20;
const MAX_DICTIONARY_VALUES: usize = 256;
const INTERESTING_BYTES: [u8; 10] = [0, 1, 16, 31, 32, 63, 64, 127, 128, 255];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Curious,
    Shy,
}

/// Replayable RNG path produced by [`DemonicRng::fork_case`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemonicCase {
    seed: u64,
    prefix: Vec<u8>,
    zero_tail: bool,
}

impl DemonicCase {
    /// Replay this case without recording coverage.
    pub fn replay(self) -> Demonic<NoCoverage> {
        Demonic::new(NoCoverage, Mode::Curious).seed_case(self)
    }
}

/// Coverage and path-size stats for one completed [`DemonicRng`] execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DemonicCoverage {
    pub feature_count: usize,
    pub bytes_consumed: usize,
}

impl PartialOrd for DemonicCoverage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DemonicCoverage {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.bytes_consumed, self.feature_count).cmp(&(other.bytes_consumed, other.feature_count))
    }
}

/// Coverage-maximizing RNG iterator.
///
/// Each item is an RNG. The RNG owns a coverage guard; when the item is dropped at the end of the
/// caller's loop body, the guard may record coverage and update the next seed choice.
pub fn curious() -> Demonic<SancovCoverage> {
    Demonic::new(SancovCoverage::new(), Mode::Curious)
}

/// Code-path-minimizing RNG iterator.
///
/// Seed it with [`Demonic::seed_case`]. Each yielded variant records coverage unless the caller
/// excludes it with [`DemonicRng::discard`].
pub fn shy() -> Demonic<SancovCoverage> {
    Demonic::new(SancovCoverage::new(), Mode::Shy)
}

/// Iterator returned by [`curious`] and [`shy`].
pub struct Demonic<Capture: CoverageCapture = SancovCoverage> {
    shared: Arc<Mutex<State<Capture>>>,
}

#[derive(Debug)]
struct State<Capture: CoverageCapture> {
    capture: Capture,
    mode: Mode,
    base_seed: u64,
    next: u64,
    scheduler: SmallRng,
    global: CoverageSet,
    coverage_frequency: HashMap<CoverageId, u64>,
    min_path_removed_frequency: HashMap<CoverageId, u64>,
    min_path_target: CoverageSet,
    min_path_target_initialized: bool,
    min_path_best: Option<MinPathScore>,
    min_path_best_index: Option<usize>,
    corpus: Vec<CorpusSeed>,
    energy_index: EnergyIndex,
    pending_cases: VecDeque<DemonicCase>,
    pending_candidates: VecDeque<Candidate>,
    dictionary: Vec<Vec<u8>>,
    executions_since_refresh: u64,
    mutate_depth: usize,
    seed_ratio: u64,
    seed_step: u64,
    active_cases: u64,
    stats: DemonicStats,
}

#[derive(Debug)]
struct Active {
    seed: u64,
    trace: Vec<u8>,
    bytes_consumed: usize,
}

#[derive(Debug, Clone)]
struct CorpusSeed {
    seed: u64,
    prefix: Vec<u8>,
    coverage: Vec<CoverageId>,
    removed: Vec<CoverageId>,
    score: usize,
    path_len: usize,
    energy: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MinPathScore {
    bytes: usize,
    features: usize,
}

impl MinPathScore {
    fn new(feature_count: usize, bytes_consumed: usize) -> Self {
        Self {
            bytes: bytes_consumed,
            features: feature_count,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct EnergyIndex {
    weights: Vec<f64>,
    tree: Vec<f64>,
    total: f64,
}

impl EnergyIndex {
    fn push(&mut self, weight: f64) {
        self.weights.push(0.0);
        self.tree.push(0.0);
        if self.tree.len() == 1 {
            self.tree.push(0.0);
        }
        self.set(self.weights.len() - 1, weight);
    }

    fn set(&mut self, index: usize, weight: f64) {
        let Some(slot) = self.weights.get_mut(index) else {
            return;
        };
        let weight = sanitize_energy(weight);
        let delta = weight - *slot;
        *slot = weight;
        self.total += delta;

        let mut tree_index = index + 1;
        while tree_index < self.tree.len() {
            self.tree[tree_index] += delta;
            tree_index += lowbit(tree_index);
        }
    }

    fn rebuild(&mut self, weights: impl IntoIterator<Item = f64>) {
        self.weights = weights.into_iter().map(sanitize_energy).collect();
        self.total = self.weights.iter().sum();
        self.tree.clear();
        self.tree.resize(self.weights.len() + 1, 0.0);
        for index in 1..self.tree.len() {
            self.tree[index] += self.weights[index - 1];
            let parent = index + lowbit(index);
            if parent < self.tree.len() {
                self.tree[parent] += self.tree[index];
            }
        }
    }

    fn swap_remove(&mut self, index: usize) {
        if index >= self.weights.len() {
            return;
        }
        let last = self.weights.len() - 1;
        if index == last {
            self.set(last, 0.0);
            self.weights.pop();
            self.tree.pop();
            return;
        }

        let moved = self.weights[last];
        self.set(index, moved);
        self.set(last, 0.0);
        self.weights.pop();
        self.tree.pop();
    }

    fn sample(&self, rng: &mut SmallRng) -> Option<usize> {
        if self.weights.is_empty() || !self.total.is_finite() || self.total <= 0.0 {
            return None;
        }

        let mut target = rng.random::<f64>() * self.total;
        let mut index = 0;
        let mut bit = self.weights.len().next_power_of_two();
        while bit > 0 {
            let next = index + bit;
            if next < self.tree.len() && self.tree[next] <= target {
                index = next;
                target -= self.tree[next];
            }
            bit >>= 1;
        }

        Some(index.min(self.weights.len() - 1))
    }
}

fn sanitize_energy(weight: f64) -> f64 {
    if weight.is_finite() && weight > 0.0 {
        weight
    } else {
        1.0
    }
}

fn lowbit(value: usize) -> usize {
    value & value.wrapping_neg()
}

/// Counters for a [`Demonic`] run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DemonicStats {
    pub generated: u64,
    pub executed: u64,
    pub accepted: u64,
    pub coverage_ids: u64,
    pub mutated: u64,
}

impl<Capture: CoverageCapture> Demonic<Capture> {
    fn new(capture: Capture, mode: Mode) -> Self {
        Self {
            shared: Arc::new(Mutex::new(State {
                capture,
                mode,
                base_seed: 0,
                next: 0,
                scheduler: SmallRng::seed_from_u64(0xD3A0_51C0_FFEE),
                global: CoverageSet::new(),
                coverage_frequency: HashMap::new(),
                min_path_removed_frequency: HashMap::new(),
                min_path_target: CoverageSet::new(),
                min_path_target_initialized: false,
                min_path_best: None,
                min_path_best_index: None,
                corpus: Vec::new(),
                energy_index: EnergyIndex::default(),
                pending_cases: VecDeque::new(),
                pending_candidates: VecDeque::new(),
                dictionary: Vec::new(),
                executions_since_refresh: 0,
                mutate_depth: match mode {
                    Mode::Curious => DEFAULT_MUTATE_DEPTH,
                    Mode::Shy => DEFAULT_SHY_MUTATE_DEPTH,
                },
                seed_ratio: DEFAULT_SEED_RATIO,
                seed_step: 0,
                active_cases: 0,
                stats: DemonicStats::default(),
            })),
        }
    }

    /// Use a real coverage capture backend.
    pub fn coverage<NewCapture: CoverageCapture>(self, capture: NewCapture) -> Demonic<NewCapture> {
        let state = self.shared.lock().expect("demonic state poisoned");
        Demonic {
            shared: Arc::new(Mutex::new(State {
                capture,
                mode: state.mode,
                base_seed: state.base_seed,
                next: state.next,
                scheduler: state.scheduler.clone(),
                global: state.global.clone(),
                coverage_frequency: state.coverage_frequency.clone(),
                min_path_removed_frequency: state.min_path_removed_frequency.clone(),
                min_path_target: state.min_path_target.clone(),
                min_path_target_initialized: state.min_path_target_initialized,
                min_path_best: state.min_path_best,
                min_path_best_index: state.min_path_best_index,
                corpus: state.corpus.clone(),
                energy_index: state.energy_index.clone(),
                pending_cases: state.pending_cases.clone(),
                pending_candidates: state.pending_candidates.clone(),
                dictionary: state.dictionary.clone(),
                executions_since_refresh: state.executions_since_refresh,
                mutate_depth: state.mutate_depth,
                seed_ratio: state.seed_ratio,
                seed_step: state.seed_step,
                active_cases: 0,
                stats: state.stats,
            })),
        }
    }

    /// Queue a replayable RNG case to run before generated roots.
    pub fn seed_case(self, case: DemonicCase) -> Self {
        self.shared
            .lock()
            .expect("demonic state poisoned")
            .pending_cases
            .push_back(case);
        self
    }

    /// Queue replayable RNG cases to run before generated roots.
    pub fn seed_cases(self, cases: impl IntoIterator<Item = DemonicCase>) -> Self {
        self.shared
            .lock()
            .expect("demonic state poisoned")
            .pending_cases
            .extend(cases);
        self
    }

    /// Set how many byte-prefix mutations are stacked in havoc-style candidate generation.
    pub fn mutate_depth(self, depth: usize) -> Self {
        self.shared
            .lock()
            .expect("demonic state poisoned")
            .mutate_depth = depth.max(1);
        self
    }

    /// Set how often `curious()` explores a fresh random root while a corpus exists.
    pub fn seed_ratio(self, ratio: u64) -> Self {
        self.shared
            .lock()
            .expect("demonic state poisoned")
            .seed_ratio = ratio.max(1);
        self
    }

    /// Set the first seed.
    pub fn seed(self, seed: u64) -> Self {
        let mut state = self.shared.lock().expect("demonic state poisoned");
        state.base_seed = seed;
        state.next = 0;
        state.scheduler = SmallRng::seed_from_u64(seed ^ 0xD3A0_51C0_FFEE);
        drop(state);
        self
    }

    /// Limit the iterator to `limit` cases.
    ///
    /// This mirrors [`Iterator::take`] for serial use and also provides the native Rayon
    /// entrypoint through [`IntoParallelIterator`].
    pub fn take(self, limit: usize) -> DemonicTake<Capture> {
        DemonicTake {
            inner: self,
            remaining: limit,
        }
    }

    /// Current counters.
    pub fn stats(&self) -> DemonicStats {
        self.shared.lock().expect("demonic state poisoned").stats
    }

    /// Coverage accumulated by accepted executions.
    pub fn coverage_seen(&self) -> CoverageSet {
        self.shared
            .lock()
            .expect("demonic state poisoned")
            .global
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn test_corpus_energies(&self) -> Vec<f64> {
        self.shared
            .lock()
            .expect("demonic state poisoned")
            .corpus
            .iter()
            .map(|entry| entry.energy)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn test_feature_frequency(&self, id: CoverageId) -> u64 {
        *self
            .shared
            .lock()
            .expect("demonic state poisoned")
            .coverage_frequency
            .get(&id)
            .unwrap_or(&0)
    }

    #[cfg(test)]
    pub(crate) fn test_corpus_path_lens(&self) -> Vec<usize> {
        self.shared
            .lock()
            .expect("demonic state poisoned")
            .corpus
            .iter()
            .map(|entry| entry.path_len)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn test_best_path_score(&self) -> Option<(usize, usize)> {
        self.shared
            .lock()
            .expect("demonic state poisoned")
            .corpus
            .iter()
            .min_by_key(|entry| MinPathScore::new(entry.score, entry.path_len))
            .map(|entry| (entry.score, entry.path_len))
    }
}

/// Bounded demonic case stream returned by [`Demonic::take`].
pub struct DemonicTake<Capture: CoverageCapture = SancovCoverage> {
    inner: Demonic<Capture>,
    remaining: usize,
}

impl<Capture> Iterator for DemonicTake<Capture>
where
    Capture: CoverageCapture,
{
    type Item = DemonicRng<Capture>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        self.inner.next()
    }
}

/// Rayon parallel iterator for a bounded demonic case stream.
pub struct DemonicParIter<Capture: ParallelCoverageCapture = SancovCoverage> {
    shared: Arc<Mutex<State<Capture>>>,
    capture: Capture,
    limit: usize,
}

impl<Capture> IntoParallelIterator for DemonicTake<Capture>
where
    Capture: ParallelCoverageCapture,
    Capture::Token: Send,
{
    type Item = DemonicRng<Capture>;
    type Iter = DemonicParIter<Capture>;

    fn into_par_iter(self) -> Self::Iter {
        let capture = self
            .inner
            .shared
            .lock()
            .expect("demonic state poisoned")
            .capture
            .clone();
        capture
            .validate_parallel()
            .expect("coverage backend is not safe for parallel attribution");
        DemonicParIter {
            shared: self.inner.shared,
            capture,
            limit: self.remaining,
        }
    }
}

impl<Capture> ParallelIterator for DemonicParIter<Capture>
where
    Capture: ParallelCoverageCapture,
    Capture::Token: Send,
{
    type Item = DemonicRng<Capture>;

    fn drive_unindexed<Consumer>(self, consumer: Consumer) -> Consumer::Result
    where
        Consumer: UnindexedConsumer<Self::Item>,
    {
        let shared = self.shared;
        let capture = self.capture;
        (0..self.limit)
            .into_par_iter()
            .filter_map(move |_| {
                let capture = capture.clone();
                next_parallel_rng(&shared, capture)
            })
            .drive_unindexed(consumer)
    }

    fn opt_len(&self) -> Option<usize> {
        Some(self.limit)
    }
}

impl Demonic<NoCoverage> {
    /// Use LLVM counters from the current instrumented process as the coverage signal.
    pub fn llvm_coverage(self) -> Result<Demonic<LlvmCoverage>, String> {
        Ok(self.coverage(LlvmCoverage::new()?))
    }
}

impl Demonic<SancovCoverage> {
    /// Use LLVM source-profile counters instead of SanitizerCoverage feedback.
    pub fn llvm_coverage(self) -> Result<Demonic<LlvmCoverage>, String> {
        Ok(self.coverage(LlvmCoverage::new()?))
    }
}

fn coverage_delta(global: &CoverageSet, candidate: &CoverageSet) -> CoverageSet {
    candidate.difference(global)
}

impl<Capture> Iterator for Demonic<Capture>
where
    Capture: CoverageCapture,
{
    type Item = DemonicRng<Capture>;

    fn next(&mut self) -> Option<Self::Item> {
        let plan = {
            let mut state = self.shared.lock().expect("demonic state poisoned");
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

        let mut state = self.shared.lock().expect("demonic state poisoned");
        state.stats.generated += 1;
        state.stats.mutated += u64::from(candidate.mutated);
        drop(state);

        Some(DemonicRng {
            shared: Arc::clone(&self.shared),
            fallback: SmallRng::seed_from_u64(candidate.seed),
            seed: candidate.seed,
            prefix: candidate.prefix,
            zero_tail: candidate.zero_tail,
            cursor: 0,
            bytes_consumed: 0,
            trace: Vec::new(),
            token: Some(token),
            local_capture: None,
            start_error: None,
            finished: false,
        })
    }
}

fn next_parallel_rng<Capture>(
    shared: &Arc<Mutex<State<Capture>>>,
    mut capture: Capture,
) -> Option<DemonicRng<Capture>>
where
    Capture: ParallelCoverageCapture,
    Capture::Token: Send,
{
    let plan = loop {
        let mut state = shared.lock().expect("demonic state poisoned");
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
        let mut state = shared.lock().expect("demonic state poisoned");
        state.stats.generated += 1;
        state.stats.mutated += u64::from(candidate.mutated);
    }

    Some(DemonicRng {
        shared: Arc::clone(shared),
        fallback: SmallRng::seed_from_u64(candidate.seed),
        seed: candidate.seed,
        prefix: candidate.prefix,
        zero_tail: candidate.zero_tail,
        cursor: 0,
        bytes_consumed: 0,
        trace: Vec::new(),
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
            .expect("demonic state poisoned")
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
    let mut state = shared.lock().expect("demonic state poisoned");
    state.active_cases = state.active_cases.saturating_sub(1);
}

#[derive(Debug, Clone)]
struct Candidate {
    seed: u64,
    prefix: Vec<u8>,
    mutated: bool,
    zero_tail: bool,
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
    ShyMutation {
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
            zero_tail: state.mode == Mode::Shy || case.zero_tail,
        }));
    }

    if let Some(candidate) = state.pending_candidates.pop_front() {
        return Some(CandidatePlan::Ready(candidate));
    }

    if state.mode == Mode::Shy && state.corpus.is_empty() {
        return None;
    }

    if state.mode == Mode::Shy {
        return choose_shy_candidate_plan(state);
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
        }));
    }

    let Some(index) = choose_corpus_index(state) else {
        return Some(CandidatePlan::Ready(Candidate {
            seed: fallback,
            prefix: Vec::new(),
            mutated: false,
            zero_tail: false,
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

fn choose_shy_candidate_plan<Capture: CoverageCapture>(
    state: &mut State<Capture>,
) -> Option<CandidatePlan> {
    let index = min_path_corpus_index(state)?;
    let (parent_seed, parent_prefix) = {
        let parent = &state.corpus[index];
        (parent.seed, parent.prefix.clone())
    };
    record_min_path_schedule(state);
    let fallback = state.base_seed.wrapping_add(state.next);
    state.next = state.next.wrapping_add(1);
    let rng_seed = state.scheduler.random();
    Some(CandidatePlan::ShyMutation {
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
            }
        }
        CandidatePlan::ShyMutation {
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
            }
        }
    }
}

fn min_path_corpus_index<Capture: CoverageCapture>(state: &mut State<Capture>) -> Option<usize> {
    state
        .energy_index
        .sample(&mut state.scheduler)
        .or_else(|| Some(state.scheduler.random_range(0..state.corpus.len())))
}

fn record_min_path_schedule<Capture: CoverageCapture>(state: &mut State<Capture>) {
    state.executions_since_refresh = state.executions_since_refresh.saturating_add(1);
    if state.executions_since_refresh >= energy_refresh_interval(state.mode) {
        refresh_corpus_energies(state);
    }
}

fn min_path_schedule_energy(
    removed_frequency: &HashMap<CoverageId, u64>,
    accepted: u64,
    best: MinPathScore,
    removed: &[CoverageId],
    score: usize,
    path_len: usize,
) -> f64 {
    let accepted = accepted.max(1) as f64;
    let mut rarity = 0.0;
    for id in removed {
        let frequency = (*removed_frequency.get(id).unwrap_or(&1)).max(1) as f64;
        rarity += (accepted / frequency).ln().max(0.0);
    }

    let byte_quality = ((best.bytes + 1) as f64 / (path_len + 1) as f64)
        .min(1.0)
        .powi(3);
    let feature_quality = ((best.features + 1) as f64 / (score + 1) as f64)
        .min(1.0)
        .sqrt();
    let quality = byte_quality * feature_quality;
    ((rarity + 1.0) * quality).max(0.01)
}

fn havoc_prefix(
    prefix: &[u8],
    rng: &mut SmallRng,
    depth: usize,
    dictionary: &[Vec<u8>],
) -> Vec<u8> {
    let mut candidate = prefix.to_vec();
    for _ in 0..depth.max(1) {
        mutate_minimizing_havoc(&mut candidate, rng, dictionary);
        if candidate.len() > MAX_PREFIX_LEN {
            candidate.truncate(MAX_PREFIX_LEN);
        }
    }
    if candidate == prefix {
        mutate_minimizing_havoc(&mut candidate, rng, dictionary);
    }
    candidate
}

fn mutate_minimizing_havoc(prefix: &mut Vec<u8>, rng: &mut SmallRng, dictionary: &[Vec<u8>]) {
    match rng.random_range(0..32) {
        0..=4 if prefix.len() > 1 => {
            let removed = drain_minimizing_chunk(prefix, rng, true);
            shrink_leading_byte(prefix, removed, rng);
        }
        5..=7 if prefix.len() > 1 => {
            drain_minimizing_chunk(prefix, rng, false);
        }
        8 if prefix.len() > 1 => {
            let keep_from = rng.random_range(1..prefix.len());
            prefix.drain(0..keep_from);
        }
        9..=10 if prefix.len() > 1 => {
            let keep = 1 + minimizing_index(prefix.len() - 1, rng);
            let removed = prefix.len() - keep;
            prefix.truncate(keep);
            shrink_leading_byte(prefix, removed, rng);
        }
        11 if !prefix.is_empty() => {
            let len = minimizing_index(prefix.len(), rng);
            prefix.truncate(len);
        }
        12..=13 if !prefix.is_empty() => {
            let start = minimizing_index(prefix.len(), rng);
            let end = minimizing_end(prefix.len(), start, rng);
            prefix[start..end].fill(0);
        }
        14..=17 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = shrink_byte(prefix[index], rng);
        }
        18 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = small_or_interesting_byte(rng);
        }
        19 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] ^= 1 << rng.random_range(0..8);
        }
        20 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = prefix[index].wrapping_add(rng.random_range(1..=35));
        }
        21 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = prefix[index].wrapping_sub(rng.random_range(1..=35));
        }
        22 if !dictionary.is_empty() && !prefix.is_empty() => {
            let bytes = &dictionary[rng.random_range(0..dictionary.len())];
            replace_bytes(prefix, rng, bytes);
        }
        23 if !dictionary.is_empty() => {
            let bytes = &dictionary[rng.random_range(0..dictionary.len())];
            insert_bytes(prefix, rng, bytes);
        }
        24 if prefix.len() >= 2 => {
            mutate_word(prefix, rng, 2);
        }
        25 if prefix.len() >= 4 => {
            mutate_word(prefix, rng, 4);
        }
        26 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = 0;
        }
        27 if prefix.len() > 1 => {
            let index = minimizing_index(prefix.len(), rng);
            prefix.remove(index);
        }
        28 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = rng.random();
        }
        29 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = prefix[index].min(small_or_interesting_byte(rng));
        }
        30 if prefix.len() > 1 => {
            let start = minimizing_index(prefix.len(), rng);
            let end = minimizing_end(prefix.len(), start, rng);
            for byte in &mut prefix[start..end] {
                *byte = small_or_interesting_byte(rng);
            }
        }
        31 => {
            let index = rng.random_range(0..=prefix.len());
            prefix.insert(index, rng.random());
        }
        _ if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = shrink_byte(prefix[index], rng);
        }
        _ => prefix.push(rng.random()),
    }
}

fn drain_minimizing_chunk(prefix: &mut Vec<u8>, rng: &mut SmallRng, body_only: bool) -> usize {
    let start = if body_only && prefix.len() > 1 {
        1 + minimizing_index(prefix.len() - 1, rng)
    } else {
        minimizing_index(prefix.len(), rng)
    };
    let end = minimizing_end(prefix.len(), start, rng);
    let removed = end - start;
    prefix.drain(start..end);
    removed
}

fn shrink_leading_byte(prefix: &mut [u8], removed: usize, rng: &mut SmallRng) {
    let Some(first) = prefix.first_mut() else {
        return;
    };
    let max = removed.min(16) as u8;
    if max != 0 {
        *first = first.saturating_sub(rng.random_range(1..=max));
    }
}

fn minimizing_index(len: usize, rng: &mut SmallRng) -> usize {
    if len <= 1 {
        return 0;
    }
    if rng.random_bool(0.25) {
        return 0;
    }
    rng.random_range(0..len)
        .min(rng.random_range(0..len))
        .min(rng.random_range(0..len))
}

fn minimizing_end(len: usize, start: usize, rng: &mut SmallRng) -> usize {
    let remaining = len - start;
    let max_len = remaining.min(1 << rng.random_range(0..=remaining.ilog2()));
    start + rng.random_range(1..=max_len.max(1))
}

fn small_or_interesting_byte(rng: &mut SmallRng) -> u8 {
    if rng.random_bool(0.75) {
        rng.random_range(0..=16)
    } else {
        interesting_byte(rng)
    }
}

fn shrink_byte(byte: u8, rng: &mut SmallRng) -> u8 {
    if byte == 0 {
        0
    } else if rng.random_bool(0.5) {
        rng.random_range(0..=byte)
    } else {
        byte.saturating_sub(rng.random_range(1..=byte.min(16)))
    }
}

fn choose_corpus_index<Capture: CoverageCapture>(state: &mut State<Capture>) -> Option<usize> {
    if state.corpus.is_empty() {
        return None;
    }

    entropic_corpus_index(state)
}

fn entropic_corpus_index<Capture: CoverageCapture>(state: &mut State<Capture>) -> Option<usize> {
    state
        .energy_index
        .sample(&mut state.scheduler)
        .or_else(|| Some(state.scheduler.random_range(0..state.corpus.len())))
}

fn mutate_prefix(
    prefix: &mut Vec<u8>,
    rng: &mut SmallRng,
    crossover_prefix: Option<&[u8]>,
    dictionary: &[Vec<u8>],
    salt: u64,
) {
    match rng.random_range(0..14) {
        0 if !prefix.is_empty() => {
            let index = rng.random_range(0..prefix.len());
            prefix[index] ^= 1 << rng.random_range(0..8);
        }
        1 if !prefix.is_empty() => {
            let index = rng.random_range(0..prefix.len());
            prefix[index] = rng.random();
        }
        2 => {
            let index = rng.random_range(0..=prefix.len());
            prefix.insert(index, rng.random());
        }
        3 if prefix.len() > 1 => {
            let index = rng.random_range(0..prefix.len());
            prefix.remove(index);
        }
        4 if !prefix.is_empty() => {
            let start = rng.random_range(0..prefix.len());
            let end = rng.random_range(start + 1..=prefix.len());
            for byte in &mut prefix[start..end] {
                *byte = rng.random();
            }
        }
        5 if prefix.len() > 1 => {
            let start = rng.random_range(0..prefix.len());
            let end = rng.random_range(start + 1..=prefix.len());
            prefix.drain(start..end);
        }
        6 if !prefix.is_empty() => {
            let start = rng.random_range(0..prefix.len());
            let end = rng.random_range(start + 1..=prefix.len());
            let chunk: Vec<_> = prefix[start..end].to_vec();
            let insert = rng.random_range(0..=prefix.len());
            prefix.splice(insert..insert, chunk);
        }
        7 if !prefix.is_empty() => {
            let index = rng.random_range(0..prefix.len());
            prefix[index] = prefix[index].wrapping_add(rng.random_range(1..=35));
        }
        8 if !prefix.is_empty() => {
            let index = rng.random_range(0..prefix.len());
            prefix[index] = prefix[index].wrapping_sub(rng.random_range(1..=35));
        }
        9 if !prefix.is_empty() => {
            mutate_word(prefix, rng, 2);
        }
        10 if !prefix.is_empty() => {
            mutate_word(prefix, rng, 4);
        }
        11 if !dictionary.is_empty() => {
            let bytes = &dictionary[rng.random_range(0..dictionary.len())];
            insert_bytes(prefix, rng, bytes);
        }
        12 if !dictionary.is_empty() && !prefix.is_empty() => {
            let bytes = &dictionary[rng.random_range(0..dictionary.len())];
            let index = rng.random_range(0..prefix.len());
            let end = (index + bytes.len()).min(prefix.len());
            prefix.splice(index..end, bytes.iter().copied());
        }
        13 if crossover_prefix.is_some_and(|other| !other.is_empty()) => {
            let other = crossover_prefix.expect("checked crossover prefix");
            let start = rng.random_range(0..other.len());
            let end = rng.random_range(start + 1..=other.len());
            insert_bytes(prefix, rng, &other[start..end]);
        }
        _ => {
            let mut filler = SmallRng::seed_from_u64(salt);
            let extra = rng.random_range(1..=8);
            prefix.extend((0..extra).map(|_| filler.random::<u8>()));
        }
    };
}

fn mutate_word(prefix: &mut [u8], rng: &mut SmallRng, width: usize) {
    if prefix.len() < width {
        let index = rng.random_range(0..prefix.len());
        prefix[index] = interesting_byte(rng);
        return;
    }
    let index = rng.random_range(0..=prefix.len() - width);
    match width {
        2 => {
            let value = u16::from_le_bytes([prefix[index], prefix[index + 1]]);
            let value = value.wrapping_add(rng.random_range(1..=35));
            prefix[index..index + 2].copy_from_slice(&value.to_le_bytes());
        }
        4 => {
            let value = u32::from_le_bytes([
                prefix[index],
                prefix[index + 1],
                prefix[index + 2],
                prefix[index + 3],
            ]);
            let value = value.wrapping_sub(rng.random_range(1..=35));
            prefix[index..index + 4].copy_from_slice(&value.to_le_bytes());
        }
        _ => {}
    }
}

fn interesting_byte(rng: &mut SmallRng) -> u8 {
    INTERESTING_BYTES[rng.random_range(0..INTERESTING_BYTES.len())]
}

fn insert_bytes(prefix: &mut Vec<u8>, rng: &mut SmallRng, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let index = rng.random_range(0..=prefix.len());
    prefix.splice(index..index, bytes.iter().copied());
}

fn replace_bytes(prefix: &mut Vec<u8>, rng: &mut SmallRng, bytes: &[u8]) {
    if bytes.is_empty() || prefix.is_empty() {
        return;
    }
    let index = rng.random_range(0..prefix.len());
    let end = (index + bytes.len()).min(prefix.len());
    prefix.splice(index..end, bytes.iter().copied());
}

#[cfg(test)]
pub(crate) fn test_dictionary_mutation(prefix: &mut Vec<u8>, dictionary: &[Vec<u8>]) {
    if let Some(bytes) = dictionary.first() {
        let mut rng = SmallRng::seed_from_u64(1);
        insert_bytes(prefix, &mut rng, bytes);
    }
}

fn corpus_energy<Capture: CoverageCapture>(state: &State<Capture>, coverage: &[CoverageId]) -> f64 {
    let executions = state.stats.executed.max(1) as f64;
    let mut energy = 0.0;
    for id in coverage {
        let frequency = (*state.coverage_frequency.get(id).unwrap_or(&1)).max(1) as f64;
        energy += (executions / frequency).ln().max(0.0);
    }
    energy.max(1.0)
}

fn refresh_corpus_energies<Capture: CoverageCapture>(state: &mut State<Capture>) {
    match state.mode {
        Mode::Curious => {
            let executions = state.stats.executed.max(1) as f64;
            for entry in &mut state.corpus {
                let mut energy = 0.0;
                for id in &entry.coverage {
                    let frequency = (*state.coverage_frequency.get(id).unwrap_or(&1)).max(1) as f64;
                    energy += (executions / frequency).ln().max(0.0);
                }
                entry.energy = energy.max(1.0);
            }
        }
        Mode::Shy => {
            if let Some(best) = state.min_path_best {
                for entry in &mut state.corpus {
                    entry.energy = min_path_schedule_energy(
                        &state.min_path_removed_frequency,
                        state.stats.accepted,
                        best,
                        &entry.removed,
                        entry.score,
                        entry.path_len,
                    );
                }
            }
        }
    }
    state
        .energy_index
        .rebuild(state.corpus.iter().map(|entry| entry.energy));
    state.executions_since_refresh = 0;
}

/// RNG yielded by [`Demonic`].
pub struct DemonicRng<Capture: CoverageCapture = SancovCoverage> {
    shared: Arc<Mutex<State<Capture>>>,
    fallback: SmallRng,
    seed: u64,
    prefix: Vec<u8>,
    zero_tail: bool,
    cursor: usize,
    bytes_consumed: usize,
    trace: Vec<u8>,
    token: Option<Capture::Token>,
    local_capture: Option<Capture>,
    start_error: Option<String>,
    finished: bool,
}

impl<Capture: CoverageCapture> DemonicRng<Capture> {
    /// Seed backing this execution.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Fork the consumed RNG path into a replayable case.
    pub fn fork_case(&self) -> DemonicCase {
        DemonicCase {
            seed: self.seed,
            prefix: self.trace.clone(),
            zero_tail: self.zero_tail,
        }
    }

    /// Finish this execution immediately and return its coverage stats.
    ///
    /// This consumes the RNG because coverage is only meaningful after the caller has finished
    /// executing the path being measured.
    pub fn coverage(mut self) -> Result<DemonicCoverage, String> {
        self.finish(true)
    }

    /// Exclude this execution from coverage feedback when the RNG is dropped.
    pub fn discard(mut self) {
        let _ = self.finish(false);
    }
}

impl<Capture: CoverageCapture> RngCore for DemonicRng<Capture> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = self.untraced_word_bytes::<4>();
        bytes[0] = self.next_byte();
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = self.untraced_word_bytes::<8>();
        bytes[0] = self.next_byte();
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for byte in dst {
            *byte = self.next_byte();
        }
    }
}

impl<Capture: CoverageCapture> DemonicRng<Capture> {
    fn untraced_word_bytes<const N: usize>(&mut self) -> [u8; N] {
        self.ensure_started();
        let mut bytes = [0; N];
        if !self.zero_tail {
            self.fallback.fill_bytes(&mut bytes);
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
        if self.trace.len() < MAX_PREFIX_LEN {
            self.trace.push(byte);
        }
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
                    .expect("demonic state poisoned")
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

    fn finish(&mut self, record_coverage: bool) -> Result<DemonicCoverage, String> {
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
                    let mut state = self.shared.lock().expect("demonic state poisoned");
                    merge_finished_execution(&mut state, active, outcome)
                }
                Err(error) => {
                    let mut state = self.shared.lock().expect("demonic state poisoned");
                    state.stats.executed += 1;
                    state.active_cases = state.active_cases.saturating_sub(1);
                    Err(error)
                }
            }
        } else {
            let mut state = self.shared.lock().expect("demonic state poisoned");
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

impl<Capture> Drop for DemonicRng<Capture>
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
    coverage: Option<CoverageSet>,
    dictionary: Vec<Vec<u8>>,
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
        return Ok(FinishedCapture {
            coverage: None,
            dictionary: Vec::new(),
        });
    }

    if let Some(error) = start_error {
        return Err(error);
    }
    let token = token.ok_or_else(|| "coverage capture never started".to_string())?;
    let coverage = capture.finish_capture(token)?;
    Ok(FinishedCapture {
        coverage: Some(coverage),
        dictionary: capture.dictionary_values(),
    })
}

fn merge_finished_execution<Capture>(
    state: &mut State<Capture>,
    active: Active,
    finished: FinishedCapture,
) -> Result<DemonicCoverage, String>
where
    Capture: CoverageCapture,
{
    state.stats.executed += 1;
    state.active_cases = state.active_cases.saturating_sub(1);
    merge_dictionary_values(state, finished.dictionary);

    let Some(coverage) = finished.coverage else {
        return Ok(DemonicCoverage {
            feature_count: 0,
            bytes_consumed: active.bytes_consumed,
        });
    };

    let run_coverage = DemonicCoverage {
        feature_count: coverage.len(),
        bytes_consumed: active.bytes_consumed,
    };
    let score = run_coverage.feature_count;
    let path_len = run_coverage.bytes_consumed;
    let removed_ids: Vec<_> = if state.mode == Mode::Shy {
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
    let interesting = if state.mode == Mode::Shy {
        true
    } else {
        !coverage_delta(&state.global, &coverage).is_empty()
    };
    let best_shy_score = (state.mode == Mode::Shy)
        .then_some(state.min_path_best)
        .flatten();
    let candidate_score = MinPathScore::new(score, path_len);
    let improves_best_shy = best_shy_score.is_none_or(|best| candidate_score < best);

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
        if state.mode == Mode::Shy {
            for id in &removed_ids {
                *state.min_path_removed_frequency.entry(*id).or_insert(0) += 1;
            }
        }
        state.stats.accepted += 1;
        let energy = match state.mode {
            Mode::Curious => corpus_energy(state, &coverage_ids),
            Mode::Shy => {
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
                    path_len,
                )
            }
        };
        match state.mode {
            Mode::Curious => {
                state.global.extend(coverage.iter());
                state.stats.coverage_ids = state.global.len() as u64;
            }
            Mode::Shy if improves_best_shy => {
                state.global = coverage.clone();
                state.stats.coverage_ids = score as u64;
            }
            Mode::Shy => {}
        }
        state.corpus.push(CorpusSeed {
            seed: active.seed,
            prefix: active.trace.clone(),
            coverage: coverage_ids,
            removed: removed_ids,
            score,
            path_len,
            energy,
        });
        let inserted_index = state.corpus.len() - 1;
        state.energy_index.push(energy);
        if state.mode == Mode::Shy && improves_best_shy {
            state.min_path_best = Some(candidate_score);
            state.min_path_best_index = Some(inserted_index);
            refresh_corpus_energies(state);
            enqueue_shy_best_neighbors(state, inserted_index);
        }
        prune_corpus(state);
    }

    Ok(run_coverage)
}

fn merge_dictionary_values<Capture: CoverageCapture>(
    state: &mut State<Capture>,
    values: Vec<Vec<u8>>,
) {
    for value in values {
        if state.dictionary.len() >= MAX_DICTIONARY_VALUES {
            break;
        }
        if value.is_empty() || state.dictionary.iter().any(|existing| existing == &value) {
            continue;
        }
        state.dictionary.push(value);
    }
}

fn enqueue_shy_best_neighbors<Capture: CoverageCapture>(state: &mut State<Capture>, index: usize) {
    let Some(entry) = state.corpus.get(index) else {
        return;
    };
    let seed = entry.seed;
    let prefix = entry.prefix.clone();
    if prefix.len() <= 1 {
        return;
    }

    let mut variants = Vec::new();
    for trim in [4, 3, 2, 1] {
        if variants.len() >= MAX_SHY_BEST_NEIGHBORS || trim >= prefix.len() {
            continue;
        }
        let mut candidate = prefix[..prefix.len() - trim].to_vec();
        shrink_first_by(&mut candidate, trim);
        variants.push(candidate);
    }

    for index in 1..prefix.len() {
        if variants.len() >= MAX_SHY_BEST_NEIGHBORS {
            break;
        }
        let mut candidate = prefix.clone();
        candidate.remove(index);
        shrink_first_by(&mut candidate, 1);
        variants.push(candidate);
    }

    let chunk_starts = [
        1,
        prefix.len().saturating_sub(4),
        prefix.len().saturating_sub(3),
        prefix.len().saturating_sub(2),
        prefix.len() / 2,
    ];
    for width in [2, 3, 4] {
        for start in chunk_starts {
            if variants.len() >= MAX_SHY_BEST_NEIGHBORS {
                break;
            }
            if start == 0 || start >= prefix.len() {
                continue;
            }
            let end = (start + width).min(prefix.len());
            if end <= start {
                continue;
            }
            let mut candidate = prefix.clone();
            candidate.drain(start..end);
            shrink_first_by(&mut candidate, end - start);
            variants.push(candidate);
        }
    }

    for mut candidate in variants.into_iter().rev() {
        if candidate.len() > MAX_PREFIX_LEN {
            candidate.truncate(MAX_PREFIX_LEN);
        }
        state.pending_candidates.push_front(Candidate {
            seed,
            prefix: candidate,
            mutated: true,
            zero_tail: true,
        });
    }
    while state.pending_candidates.len() > MAX_PENDING_CANDIDATES {
        state.pending_candidates.pop_back();
    }
}

fn shrink_first_by(prefix: &mut [u8], amount: usize) {
    let Some(first) = prefix.first_mut() else {
        return;
    };
    *first = first.saturating_sub(amount.min(u8::MAX as usize) as u8);
}

fn energy_refresh_interval(mode: Mode) -> u64 {
    match mode {
        Mode::Curious => CURIOUS_ENERGY_REFRESH_INTERVAL,
        Mode::Shy => SHY_ENERGY_REFRESH_INTERVAL,
    }
}

fn prune_corpus<Capture: CoverageCapture>(state: &mut State<Capture>) {
    if state.corpus.len() <= MAX_CORPUS_LEN {
        return;
    }

    let remove = if state.mode == Mode::Shy {
        state
            .corpus
            .iter()
            .enumerate()
            .max_by_key(|(_, entry)| MinPathScore::new(entry.score, entry.path_len))
            .map(|(index, _)| index)
    } else {
        state
            .corpus
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.energy.total_cmp(&b.energy))
            .map(|(index, _)| index)
    }
    .or_else(|| {
        state
            .corpus
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.energy.total_cmp(&b.energy))
            .map(|(index, _)| index)
    });

    if let Some(index) = remove {
        state.corpus.swap_remove(index);
        state.energy_index.swap_remove(index);
        if state.mode == Mode::Shy {
            refresh_min_path_best(state);
        }
    }
}

fn refresh_min_path_best<Capture: CoverageCapture>(state: &mut State<Capture>) {
    let best = state
        .corpus
        .iter()
        .enumerate()
        .map(|(index, entry)| (index, MinPathScore::new(entry.score, entry.path_len)))
        .min_by_key(|(_, score)| *score);
    state.min_path_best = best.map(|(_, score)| score);
    state.min_path_best_index = best.map(|(index, _)| index);
}

/// Coverage backend used when callers only want the RNG shape.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoCoverage;

impl CoverageCapture for NoCoverage {
    type Token = ();

    fn start_capture(&mut self) -> Result<Self::Token, String> {
        Ok(())
    }

    fn finish_capture(&mut self, _token: Self::Token) -> Result<CoverageSet, String> {
        Ok(CoverageSet::new())
    }
}

impl ParallelCoverageCapture for NoCoverage {}
