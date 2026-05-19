//! Shared contracts and data types for dowsing crates.

use dowsing_rng::Trace;
use rand::{Rng, rngs::SmallRng};
use rustc_hash::FxHashMap;
use std::{
    any::{Any, TypeId},
    fmt,
};

/// Replayable RNG trace used as a generated case.
pub type Case = Trace;

/// Maximum flattened prefix length retained by optimizers and mutators.
pub const MAX_PREFIX_LEN: usize = 4096;

/// Small values commonly useful for byte-level mutation.
pub const INTERESTING_BYTES: [u8; 10] = [0, 1, 16, 31, 32, 63, 64, 127, 128, 255];

/// Stable identifier for one coverage feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoverageId(pub(crate) u64);

impl CoverageId {
    /// Construct a coverage ID from a raw feature key.
    pub fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Raw feature key behind this coverage ID.
    pub fn raw(self) -> u64 {
        self.0
    }
}

/// Coverage observed during one execution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoverageSet {
    ids: Vec<CoverageId>,
}

impl CoverageSet {
    /// Create an empty coverage set.
    pub fn new() -> Self {
        Self { ids: Vec::new() }
    }

    /// Insert one ID. Returns `true` if it was not already present.
    pub fn insert(&mut self, id: CoverageId) -> bool {
        match self.ids.binary_search(&id) {
            Ok(_) => false,
            Err(index) => {
                self.ids.insert(index, id);
                true
            }
        }
    }

    /// Extend this set from an iterator of IDs.
    pub fn extend(&mut self, ids: impl IntoIterator<Item = CoverageId>) {
        let mut incoming: Vec<CoverageId> = ids.into_iter().collect();
        if incoming.is_empty() {
            return;
        }
        incoming.sort_unstable();
        incoming.dedup();

        if self.ids.is_empty() {
            self.ids = incoming;
            return;
        }

        let mut out = Vec::with_capacity(self.ids.len() + incoming.len());
        let (mut i, mut j) = (0, 0);
        let existing = &self.ids;
        while i < existing.len() && j < incoming.len() {
            match existing[i].cmp(&incoming[j]) {
                std::cmp::Ordering::Less => {
                    out.push(existing[i]);
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    out.push(incoming[j]);
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    out.push(existing[i]);
                    i += 1;
                    j += 1;
                }
            }
        }
        out.extend_from_slice(&existing[i..]);
        out.extend_from_slice(&incoming[j..]);
        self.ids = out;
    }

    /// Number of unique IDs in this set.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Returns `true` if this set has no coverage IDs.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Iterate over coverage IDs.
    pub fn iter(&self) -> impl Iterator<Item = CoverageId> + '_ {
        self.ids.iter().copied()
    }

    /// IDs in this set but not in `other`.
    pub fn difference(&self, other: &Self) -> Self {
        let mut ids = Vec::new();
        let mut left = 0;
        let mut right = 0;
        while left < self.ids.len() {
            while right < other.ids.len() && other.ids[right] < self.ids[left] {
                right += 1;
            }
            if right == other.ids.len() || self.ids[left] < other.ids[right] {
                ids.push(self.ids[left]);
            }
            left += 1;
        }
        Self { ids }
    }

    /// Build a deduplicated coverage set from unsorted IDs.
    pub fn from_unsorted(mut ids: Vec<CoverageId>) -> Self {
        ids.sort_unstable();
        ids.dedup();
        Self { ids }
    }
}

impl FromIterator<CoverageId> for CoverageSet {
    fn from_iter<T: IntoIterator<Item = CoverageId>>(iter: T) -> Self {
        let mut ids: Vec<_> = iter.into_iter().collect();
        ids.sort_unstable();
        ids.dedup();
        Self { ids }
    }
}

/// Feedback observed during one execution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionFeedback {
    /// Coverage features observed during the execution.
    pub features: CoverageSet,
    /// Coarse execution intensity derived from hit-count buckets when available.
    pub hit_count_weight: u64,
    /// Values learned from comparison feedback during this execution.
    pub dictionary: Vec<Vec<u8>>,
}

impl ExecutionFeedback {
    /// Build feedback from all observed parts.
    pub fn new(features: CoverageSet, hit_count_weight: u64, dictionary: Vec<Vec<u8>>) -> Self {
        Self {
            features,
            hit_count_weight,
            dictionary,
        }
    }

    /// Build feedback from coverage features. The default hit-count weight is one unit per feature.
    pub fn from_features(features: CoverageSet) -> Self {
        let hit_count_weight = features.len() as u64;
        Self::new(features, hit_count_weight, Vec::new())
    }

    /// Override the coarse execution intensity.
    pub fn with_hit_count_weight(mut self, hit_count_weight: u64) -> Self {
        self.hit_count_weight = hit_count_weight;
        self
    }

    /// Attach comparison dictionary values to this feedback.
    pub fn with_dictionary(mut self, dictionary: Vec<Vec<u8>>) -> Self {
        self.dictionary = dictionary;
        self
    }

    /// Coverage features observed during the execution.
    pub fn features(&self) -> &CoverageSet {
        &self.features
    }

    /// Coarse execution intensity derived from hit-count buckets when available.
    pub fn hit_count_weight(&self) -> u64 {
        self.hit_count_weight
    }

    /// Values learned from comparison feedback during this execution.
    pub fn dictionary(&self) -> &[Vec<u8>] {
        &self.dictionary
    }

    /// Split feedback into owned parts.
    pub fn into_parts(self) -> (CoverageSet, u64, Vec<Vec<u8>>) {
        (self.features, self.hit_count_weight, self.dictionary)
    }
}

impl From<CoverageSet> for ExecutionFeedback {
    fn from(features: CoverageSet) -> Self {
        Self::from_features(features)
    }
}

/// Result of attempting to start one coverage capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureStart<Session> {
    /// Capture started and must be finished or discarded with this session.
    Started(Session),
    /// The backend is temporarily busy and the caller may retry later.
    Busy,
}

/// Starts and finishes coverage capture for one RNG case.
pub trait CoverageCapture {
    /// Opaque per-execution session.
    type Session;

    /// Start capturing coverage.
    fn start_capture(&mut self) -> Result<CaptureStart<Self::Session>, String>;

    /// Finish coverage capture and return the observed feedback.
    fn finish_capture(&mut self, session: Self::Session) -> Result<ExecutionFeedback, String>;

    /// Discard a capture without reading/exporting its coverage.
    fn discard_capture(&mut self, _session: Self::Session) -> Result<(), String> {
        Ok(())
    }
}

/// Coverage backend that can correctly attribute multiple concurrent in-process executions.
pub trait ParallelCoverageCapture: CoverageCapture + Clone + Send + Sync + 'static {
    /// Validate that the current process is configured for concurrent attribution.
    fn validate_parallel(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Coverage backend used when callers only want the RNG shape.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoCoverage;

impl CoverageCapture for NoCoverage {
    type Session = ();

    fn start_capture(&mut self) -> Result<CaptureStart<Self::Session>, String> {
        Ok(CaptureStart::Started(()))
    }

    fn finish_capture(&mut self, _session: Self::Session) -> Result<ExecutionFeedback, String> {
        Ok(ExecutionFeedback::default())
    }
}

impl ParallelCoverageCapture for NoCoverage {}

/// Byte-prefix mutation.
pub trait RngByteMutation: fmt::Debug + RngByteMutationClone + Send + Any {
    /// Apply this mutation to a flattened RNG prefix.
    fn apply_bytes(&self, prefix: &mut Vec<u8>, dictionary: &[Vec<u8>]) -> bool;
}

/// Clone support for boxed byte mutations.
pub trait RngByteMutationClone {
    /// Clone this mutation into a boxed trait object.
    fn clone_byte_box(&self) -> Box<dyn RngByteMutation>;
}

impl<T> RngByteMutationClone for T
where
    T: 'static + RngByteMutation + Clone,
{
    fn clone_byte_box(&self) -> Box<dyn RngByteMutation> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn RngByteMutation> {
    fn clone(&self) -> Self {
        self.clone_byte_box()
    }
}

/// Structured trace mutation with a byte-prefix fallback.
pub trait RngTreeMutation: RngByteMutation + RngTreeMutationClone + Send {
    /// Apply this mutation to a structured RNG trace.
    fn apply_tree(&self, trace: &mut Case, dictionary: &[Vec<u8>]) -> bool;
}

/// Clone support for boxed tree mutations.
pub trait RngTreeMutationClone {
    /// Clone this mutation into a boxed trait object.
    fn clone_tree_box(&self) -> Box<dyn RngTreeMutation>;
}

impl<T> RngTreeMutationClone for T
where
    T: 'static + RngTreeMutation + Clone,
{
    fn clone_tree_box(&self) -> Box<dyn RngTreeMutation> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn RngTreeMutation> {
    fn clone(&self) -> Self {
        self.clone_tree_box()
    }
}

const MIN_MUTATION_WEIGHT: f64 = 0.10;
const MAX_MUTATION_WEIGHT: f64 = 16.0;
const MUTATION_WEIGHT_PRIORITY_SCALE: f64 = 1_000_000.0;

/// Adaptive per-mutation selection weights.
#[derive(Debug, Clone, Default)]
pub struct MutationWeights {
    multipliers: FxHashMap<TypeId, f64>,
}

impl MutationWeights {
    /// Current multiplier for a mutation kind.
    pub fn multiplier(&self, mutation_id: TypeId) -> f64 {
        *self.multipliers.get(&mutation_id).unwrap_or(&1.0)
    }

    /// Baseline selection weight adjusted by current feedback.
    pub fn selection_weight(&self, mutation_id: TypeId, baseline: f64) -> f64 {
        let weight = baseline * self.multiplier(mutation_id);
        if weight.is_finite() && weight > 0.0 {
            weight
        } else {
            baseline.max(1.0)
        }
    }

    /// Integer priority key for stable ordering.
    pub fn priority_key(&self, mutation_id: TypeId) -> u64 {
        (self.multiplier(mutation_id) * MUTATION_WEIGHT_PRIORITY_SCALE).round() as u64
    }

    /// Reward or penalize several mutation kinds with split credit.
    pub fn reward_many(&mut self, mutation_ids: &[TypeId], factor: f64) {
        if mutation_ids.is_empty() || !factor.is_finite() || factor <= 0.0 {
            return;
        }
        let step = factor.powf(1.0 / mutation_ids.len() as f64);
        for mutation_id in mutation_ids {
            self.apply_factor(*mutation_id, step);
        }
    }

    fn apply_factor(&mut self, mutation_id: TypeId, factor: f64) {
        if !factor.is_finite() || factor <= 0.0 {
            return;
        }
        let slot = self.multipliers.entry(mutation_id).or_insert(1.0);
        *slot = (*slot * factor).clamp(MIN_MUTATION_WEIGHT, MAX_MUTATION_WEIGHT);
    }

    /// Test-only direct multiplier hook used by downstream tests.
    #[doc(hidden)]
    pub fn set_for_test(&mut self, mutation_id: TypeId, multiplier: f64) {
        self.multipliers.insert(
            mutation_id,
            multiplier.clamp(MIN_MUTATION_WEIGHT, MAX_MUTATION_WEIGHT),
        );
    }
}

/// Materializable reduction operation.
#[derive(Debug, Clone)]
pub struct ReductionOp {
    start: usize,
    len: usize,
    target: u64,
    simplification: usize,
    /// Concrete mutation type identifier.
    pub type_id: TypeId,
    mutator: Box<dyn RngReductionMutation>,
}

/// Materializes a deterministic reduction candidate.
pub trait RngReductionMutation: fmt::Debug + RngReductionMutationClone + Send {
    /// Build a reduced trace and flattened prefix.
    fn materialize(
        &self,
        seed: u64,
        base_case: &Case,
        base_prefix: &[u8],
        dictionary: &[Vec<u8>],
    ) -> Option<(Case, Vec<u8>)>;
}

/// Clone support for boxed reduction mutations.
pub trait RngReductionMutationClone {
    /// Clone this mutation into a boxed trait object.
    fn clone_reduction_box(&self) -> Box<dyn RngReductionMutation>;
}

impl<T> RngReductionMutationClone for T
where
    T: 'static + RngReductionMutation + Clone,
{
    fn clone_reduction_box(&self) -> Box<dyn RngReductionMutation> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn RngReductionMutation> {
    fn clone(&self) -> Self {
        self.clone_reduction_box()
    }
}

#[derive(Debug, Clone)]
struct ByteReductionMutation {
    mutator: Box<dyn RngByteMutation>,
}

#[derive(Debug, Clone)]
struct TreeReductionMutation {
    mutator: Box<dyn RngTreeMutation>,
}

impl RngReductionMutation for ByteReductionMutation {
    fn materialize(
        &self,
        seed: u64,
        _base_case: &Case,
        base_prefix: &[u8],
        dictionary: &[Vec<u8>],
    ) -> Option<(Case, Vec<u8>)> {
        materialize_bytes(seed, base_prefix, dictionary, self.mutator.as_ref())
    }
}

impl RngReductionMutation for TreeReductionMutation {
    fn materialize(
        &self,
        seed: u64,
        base_case: &Case,
        base_prefix: &[u8],
        dictionary: &[Vec<u8>],
    ) -> Option<(Case, Vec<u8>)> {
        let mut case = base_case.clone();
        if self.mutator.apply_tree(&mut case, dictionary) {
            let prefix = case.flatten_prefix();
            Some((case, prefix))
        } else {
            materialize_bytes(seed, base_prefix, dictionary, self.mutator.as_ref())
        }
    }
}

impl ReductionOp {
    /// Build a byte-prefix reduction operation.
    pub fn byte<Mutation>(
        start: usize,
        len: usize,
        target: u64,
        simplification: usize,
        mutator: Mutation,
    ) -> Self
    where
        Mutation: RngByteMutation + Clone + 'static,
    {
        Self {
            start,
            len,
            target,
            simplification,
            type_id: TypeId::of::<Mutation>(),
            mutator: Box::new(ByteReductionMutation {
                mutator: Box::new(mutator),
            }),
        }
    }

    /// Build a structured trace reduction operation.
    pub fn tree<Mutation>(
        start: usize,
        len: usize,
        target: u64,
        simplification: usize,
        mutator: Mutation,
    ) -> Self
    where
        Mutation: RngTreeMutation + Clone + 'static,
    {
        Self {
            start,
            len,
            target,
            simplification,
            type_id: TypeId::of::<Mutation>(),
            mutator: Box::new(TreeReductionMutation {
                mutator: Box::new(mutator),
            }),
        }
    }

    /// Mutated prefix start.
    pub fn start(&self) -> usize {
        self.start
    }

    /// Mutated prefix length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when this operation has no byte range.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Operation-specific target value.
    pub fn target(&self) -> u64 {
        self.target
    }

    /// Estimated simplification amount.
    pub fn simplification(&self) -> usize {
        self.simplification
    }

    /// Materialize this operation against a base case.
    pub fn materialize(
        &self,
        seed: u64,
        base_case: &Case,
        base_prefix: &[u8],
        dictionary: &[Vec<u8>],
    ) -> Option<(Case, Vec<u8>)> {
        self.mutator
            .materialize(seed, base_case, base_prefix, dictionary)
    }
}

fn materialize_bytes(
    seed: u64,
    base_prefix: &[u8],
    dictionary: &[Vec<u8>],
    mutation: &dyn RngByteMutation,
) -> Option<(Case, Vec<u8>)> {
    let mut prefix = base_prefix.to_vec();
    if !mutation.apply_bytes(&mut prefix, dictionary) {
        return None;
    }
    Some((Case::from_flat_prefix(seed, prefix.clone()), prefix))
}

/// Built-in mutation source kinds understood by the default optimizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltInMutationSource {
    /// Random exploratory mutations suitable for coverage discovery.
    CoverageHavoc,
    /// Random simplifying mutations suitable for minimization fallback.
    MinimizingHavoc,
    /// Deterministic semantic reductions over ranges, scalars, draws, and byte spans.
    SemanticReductions,
}

/// Context passed to custom candidate sources.
pub struct MutationContext<'a> {
    parent: &'a Case,
    parent_prefix: &'a [u8],
    draws: &'a [dowsing_rng::DrawSpan],
    scalars: &'a [dowsing_rng::ScalarSpan],
    sequences: &'a [dowsing_rng::SequenceSpan],
    dictionary: &'a [Vec<u8>],
    rng: &'a mut SmallRng,
    fallback_seed: u64,
    max_prefix_len: usize,
}

impl<'a> MutationContext<'a> {
    /// Build a candidate source context.
    pub fn new(
        parent: &'a Case,
        parent_prefix: &'a [u8],
        draws: &'a [dowsing_rng::DrawSpan],
        scalars: &'a [dowsing_rng::ScalarSpan],
        sequences: &'a [dowsing_rng::SequenceSpan],
        dictionary: &'a [Vec<u8>],
        rng: &'a mut SmallRng,
        fallback_seed: u64,
    ) -> Self {
        Self {
            parent,
            parent_prefix,
            draws,
            scalars,
            sequences,
            dictionary,
            rng,
            fallback_seed,
            max_prefix_len: MAX_PREFIX_LEN,
        }
    }

    /// Parent replay case selected from the corpus.
    pub fn parent(&self) -> &Case {
        self.parent
    }

    /// Flattened parent bytes.
    pub fn parent_prefix(&self) -> &[u8] {
        self.parent_prefix
    }

    /// Semantic byte draws recorded by the parent.
    pub fn draws(&self) -> &[dowsing_rng::DrawSpan] {
        self.draws
    }

    /// Shrink-aware scalar spans recorded by the parent.
    pub fn scalars(&self) -> &[dowsing_rng::ScalarSpan] {
        self.scalars
    }

    /// Semantic range spans recorded by the parent.
    pub fn sequences(&self) -> &[dowsing_rng::SequenceSpan] {
        self.sequences
    }

    /// Comparison dictionary values learned so far.
    pub fn dictionary(&self) -> &[Vec<u8>] {
        self.dictionary
    }

    /// Scheduler RNG for this source invocation.
    pub fn rng(&mut self) -> &mut SmallRng {
        self.rng
    }

    /// Fresh seed component reserved for this candidate.
    pub fn fallback_seed(&self) -> u64 {
        self.fallback_seed
    }

    /// Maximum flattened prefix length retained by the optimizer.
    pub fn max_prefix_len(&self) -> usize {
        self.max_prefix_len
    }
}

/// Candidate emitted by a custom candidate source.
#[derive(Debug, Clone)]
pub struct MutationCandidate {
    case: Option<Case>,
    prefix: Option<Vec<u8>>,
    mutations: Vec<TypeId>,
}

impl MutationCandidate {
    /// Build a candidate from a mutated flattened prefix.
    pub fn from_prefix(prefix: Vec<u8>) -> Self {
        Self {
            case: None,
            prefix: Some(prefix),
            mutations: Vec::new(),
        }
    }

    /// Build a candidate from a full replay case.
    pub fn from_case(case: Case) -> Self {
        Self {
            case: Some(case),
            prefix: None,
            mutations: Vec::new(),
        }
    }

    /// Attach one mutation type to this candidate.
    pub fn with_mutation<T: 'static>(mut self) -> Self {
        self.mutations.push(TypeId::of::<T>());
        self
    }

    /// Attach several mutation type identifiers to this candidate.
    pub fn with_mutations(mut self, ids: impl IntoIterator<Item = TypeId>) -> Self {
        self.mutations.extend(ids);
        self
    }

    /// Materialize this candidate into a replay case and mutation IDs.
    pub fn materialize(
        mut self,
        parent_seed: u64,
        fallback: u64,
        rng: &mut SmallRng,
    ) -> (Case, Vec<TypeId>) {
        let case = if let Some(case) = self.case.take() {
            case
        } else {
            let mut prefix = self.prefix.take().unwrap_or_default();
            if prefix.is_empty() {
                prefix.push(rng.random());
            }
            if prefix.len() > MAX_PREFIX_LEN {
                prefix.truncate(MAX_PREFIX_LEN);
            }
            Case::from_flat_prefix(parent_seed ^ fallback.rotate_left(17), prefix)
        };
        (case, self.mutations)
    }
}

/// Feedback delivered to custom candidate sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFeedback {
    /// Candidate was discarded by the harness.
    Discarded,
    /// Candidate was executed but not retained by the goal.
    Rejected,
    /// Candidate was retained by the goal.
    Accepted,
    /// Candidate became the current best retained case.
    Improved,
}

/// User-extensible producer of mutation candidates.
pub trait CandidateSource: fmt::Debug + CandidateSourceClone + Send {
    /// Try to produce one candidate from the selected parent.
    fn next_candidate(&mut self, context: &mut MutationContext<'_>) -> Option<MutationCandidate>;

    /// Observe feedback for a candidate previously emitted by this source.
    fn record_feedback(&mut self, _feedback: SourceFeedback) {}
}

/// Clone support for boxed custom candidate sources.
pub trait CandidateSourceClone {
    /// Clone this source into a boxed trait object.
    fn clone_source_box(&self) -> Box<dyn CandidateSource>;
}

impl<T> CandidateSourceClone for T
where
    T: CandidateSource + Clone + 'static,
{
    fn clone_source_box(&self) -> Box<dyn CandidateSource> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn CandidateSource> {
    fn clone(&self) -> Self {
        self.clone_source_box()
    }
}

/// Configured candidate source.
#[derive(Debug, Clone)]
pub struct MutationSource {
    /// Candidate source implementation.
    pub kind: MutationSourceKind,
}

impl MutationSource {
    /// Wrap a custom source.
    pub fn custom(source: impl CandidateSource + Clone + 'static) -> Self {
        Self {
            kind: MutationSourceKind::Custom(Box::new(source)),
        }
    }

    /// Build a built-in source marker.
    pub fn built_in(source: BuiltInMutationSource) -> Self {
        Self {
            kind: MutationSourceKind::BuiltIn(source),
        }
    }
}

/// Configured source kind.
#[derive(Debug, Clone)]
pub enum MutationSourceKind {
    /// Built-in source implemented by `dowsing-mutators`.
    BuiltIn(BuiltInMutationSource),
    /// User-provided source.
    Custom(Box<dyn CandidateSource>),
}
