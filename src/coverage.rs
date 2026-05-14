use crate::{CoverageExplorer, Step};
use std::{
    collections::BTreeSet,
    fmt::Debug,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

/// Replay a materialized slice of ops from a fresh state.
///
/// For the lazy version that streams ops directly from a [`GeneratedCase`] without allocating
/// a `Vec`, use [`GeneratedCase::replay`]. This slice-based helper exists for the reducer's
/// inner predicate, which operates on shrunk `&[Op]` candidates.
pub fn replay_ops<Op, State, Init, Fold>(
    ops: &[Op],
    mut init: Init,
    mut step: Fold,
) -> Result<(), String>
where
    Init: FnMut() -> State,
    Fold: for<'a> FnMut(&mut State, Step<'a, Op>) -> Result<(), String>,
{
    let mut state = init();
    for (index, op) in ops.iter().enumerate() {
        step(&mut state, Step { index, op })?;
    }
    Ok(())
}

/// Cost model used by the reducer.
pub trait CostModel<Op> {
    /// Cost for a single operation. Lower is better.
    fn cost(&self, op: &Op) -> u64;

    /// Cost for a whole operation list.
    fn total_cost(&self, ops: &[Op]) -> u64 {
        ops.iter().map(|op| self.cost(op)).sum()
    }
}

/// Domain-aware sequence mutator used by reducers and coverage-guided exploration.
///
/// Implementations receive the current operation sequence and emit valid replacement sequences.
/// The caller decides whether each emitted candidate is interesting: a reducer may require the
/// same failure, while the coverage explorer may require new coverage.
pub trait SequenceMutator<Op> {
    /// Emit zero or more candidate operation sequences derived from `ops`.
    fn mutate(&mut self, ops: &[Op], emit: &mut dyn FnMut(Vec<Op>));
}

impl<Op, F> SequenceMutator<Op> for F
where
    F: FnMut(&[Op], &mut dyn FnMut(Vec<Op>)),
{
    fn mutate(&mut self, ops: &[Op], emit: &mut dyn FnMut(Vec<Op>)) {
        self(ops, emit);
    }
}

impl<Op, F> CostModel<Op> for F
where
    F: Fn(&Op) -> u64,
{
    fn cost(&self, op: &Op) -> u64 {
        self(op)
    }
}

/// Every operation has cost `1`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnitCost;

impl<Op> CostModel<Op> for UnitCost {
    fn cost(&self, _op: &Op) -> u64 {
        1
    }
}

/// Stable identifier for one coverage feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoverageId(pub(crate) u64);

impl CoverageId {
    /// Construct a coverage ID from a raw `u64` feature key.
    pub fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Raw `u64` feature key behind this coverage ID.
    pub fn raw(self) -> u64 {
        self.0
    }
}

/// Set of coverage IDs observed by one case or the global corpus.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoverageSet {
    ids: BTreeSet<CoverageId>,
}

impl CoverageSet {
    /// Create an empty coverage set.
    pub fn new() -> Self {
        Self {
            ids: BTreeSet::new(),
        }
    }

    /// Insert one ID. Returns `true` if it was not already present.
    pub fn insert(&mut self, id: CoverageId) -> bool {
        self.ids.insert(id)
    }

    /// Extend this set from an iterator of IDs.
    pub fn extend(&mut self, ids: impl IntoIterator<Item = CoverageId>) {
        self.ids.extend(ids);
    }

    /// Number of unique IDs in this set.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Returns `true` if this set has no coverage IDs.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Returns `true` if `id` is in this set.
    pub fn contains(&self, id: &CoverageId) -> bool {
        self.ids.contains(id)
    }

    /// Return IDs present in `self` but absent from `other`.
    pub fn difference(&self, other: &Self) -> Self {
        Self {
            ids: self.ids.difference(&other.ids).copied().collect(),
        }
    }

    /// Returns `true` if every ID in `self` is also in `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.ids.is_subset(&other.ids)
    }

    /// Returns `true` if every ID in `other` is also in `self`.
    pub fn is_superset(&self, other: &Self) -> bool {
        self.ids.is_superset(&other.ids)
    }

    /// Iterate over coverage IDs in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = CoverageId> + '_ {
        self.ids.iter().copied()
    }
}

impl FromIterator<CoverageId> for CoverageSet {
    fn from_iter<T: IntoIterator<Item = CoverageId>>(iter: T) -> Self {
        Self {
            ids: iter.into_iter().collect(),
        }
    }
}

/// Manifest metadata for an accepted corpus entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusEntry<Id = String> {
    pub(crate) id: Id,
    pub(crate) parent: Option<Id>,
    pub(crate) coverage: CoverageSet,
    pub(crate) unique_coverage: CoverageSet,
    pub(crate) is_failure: bool,
    pub(crate) cost: u64,
    pub(crate) len: usize,
}

impl<Id> CorpusEntry<Id> {
    /// Stable corpus entry ID.
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// Parent corpus entry ID, if this case came from mutation.
    pub fn parent(&self) -> Option<&Id> {
        self.parent.as_ref()
    }

    /// Full coverage observed while replaying this entry.
    pub fn coverage(&self) -> &CoverageSet {
        &self.coverage
    }

    /// Coverage this entry added to the corpus when accepted.
    pub fn unique_coverage(&self) -> &CoverageSet {
        &self.unique_coverage
    }

    /// Whether replay failed.
    pub fn is_failure(&self) -> bool {
        self.is_failure
    }

    /// Caller-defined case cost, usually file size or op count.
    pub fn cost(&self) -> u64 {
        self.cost
    }

    /// Operation count when known.
    pub fn len(&self) -> usize {
        self.len
    }
}

/// Result of testing a candidate against a corpus coverage set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterestingCase<Id = String> {
    pub(crate) id: Id,
    pub(crate) new_coverage: CoverageSet,
    pub(crate) is_failure: bool,
}

impl<Id> InterestingCase<Id> {
    /// Candidate ID.
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// Coverage IDs not yet present in the corpus.
    pub fn new_coverage(&self) -> &CoverageSet {
        &self.new_coverage
    }

    /// Whether replay failed.
    pub fn is_failure(&self) -> bool {
        self.is_failure
    }
}

/// Aggregate counters for a coverage-guided exploration run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExplorationStats {
    pub(crate) generated: u64,
    pub(crate) mutated: u64,
    pub(crate) executed: u64,
    pub(crate) accepted: u64,
    pub(crate) failures: u64,
    pub(crate) errors: u64,
    pub(crate) coverage_ids: u64,
}

impl ExplorationStats {
    /// Cases generated directly from seeds.
    pub fn generated(&self) -> u64 {
        self.generated
    }

    /// Cases generated by mutating corpus entries.
    pub fn mutated(&self) -> u64 {
        self.mutated
    }

    /// Cases executed in the target harness.
    pub fn executed(&self) -> u64 {
        self.executed
    }

    /// Cases accepted into the corpus.
    pub fn accepted(&self) -> u64 {
        self.accepted
    }

    /// Accepted cases that failed the harness.
    pub fn failures(&self) -> u64 {
        self.failures
    }

    /// Cases whose evaluator failed before producing coverage.
    pub fn errors(&self) -> u64 {
        self.errors
    }

    /// Unique coverage IDs in the accepted corpus.
    pub fn coverage_ids(&self) -> u64 {
        self.coverage_ids
    }
}

/// Result from evaluating one materialized operation sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageEvaluation {
    pub(crate) outcome: Result<(), String>,
    pub(crate) coverage: CoverageSet,
}

impl CoverageEvaluation {
    /// Construct a passing evaluation.
    pub fn pass(coverage: CoverageSet) -> Self {
        Self {
            outcome: Ok(()),
            coverage,
        }
    }

    /// Construct a failing evaluation.
    pub fn fail(error: impl Into<String>, coverage: CoverageSet) -> Self {
        Self {
            outcome: Err(error.into()),
            coverage,
        }
    }

    /// Construct an evaluation from an existing pass/fail outcome.
    pub fn from_outcome(outcome: Result<(), String>, coverage: CoverageSet) -> Self {
        Self { outcome, coverage }
    }

    /// Replay outcome attached to this evaluation.
    pub fn outcome(&self) -> &Result<(), String> {
        &self.outcome
    }

    /// Coverage or semantic features observed while replaying the case.
    pub fn coverage(&self) -> &CoverageSet {
        &self.coverage
    }

    /// Returns `true` when `outcome` is `Err`.
    pub fn is_failure(&self) -> bool {
        self.outcome.is_err()
    }
}

/// Metadata that identifies where a materialized case came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseMeta {
    pub(crate) seed: Option<u64>,
    pub(crate) parent: Option<u64>,
    pub(crate) depth: usize,
}

impl CaseMeta {
    /// Metadata for a root case.
    pub fn root(seed: Option<u64>) -> Self {
        Self {
            seed,
            parent: None,
            depth: 0,
        }
    }

    /// Seed that generated the case, if it came directly from [`Fuzzer::sequences`].
    pub fn seed(&self) -> Option<u64> {
        self.seed
    }

    /// Parent corpus entry, if this case came from mutation.
    pub fn parent(&self) -> Option<u64> {
        self.parent
    }

    /// Mutation depth from the original generated seed case.
    pub fn depth(&self) -> usize {
        self.depth
    }
}

/// A case accepted into a coverage-guided corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedCase<Op> {
    pub(crate) id: u64,
    pub(crate) seed: Option<u64>,
    pub(crate) parent: Option<u64>,
    pub(crate) depth: usize,
    pub(crate) ops: Vec<Op>,
    pub(crate) coverage: CoverageSet,
    pub(crate) unique_coverage: CoverageSet,
    pub(crate) outcome: Result<(), String>,
    pub(crate) cost: u64,
    pub(crate) len: usize,
}

impl<Op> AcceptedCase<Op> {
    /// Monotonic ID assigned by the coverage-guided iterator.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Seed that generated the case, if it came directly from [`Fuzzer::sequences`].
    pub fn seed(&self) -> Option<u64> {
        self.seed
    }

    /// Parent corpus entry, if this case came from mutation.
    pub fn parent(&self) -> Option<u64> {
        self.parent
    }

    /// Mutation depth from the original generated seed case.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Materialized operation list for replay or reproduction.
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    /// Full coverage observed while replaying this entry.
    pub fn coverage(&self) -> &CoverageSet {
        &self.coverage
    }

    /// Coverage this entry added to the corpus when accepted.
    pub fn unique_coverage(&self) -> &CoverageSet {
        &self.unique_coverage
    }

    /// `Ok(())` if replay passed, `Err` with the failure message otherwise.
    pub fn outcome(&self) -> &Result<(), String> {
        &self.outcome
    }

    /// Caller-defined case cost.
    pub fn cost(&self) -> u64 {
        self.cost
    }

    /// Operation count.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when `outcome` is `Err`.
    pub fn is_failure(&self) -> bool {
        self.outcome.is_err()
    }
}

/// Backwards-compatible name for accepted coverage cases.
pub type CoveredCase<Op> = AcceptedCase<Op>;

/// Materialized operation sequence ready for coverage capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputCase<Op> {
    pub(crate) seed: Option<u64>,
    pub(crate) parent: Option<u64>,
    pub(crate) depth: usize,
    pub(crate) ops: Vec<Op>,
}

impl<Op> InputCase<Op> {
    /// Create a root case with no parent.
    pub fn root(seed: Option<u64>, ops: Vec<Op>) -> Self {
        Self {
            seed,
            parent: None,
            depth: 0,
            ops,
        }
    }

    /// Seed that generated the case, if it came directly from [`Fuzzer::sequences`].
    pub fn seed(&self) -> Option<u64> {
        self.seed
    }

    /// Parent corpus entry, if this case came from mutation.
    pub fn parent(&self) -> Option<u64> {
        self.parent
    }

    /// Mutation depth from the original generated seed case.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Materialized operation list for replay or reproduction.
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }
}

/// Backwards-compatible name for materialized input cases.
pub type CoverageCase<Op> = InputCase<Op>;

/// A materialized case plus its observed replay outcome and coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredCase<Op> {
    pub(crate) case: CoverageCase<Op>,
    pub(crate) evaluation: CoverageEvaluation,
}

impl<Op> MeasuredCase<Op> {
    /// Materialized case that was evaluated.
    pub fn case(&self) -> &CoverageCase<Op> {
        &self.case
    }

    /// Replay outcome and coverage produced by the evaluator.
    pub fn evaluation(&self) -> &CoverageEvaluation {
        &self.evaluation
    }
}

/// Iterator that evaluates coverage for materialized cases.
pub struct MeasureCoverage<I, Evaluate> {
    inner: I,
    evaluate: Evaluate,
}

impl<I, Evaluate> MeasureCoverage<I, Evaluate> {
    fn new(inner: I, evaluate: Evaluate) -> Self {
        Self { inner, evaluate }
    }
}

impl<I, Op, Evaluate> Iterator for MeasureCoverage<I, Evaluate>
where
    I: Iterator<Item = InputCase<Op>>,
    Evaluate: CoverageEvaluator<Op>,
{
    type Item = Result<MeasuredCase<Op>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        let case = self.inner.next()?;
        let evaluation = match self.evaluate.evaluate(&case.ops) {
            Ok(evaluation) => evaluation,
            Err(error) => return Some(Err(error)),
        };
        Some(Ok(MeasuredCase { case, evaluation }))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<I, Op, Evaluate> std::iter::FusedIterator for MeasureCoverage<I, Evaluate>
where
    I: Iterator<Item = InputCase<Op>> + std::iter::FusedIterator,
    Evaluate: CoverageEvaluator<Op>,
{
}

/// Iterator adapters for materialized coverage cases.
pub trait InputCaseIteratorExt<Op>: Iterator<Item = InputCase<Op>> + Sized {
    /// Evaluate each materialized case and attach its coverage.
    fn measure_coverage<Evaluate>(self, evaluate: Evaluate) -> MeasureCoverage<Self, Evaluate>
    where
        Evaluate: CoverageEvaluator<Op>,
    {
        MeasureCoverage::new(self, evaluate)
    }

    /// Start guard-based coverage exploration over these materialized cases.
    fn explore_coverage<Capture>(self, capture: Capture) -> CoverageExplorer<Op, Self, Capture>
    where
        Op: Clone,
        Capture: CoverageCapture,
    {
        CoverageExplorer::new(self, capture)
    }
}

impl<I, Op> InputCaseIteratorExt<Op> for I where I: Iterator<Item = InputCase<Op>> {}

/// Backwards-compatible extension-trait name.
pub trait CoverageCaseIteratorExt<Op>: InputCaseIteratorExt<Op> {}

impl<I, Op> CoverageCaseIteratorExt<Op> for I where I: InputCaseIteratorExt<Op> {}

/// Return the directory used for coverage/fuzzing artifacts.
///
/// `FUZZ_OUT_DIR` wins when present. Otherwise this uses the parent directory of
/// `LLVM_PROFILE_FILE`, which keeps accepted cases beside the generated `.profraw` files.
pub fn fuzz_output_dir_from_env(default: impl Into<PathBuf>) -> PathBuf {
    if let Some(path) = std::env::var_os("FUZZ_OUT_DIR") {
        return PathBuf::from(path);
    }

    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        let profile = PathBuf::from(profile);
        if let Some(parent) = profile.parent() {
            return parent.to_path_buf();
        }
    }

    default.into()
}

/// Writes accepted coverage-guided cases as `Debug`-formatted operation lists.
///
/// This exporter is intentionally format-light: the files are meant to be durable artifacts for
/// inspection and later conversion into domain-specific replay tests.
pub struct DebugCaseExporter {
    cases_dir: PathBuf,
    manifest: File,
}

impl DebugCaseExporter {
    /// Create an exporter rooted at `out_dir/cases`.
    pub fn new(out_dir: impl AsRef<Path>) -> io::Result<Self> {
        let cases_dir = out_dir.as_ref().join("cases");
        fs::create_dir_all(&cases_dir)?;
        let mut manifest = File::create(cases_dir.join("manifest.tsv"))?;
        writeln!(
            manifest,
            "accepted\tid\tseed\tparent\tdepth\tlen\tcost\tnew_coverage\toutcome\tfile"
        )?;
        Ok(Self {
            cases_dir,
            manifest,
        })
    }

    /// Directory containing the manifest and exported case files.
    pub fn cases_dir(&self) -> &Path {
        &self.cases_dir
    }

    /// Export one accepted corpus case.
    pub fn export<Op: Debug>(
        &mut self,
        accepted: usize,
        case: &AcceptedCase<Op>,
    ) -> io::Result<()> {
        let file_name = format!("case-{accepted:06}-id-{:06}.ops.txt", case.id);
        self.write_ops_file(
            &file_name,
            &case.ops,
            &[
                format!("accepted={accepted}"),
                format!("id={}", case.id),
                format!("seed={:?}", case.seed),
                format!("parent={:?}", case.parent),
                format!("depth={}", case.depth),
                format!("len={}", case.len),
                format!("cost={}", case.cost),
                format!("new_coverage={}", case.unique_coverage.len()),
                format!(
                    "outcome={}",
                    if case.is_failure() { "failure" } else { "pass" }
                ),
            ],
        )?;

        writeln!(
            self.manifest,
            "{accepted}\t{}\t{:?}\t{:?}\t{}\t{}\t{}\t{}\t{}\t{}",
            case.id,
            case.seed,
            case.parent,
            case.depth,
            case.len,
            case.cost,
            case.unique_coverage.len(),
            if case.is_failure() { "failure" } else { "pass" },
            file_name
        )?;
        self.manifest.flush()
    }

    /// Export a minimized failing operation list related to an accepted case.
    pub fn export_minimized_failure<Op: Debug>(
        &mut self,
        id: u64,
        ops: &[Op],
        error: &str,
        cost: u64,
    ) -> io::Result<()> {
        let file_name = format!("failure-minimized-id-{id:06}.ops.txt");
        self.write_ops_file(
            &file_name,
            ops,
            &[
                format!("id={id}"),
                format!("len={}", ops.len()),
                format!("cost={cost}"),
                "outcome=failure-minimized".to_string(),
                format!("error={}", error.replace('\n', "\\n")),
            ],
        )
    }

    fn write_ops_file<Op: Debug>(
        &self,
        file_name: &str,
        ops: &[Op],
        metadata: &[String],
    ) -> io::Result<()> {
        let mut file = File::create(self.cases_dir.join(file_name))?;
        writeln!(file, "// iterator-fuzz coverage-guided case")?;
        for item in metadata {
            writeln!(file, "// {item}")?;
        }
        writeln!(file, "let ops = vec![")?;
        for op in ops {
            writeln!(file, "    {op:?},")?;
        }
        writeln!(file, "];")
    }
}

/// Evaluates a materialized operation sequence for direct coverage filtering.
pub trait CoverageEvaluator<Op> {
    /// Replay `ops` and return the observed outcome and coverage.
    fn evaluate(&mut self, ops: &[Op]) -> Result<CoverageEvaluation, String>;
}

impl<Op, F> CoverageEvaluator<Op> for F
where
    F: FnMut(&[Op]) -> Result<CoverageEvaluation, String>,
{
    fn evaluate(&mut self, ops: &[Op]) -> Result<CoverageEvaluation, String> {
        self(ops)
    }
}

/// Backwards-compatible evaluator trait name.
pub trait CaseEvaluator<Op>: CoverageEvaluator<Op> {}

impl<Op, T> CaseEvaluator<Op> for T where T: CoverageEvaluator<Op> {}

/// Starts and finishes coverage capture for guard-based exploration.
pub trait CoverageCapture {
    /// Opaque per-case capture token.
    type Token;

    /// Start capturing one case.
    fn start_capture(&mut self) -> Result<Self::Token, String>;

    /// Finish capturing one case and attach coverage to the caller-reported outcome.
    fn finish_capture(
        &mut self,
        token: Self::Token,
        outcome: Result<(), String>,
    ) -> Result<CoverageEvaluation, String>;
}

/// Final hook before a generated, mutated, or shrunk operation list is evaluated.
pub trait CaseFinalizer<Op> {
    /// Normalize or complete `ops` in place.
    fn finalize(&mut self, ops: &mut Vec<Op>);
}

impl<Op, F> CaseFinalizer<Op> for F
where
    F: FnMut(&mut Vec<Op>),
{
    fn finalize(&mut self, ops: &mut Vec<Op>) {
        self(ops);
    }
}

/// A finalizer that leaves cases unchanged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopFinalize;

impl<Op> CaseFinalizer<Op> for NoopFinalize {
    fn finalize(&mut self, _ops: &mut Vec<Op>) {}
}

/// A sequence mutator that emits no candidates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopSequenceMutator;

impl<Op> SequenceMutator<Op> for NoopSequenceMutator {
    fn mutate(&mut self, _ops: &[Op], _emit: &mut dyn FnMut(Vec<Op>)) {}
}

pub(crate) struct PendingCoverageCase<Op> {
    pub(crate) case: CoverageCase<Op>,
    pub(crate) priority: u64,
    pub(crate) order: u64,
}

pub(crate) const DEFAULT_SEED_INTERVAL: usize = 1;
