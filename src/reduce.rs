use crate::{CostModel, CoverageSet, SequenceMutator, UnitCost};

/// Return coverage in `candidate` that is absent from `global`.
pub fn coverage_delta(global: &CoverageSet, candidate: &CoverageSet) -> CoverageSet {
    candidate.difference(global)
}

/// Returns `true` when a case should be added to the corpus.
///
/// Failing cases are always interesting. Passing cases are interesting only when they add at least
/// one coverage ID not yet present in `global`.
pub fn is_coverage_interesting(
    global: &CoverageSet,
    candidate: &CoverageSet,
    is_failure: bool,
) -> bool {
    is_failure || !coverage_delta(global, candidate).is_empty()
}

/// Greedily shrink a failing operation list by deleting contiguous chunks with unit cost.
pub fn reduce<Op, Fails>(ops: &[Op], fails: Fails) -> Vec<Op>
where
    Op: Clone,
    Fails: FnMut(&[Op]) -> bool,
{
    reduce_with_cost(ops, &UnitCost, fails)
}

/// Greedily shrink a failing operation list with a caller-provided cost model.
///
/// The reducer preserves operation order and only removes operations. It accepts a candidate when
/// it still fails and has a lower `(total_cost, len)` score than the current best reproduction.
pub fn reduce_with_cost<Op, Cost, Fails>(ops: &[Op], cost: &Cost, mut fails: Fails) -> Vec<Op>
where
    Op: Clone,
    Cost: CostModel<Op>,
    Fails: FnMut(&[Op]) -> bool,
{
    reduce_by_deletion(ops.to_vec(), cost, &mut fails)
}

/// Greedily shrink a failing operation list with caller-provided sequence transforms.
///
/// The built-in reducer only assumes deletion is valid. `transforms` is the caller's hook for
/// domain-valid rewrites over the existing operation type: simplify an op's fields, replace a batch
/// op with a smaller batch, reorder operations only when that is valid for the domain, and so on.
///
/// Each emitted candidate is deletion-reduced again, then accepted only if it still fails and has a
/// lower `(total_cost, len)` score than the current best. This lets neutral transforms help when
/// they make later deletion possible without making swaps or other rewrites globally implicit.
pub fn reduce_with_cost_and_transforms<Op, Cost, Fails, Transforms>(
    ops: &[Op],
    cost: &Cost,
    mut fails: Fails,
    mut transforms: Transforms,
) -> Vec<Op>
where
    Op: Clone,
    Cost: CostModel<Op>,
    Fails: FnMut(&[Op]) -> bool,
    Transforms: SequenceMutator<Op>,
{
    let mut minimized = reduce_by_deletion(ops.to_vec(), cost, &mut fails);
    let mut best_score = score(&minimized, cost);

    loop {
        let mut accepted = None;
        transforms.mutate(&minimized, &mut |candidate| {
            if accepted.is_some() {
                return;
            }
            let reduced = reduce_by_deletion(candidate, cost, &mut fails);
            let candidate_score = score(&reduced, cost);
            if candidate_score < best_score && fails(&reduced) {
                accepted = Some((reduced, candidate_score));
            }
        });

        let Some((candidate, candidate_score)) = accepted else {
            break;
        };
        minimized = candidate;
        best_score = candidate_score;
    }

    minimized
}

/// Greedily shrink an operation list while preserving an arbitrary predicate.
///
/// This is the coverage-preserving sibling of [`reduce_with_cost_and_transforms`]. A caller can
/// require that the candidate keeps a set of coverage IDs, keeps a failure, or both. The same
/// [`SequenceMutator`] hook is used here so domain-aware rewrites can simplify cases beyond
/// deletion.
pub fn reduce_preserving_with_transforms<Op, Cost, Preserves, Transforms>(
    ops: &[Op],
    cost: &Cost,
    mut preserves: Preserves,
    mut transforms: Transforms,
) -> Vec<Op>
where
    Op: Clone,
    Cost: CostModel<Op>,
    Preserves: FnMut(&[Op]) -> bool,
    Transforms: SequenceMutator<Op>,
{
    let mut minimized = reduce_by_deletion(ops.to_vec(), cost, &mut preserves);
    let mut best_score = score(&minimized, cost);

    loop {
        let mut accepted = None;
        transforms.mutate(&minimized, &mut |candidate| {
            if accepted.is_some() {
                return;
            }
            let reduced = reduce_by_deletion(candidate, cost, &mut preserves);
            let candidate_score = score(&reduced, cost);
            if candidate_score < best_score && preserves(&reduced) {
                accepted = Some((reduced, candidate_score));
            }
        });

        let Some((candidate, candidate_score)) = accepted else {
            break;
        };
        minimized = candidate;
        best_score = candidate_score;
    }

    minimized
}

/// Emit deletion candidates for a sequence.
///
/// Protocol targets can use this as their generic shrink pass before adding domain-specific
/// rewrites. Candidates include progressively smaller contiguous chunk deletions and then
/// single-operation deletions.
pub fn emit_deletion_candidates<Op: Clone>(ops: &[Op], emit: &mut dyn FnMut(Vec<Op>)) {
    if ops.is_empty() {
        return;
    }

    let mut chunk_len = ops.len().max(1).next_power_of_two() / 2;
    while chunk_len > 1 {
        let mut index = 0;
        while index + chunk_len <= ops.len() {
            let mut candidate = ops.to_vec();
            candidate.drain(index..index + chunk_len);
            emit(candidate);
            index += chunk_len;
        }
        chunk_len /= 2;
    }

    for index in 0..ops.len() {
        let mut candidate = ops.to_vec();
        candidate.remove(index);
        emit(candidate);
    }
}

fn reduce_by_deletion<Op, Cost, Fails>(
    mut minimized: Vec<Op>,
    cost: &Cost,
    fails: &mut Fails,
) -> Vec<Op>
where
    Op: Clone,
    Cost: CostModel<Op>,
    Fails: FnMut(&[Op]) -> bool,
{
    let mut best_score = score(&minimized, cost);
    let mut chunk_len = minimized.len().max(1).next_power_of_two() / 2;

    while chunk_len > 0 {
        let mut index = 0;
        let mut accepted_candidate = false;

        while index + chunk_len <= minimized.len() {
            let mut candidate = minimized.clone();
            candidate.drain(index..index + chunk_len);
            let candidate_score = score(&candidate, cost);

            if candidate_score < best_score && fails(&candidate) {
                minimized = candidate;
                best_score = candidate_score;
                accepted_candidate = true;
            } else {
                index += chunk_len;
            }
        }

        if !accepted_candidate {
            chunk_len /= 2;
        }
    }

    minimized
}

fn score<Op, Cost>(ops: &[Op], cost: &Cost) -> (u64, usize)
where
    Cost: CostModel<Op>,
{
    (cost.total_cost(ops), ops.len())
}
