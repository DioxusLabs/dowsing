use super::{
    prelude::{
        CandidateOrigin, CautiousOptions, CautiousReducer, CorpusSeed, DrawSpan, MAX_CORPUS_LEN,
        MAX_DICTIONARY_VALUES, MAX_PREFIX_LEN, MAX_REDUCER_TRIED_PREFIXES, MinPathScore,
        MutationWeights, PrefixFingerprint, ReductionId, ReductionOp, ReductionOperation,
        ReductionOperationState, ReductionSpec, ReductionWeights, ScalarSpan, SequenceSpan,
        StateCore,
    },
    run::Candidate,
};
use dowsing_rng::ByteAffinity;
use std::ops::Range;

const REDUCTION_OPERATIONS: [ReductionOperation; 15] = [
    ReductionOperation::SequenceDelete,
    ReductionOperation::ScalarGroup,
    ReductionOperation::ScalarCommonOffset,
    ReductionOperation::ScalarLower,
    ReductionOperation::DrawLength,
    ReductionOperation::TailTrim,
    ReductionOperation::DrawDelete,
    ReductionOperation::SequenceProject,
    ReductionOperation::SequenceReplace,
    ReductionOperation::WeightedBlockDelete,
    ReductionOperation::BlockZero,
    ReductionOperation::WordLower,
    ReductionOperation::ByteLower,
    ReductionOperation::RepeatedValue,
    ReductionOperation::DictionaryRepair,
];

impl ReductionOperationState {
    fn new(operation: ReductionOperation) -> Self {
        Self {
            operation,
            specs: Vec::new(),
            cursor: 0,
            rejects: 0,
            preserves: 0,
            drained: false,
        }
    }
}

pub(super) fn merge_dictionary_values(state: &mut StateCore, values: Vec<Vec<u8>>) {
    let dictionary = std::sync::Arc::make_mut(&mut state.dictionary);
    for value in values {
        if dictionary.len() >= MAX_DICTIONARY_VALUES {
            break;
        }
        if value.is_empty() || dictionary.iter().any(|existing| existing == &value) {
            continue;
        }
        dictionary.push(value);
    }
}

pub(super) fn next_cautious_reduction(state: &mut StateCore) -> Option<Candidate> {
    if state.cautious_reducer.best_index != state.min_path_best_index {
        reset_cautious_reducer_to_best(state);
    }

    state.cautious_reducer.next_candidate(
        &state.dictionary,
        state.cautious_options,
        &state.mutation_weights,
        &state.reduction_weights,
    )
}

pub(super) fn reset_cautious_reducer_to_best(state: &mut StateCore) {
    let Some(index) = state.min_path_best_index else {
        state.cautious_reducer = CautiousReducer::default();
        return;
    };
    let Some(entry) = state.corpus.get(index) else {
        state.cautious_reducer = CautiousReducer::default();
        return;
    };
    state.cautious_reducer.reset(index, entry);
}

pub(super) fn record_cautious_discard(state: &mut StateCore, origin: &CandidateOrigin) {
    if let Some(operation) = current_reduction_operation(state, origin) {
        state.reduction_weights.penalize_rejected(operation);
    }
    state.cautious_reducer.record_discard(
        origin,
        &state.mutation_weights,
        &state.reduction_weights,
    );
}

pub(super) fn record_cautious_preserved(state: &mut StateCore, origin: &CandidateOrigin) {
    if let Some(operation) = current_reduction_operation(state, origin) {
        state.reduction_weights.reward_preserved(operation);
    }
    state.cautious_reducer.record_preserved(
        origin,
        &state.mutation_weights,
        &state.reduction_weights,
    );
}

pub(super) fn record_cautious_improved(state: &mut StateCore, origin: &CandidateOrigin) {
    if let Some(operation) = current_reduction_operation(state, origin) {
        state.reduction_weights.reward_improved(operation);
    }
}

fn current_reduction_operation(
    state: &StateCore,
    origin: &CandidateOrigin,
) -> Option<ReductionOperation> {
    let CandidateOrigin::CautiousReduction(id) = origin else {
        return None;
    };
    (id.epoch == state.cautious_reducer.epoch).then_some(id.operation)
}

impl CautiousReducer {
    fn reset(&mut self, index: usize, entry: &CorpusSeed) {
        self.epoch = self.epoch.wrapping_add(1);
        self.best_index = Some(index);
        self.best_seed = entry.seed;
        self.best_case = entry.case.clone();
        self.best_prefix = entry.prefix.clone();
        self.best_draws = entry.draws.clone();
        self.best_scalars = entry.scalars.clone();
        self.best_sequences = entry.sequences.clone();
        self.operation_states = REDUCTION_OPERATIONS
            .iter()
            .copied()
            .map(ReductionOperationState::new)
            .collect();
        self.tried_prefixes.clear();
        self.tried_prefixes
            .insert(prefix_fingerprint(&self.best_prefix));
        self.range_pressure.clear();
        self.range_pressure.resize(self.best_prefix.len(), 1);
        self.rejects = 0;
        self.preserves = 0;
        self.exhausted = false;
    }

    fn next_candidate(
        &mut self,
        dictionary: &[Vec<u8>],
        options: CautiousOptions,
        weights: &MutationWeights,
        reduction_weights: &ReductionWeights,
    ) -> Option<Candidate> {
        if self.exhausted {
            return None;
        }

        for _ in 0..options.reducer_budget() {
            self.prepare_operation_states(dictionary, options, weights, reduction_weights);
            let Some(state_index) = self.next_operation_index(weights, reduction_weights) else {
                self.exhausted = true;
                return None;
            };

            let state = &mut self.operation_states[state_index];
            let operation = state.operation;
            let cursor = state.cursor;
            let spec = state.specs[cursor].clone();
            state.cursor += 1;
            if state.cursor >= state.specs.len() {
                state.drained = true;
            }

            let Some((mut case, mut prefix)) = spec.op.materialize(
                self.best_seed,
                &self.best_case,
                &self.best_prefix,
                dictionary,
            ) else {
                continue;
            };
            if prefix.len() > MAX_PREFIX_LEN {
                prefix.truncate(MAX_PREFIX_LEN);
                case = super::prelude::Case::from_flat_prefix(self.best_seed, prefix.clone());
            }
            if prefix == self.best_prefix {
                continue;
            }

            let fingerprint = prefix_fingerprint(&prefix);
            if self.tried_prefixes.contains(&fingerprint) {
                continue;
            }
            if self.tried_prefixes.len() >= MAX_REDUCER_TRIED_PREFIXES {
                self.tried_prefixes.clear();
                self.tried_prefixes
                    .insert(prefix_fingerprint(&self.best_prefix));
            }
            self.tried_prefixes.insert(fingerprint);

            let id = ReductionId {
                epoch: self.epoch,
                operation,
                type_id: spec.op.type_id,
                cursor,
                start: spec.start(),
                len: spec.len(),
                target: spec.target(),
                fingerprint,
            };
            return Some(Candidate {
                case,
                mutated: true,
                origin: CandidateOrigin::CautiousReduction(id),
            });
        }

        None
    }

    fn prepare_operation_states(
        &mut self,
        dictionary: &[Vec<u8>],
        options: CautiousOptions,
        weights: &MutationWeights,
        reduction_weights: &ReductionWeights,
    ) {
        let prefix = &self.best_prefix;
        let draws = &self.best_draws;
        let scalars = &self.best_scalars;
        let sequences = &self.best_sequences;
        let pressure = &self.range_pressure;
        for state in &mut self.operation_states {
            if state.drained || !state.specs.is_empty() {
                continue;
            }

            state.specs = reduction_specs(
                state.operation,
                ReductionContext {
                    prefix,
                    draws,
                    scalars,
                    sequences,
                    dictionary,
                    pressure,
                    options,
                },
            );
            sort_operation_tail(state, pressure, weights, reduction_weights);
            state.drained = state.specs.is_empty();
        }
    }

    fn next_operation_index(
        &self,
        weights: &MutationWeights,
        reduction_weights: &ReductionWeights,
    ) -> Option<usize> {
        let mut best = None;
        for (index, state) in self.operation_states.iter().enumerate() {
            if state.drained || state.cursor >= state.specs.len() {
                continue;
            }
            let spec = &state.specs[state.cursor];
            let priority = candidate_priority(
                state,
                spec,
                &self.range_pressure,
                weights,
                reduction_weights,
            );
            if best.is_none_or(|(best_priority, best_index)| {
                (priority, index) < (best_priority, best_index)
            }) {
                best = Some((priority, index));
            }
        }
        best.map(|(_, index)| index)
    }

    fn record_discard(
        &mut self,
        origin: &CandidateOrigin,
        weights: &MutationWeights,
        reduction_weights: &ReductionWeights,
    ) {
        let CandidateOrigin::CautiousReduction(id) = origin else {
            return;
        };
        if id.epoch != self.epoch {
            return;
        }

        self.rejects = self.rejects.saturating_add(1);
        if let Some(state) = self
            .operation_states
            .iter_mut()
            .find(|state| state.operation == id.operation)
        {
            state.rejects = state.rejects.saturating_add(1);
        }
        self.apply_range_feedback(id.start, id.len, Feedback::Rejected);
        self.sort_operation_tails(weights, reduction_weights);
    }

    fn record_preserved(
        &mut self,
        origin: &CandidateOrigin,
        weights: &MutationWeights,
        reduction_weights: &ReductionWeights,
    ) {
        let CandidateOrigin::CautiousReduction(id) = origin else {
            return;
        };
        if id.epoch != self.epoch {
            return;
        }

        self.preserves = self.preserves.saturating_add(1);
        if let Some(state) = self
            .operation_states
            .iter_mut()
            .find(|state| state.operation == id.operation)
        {
            state.preserves = state.preserves.saturating_add(1);
        }
        self.apply_range_feedback(id.start, id.len, Feedback::Preserved);
        self.sort_operation_tails(weights, reduction_weights);
    }

    fn sort_operation_tails(
        &mut self,
        weights: &MutationWeights,
        reduction_weights: &ReductionWeights,
    ) {
        let pressure = &self.range_pressure;
        for state in &mut self.operation_states {
            sort_operation_tail(state, pressure, weights, reduction_weights);
        }
    }

    fn apply_range_feedback(&mut self, start: usize, len: usize, feedback: Feedback) {
        if len == 0 || start >= self.range_pressure.len() {
            return;
        }
        let end = start.saturating_add(len).min(self.range_pressure.len());
        for pressure in &mut self.range_pressure[start..end] {
            match feedback {
                Feedback::Rejected => {
                    *pressure = pressure.saturating_add(8);
                }
                Feedback::Preserved => {
                    *pressure = pressure.saturating_sub(1).max(1);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Feedback {
    Rejected,
    Preserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CandidatePriority {
    reduction_weight: std::cmp::Reverse<u64>,
    operation_penalty: u64,
    mutation_weight: std::cmp::Reverse<u64>,
    range_score: u64,
    structure_rank: u8,
    simplification: std::cmp::Reverse<usize>,
    operation_rank: u8,
    start: usize,
    len: usize,
    target: u64,
}

fn candidate_priority(
    state: &ReductionOperationState,
    spec: &ReductionSpec,
    pressure: &[u16],
    weights: &MutationWeights,
    reduction_weights: &ReductionWeights,
) -> CandidatePriority {
    CandidatePriority {
        reduction_weight: std::cmp::Reverse(reduction_weights.priority_key(state.operation)),
        operation_penalty: state.rejects.saturating_sub(state.preserves),
        mutation_weight: std::cmp::Reverse(weights.priority_key(spec.op.type_id)),
        range_score: spec.bias + spec_pressure(pressure, spec),
        structure_rank: operation_structure_rank(state.operation),
        simplification: std::cmp::Reverse(spec.simplification()),
        operation_rank: operation_stable_rank(state.operation),
        start: spec.start(),
        len: spec.len(),
        target: spec.target(),
    }
}

fn sort_operation_tail(
    state: &mut ReductionOperationState,
    pressure: &[u16],
    weights: &MutationWeights,
    reduction_weights: &ReductionWeights,
) {
    if state.cursor >= state.specs.len() {
        state.drained = true;
        return;
    }

    let operation = state.operation;
    state.specs[state.cursor..].sort_by_key(|spec| {
        (
            std::cmp::Reverse(reduction_weights.priority_key(operation)),
            std::cmp::Reverse(weights.priority_key(spec.op.type_id)),
            spec.bias + spec_pressure(pressure, spec),
            std::cmp::Reverse(spec.simplification()),
            spec.start(),
            spec.len(),
            spec.target(),
            operation_stable_rank(operation),
        )
    });
}

fn spec_pressure(pressure: &[u16], spec: &ReductionSpec) -> u64 {
    range_weight(pressure, spec.start(), spec.len()).max(1)
}

fn operation_structure_rank(operation: ReductionOperation) -> u8 {
    match operation {
        ReductionOperation::SequenceDelete
        | ReductionOperation::SequenceProject
        | ReductionOperation::SequenceReplace => 0,
        ReductionOperation::ScalarGroup
        | ReductionOperation::ScalarCommonOffset
        | ReductionOperation::ScalarLower => 1,
        ReductionOperation::DrawLength | ReductionOperation::DrawDelete => 2,
        ReductionOperation::TailTrim
        | ReductionOperation::WeightedBlockDelete
        | ReductionOperation::DictionaryRepair => 3,
        ReductionOperation::BlockZero
        | ReductionOperation::WordLower
        | ReductionOperation::ByteLower
        | ReductionOperation::RepeatedValue => 4,
    }
}

fn operation_stable_rank(operation: ReductionOperation) -> u8 {
    match operation {
        ReductionOperation::SequenceDelete => 0,
        ReductionOperation::ScalarGroup => 1,
        ReductionOperation::ScalarCommonOffset => 2,
        ReductionOperation::ScalarLower => 3,
        ReductionOperation::DrawLength => 4,
        ReductionOperation::TailTrim => 5,
        ReductionOperation::DrawDelete => 6,
        ReductionOperation::SequenceProject => 7,
        ReductionOperation::SequenceReplace => 8,
        ReductionOperation::WeightedBlockDelete => 9,
        ReductionOperation::BlockZero => 10,
        ReductionOperation::WordLower => 11,
        ReductionOperation::ByteLower => 12,
        ReductionOperation::RepeatedValue => 13,
        ReductionOperation::DictionaryRepair => 14,
    }
}

struct ReductionContext<'a> {
    prefix: &'a [u8],
    draws: &'a [DrawSpan],
    scalars: &'a [ScalarSpan],
    sequences: &'a [SequenceSpan],
    dictionary: &'a [Vec<u8>],
    pressure: &'a [u16],
    options: CautiousOptions,
}

fn reduction_specs(
    operation: ReductionOperation,
    context: ReductionContext<'_>,
) -> Vec<ReductionSpec> {
    let mut specs = match operation {
        ReductionOperation::SequenceDelete if context.options.range_reductions() => {
            sequence_delete_specs(
                context.prefix,
                context.sequences,
                context.pressure,
                context.options,
            )
        }
        ReductionOperation::SequenceDelete => Vec::new(),
        ReductionOperation::SequenceProject if context.options.range_reductions() => {
            sequence_project_specs(
                context.prefix,
                context.sequences,
                context.pressure,
                context.options,
            )
        }
        ReductionOperation::SequenceReplace if context.options.range_reductions() => {
            sequence_replace_specs(
                context.prefix,
                context.sequences,
                context.pressure,
                context.options,
            )
        }
        ReductionOperation::SequenceProject | ReductionOperation::SequenceReplace => Vec::new(),
        ReductionOperation::ScalarGroup => scalar_group_specs(
            context.prefix,
            context.scalars,
            context.pressure,
            context.options,
        ),
        ReductionOperation::ScalarCommonOffset => scalar_common_offset_specs(
            context.prefix,
            context.scalars,
            context.pressure,
            context.options,
        ),
        ReductionOperation::ScalarLower => scalar_lower_specs(
            context.prefix,
            context.scalars,
            context.pressure,
            context.options,
        ),
        ReductionOperation::DrawLength => draw_length_specs(
            context.prefix,
            context.draws,
            context.pressure,
            context.options,
        ),
        ReductionOperation::TailTrim => tail_trim_specs(context.prefix, context.pressure),
        ReductionOperation::DrawDelete => draw_delete_specs(
            context.prefix,
            context.draws,
            context.pressure,
            context.options,
        ),
        ReductionOperation::WeightedBlockDelete => {
            weighted_block_delete_specs(context.prefix, context.pressure)
        }
        ReductionOperation::BlockZero => block_zero_specs(context.prefix, context.pressure),
        ReductionOperation::WordLower => word_lower_specs(
            context.prefix,
            context.draws,
            context.pressure,
            context.options,
        ),
        ReductionOperation::ByteLower => byte_lower_specs(context.prefix, context.pressure),
        ReductionOperation::RepeatedValue => repeated_value_specs(context.prefix),
        ReductionOperation::DictionaryRepair => {
            dictionary_repair_specs(context.prefix, context.dictionary, context.pressure)
        }
    };
    truncate_specs(&mut specs, context.options.operation_candidate_limit());
    specs
}

fn sequence_delete_specs(
    prefix: &[u8],
    sequences: &[SequenceSpan],
    pressure: &[u16],
    options: CautiousOptions,
) -> Vec<ReductionSpec> {
    let mut specs = Vec::new();
    for sequence in sequences.iter().take(options.range_limit()) {
        if sequence.length_len == 0
            || sequence.length_start >= prefix.len()
            || sequence.length_start.saturating_add(sequence.length_len) > prefix.len()
            || sequence.items.is_empty()
        {
            continue;
        }

        for count in shrink_sizes_including_full(sequence.items.len()) {
            if count == 0 || count > sequence.items.len() {
                continue;
            }
            for item_start in block_starts(sequence.items.len(), count) {
                let item_end = (item_start + count).min(sequence.items.len());
                if item_start >= item_end {
                    continue;
                }
                let first = &sequence.items[item_start];
                let last = &sequence.items[item_end - 1];
                if !valid_range(prefix, first)
                    || !valid_range(prefix, last)
                    || first.start >= last.end
                {
                    continue;
                }
                let target_len = sequence.items.len() - (item_end - item_start);
                specs.push(ReductionSpec {
                    op: ReductionOp::delete_sequence_items(
                        sequence.length_start,
                        sequence.length_len,
                        target_len,
                        first.start,
                        last.end - first.start,
                    ),
                    bias: 0,
                });
            }
        }
    }
    specs.sort_by_key(|spec| {
        (
            spec_pressure(pressure, spec),
            std::cmp::Reverse(spec.simplification()),
            spec.start(),
        )
    });
    specs
}

fn sequence_project_specs(
    prefix: &[u8],
    sequences: &[SequenceSpan],
    pressure: &[u16],
    options: CautiousOptions,
) -> Vec<ReductionSpec> {
    let mut specs = Vec::new();
    for sequence in sequences.iter().take(options.range_limit()) {
        let Some(region) = sequence_region(prefix, sequence) else {
            continue;
        };

        push_sequence_projection(prefix, sequence, region, Vec::new(), 0, &mut specs);

        for keep in sequence_keep_sizes(sequence.items.len()) {
            for item_start in block_starts(sequence.items.len(), keep) {
                let item_end = (item_start + keep).min(sequence.items.len());
                let indices: Vec<_> = (item_start..item_end).collect();
                push_sequence_projection(
                    prefix,
                    sequence,
                    region,
                    indices,
                    keep as u64,
                    &mut specs,
                );
            }
        }

        if sequence.items.len() > 2 {
            let even: Vec<_> = (0..sequence.items.len()).step_by(2).collect();
            push_sequence_projection(prefix, sequence, region, even, 64, &mut specs);
            let odd: Vec<_> = (1..sequence.items.len()).step_by(2).collect();
            push_sequence_projection(prefix, sequence, region, odd, 65, &mut specs);
        }
    }
    specs.sort_by_key(|spec| {
        (
            spec.target(),
            spec.bias + spec_pressure(pressure, spec),
            std::cmp::Reverse(spec.simplification()),
            spec.start(),
        )
    });
    specs
}

fn sequence_replace_specs(
    prefix: &[u8],
    sequences: &[SequenceSpan],
    pressure: &[u16],
    options: CautiousOptions,
) -> Vec<ReductionSpec> {
    let mut specs = Vec::new();
    for sequence in sequences.iter().take(options.range_limit()) {
        let Some(region) = sequence_region(prefix, sequence) else {
            continue;
        };
        if sequence.items.len() < 2 {
            continue;
        }

        for target in 1..sequence.items.len() {
            for source in replacement_sources(prefix, sequence, target) {
                let mut indices: Vec<_> = (0..sequence.items.len()).collect();
                indices[target] = source;
                push_sequence_projection(
                    prefix,
                    sequence,
                    region,
                    indices,
                    128 + target as u64,
                    &mut specs,
                );
            }
        }
    }
    specs.sort_by_key(|spec| (spec_pressure(pressure, spec), spec.start(), spec.target()));
    specs
}

#[derive(Clone, Copy)]
struct SequenceRegion {
    start: usize,
    len: usize,
}

fn sequence_region(prefix: &[u8], sequence: &SequenceSpan) -> Option<SequenceRegion> {
    if sequence.length_len == 0
        || sequence.length_start >= prefix.len()
        || sequence.length_start.saturating_add(sequence.length_len) > prefix.len()
        || sequence.items.is_empty()
    {
        return None;
    }

    let first = sequence.items.first()?;
    let last = sequence.items.last()?;
    if !valid_range(prefix, first) || !valid_range(prefix, last) || first.start >= last.end {
        return None;
    }

    Some(SequenceRegion {
        start: first.start,
        len: last.end - first.start,
    })
}

fn push_sequence_projection(
    prefix: &[u8],
    sequence: &SequenceSpan,
    region: SequenceRegion,
    indices: Vec<usize>,
    weight_bias: u64,
    specs: &mut Vec<ReductionSpec>,
) {
    if indices.len() == sequence.items.len() && indices.iter().copied().eq(0..sequence.items.len())
    {
        return;
    }

    let mut items = Vec::with_capacity(indices.len());
    for index in indices {
        let Some(item) = sequence.items.get(index) else {
            return;
        };
        if !valid_range(prefix, item) {
            return;
        }
        items.push((item.start, item.len()));
    }

    specs.push(ReductionSpec {
        op: ReductionOp::project_sequence_items(
            sequence.length_start,
            sequence.length_len,
            items.len(),
            region.start,
            region.len,
            items,
        ),
        bias: weight_bias,
    });
}

fn sequence_keep_sizes(len: usize) -> Vec<usize> {
    let mut sizes = Vec::new();
    for size in [1, 2, 3, 4, 8, 16, len / 4, len / 2, len.saturating_sub(1)] {
        if size > 0 && size < len && !sizes.contains(&size) {
            sizes.push(size);
        }
    }
    sizes
}

fn replacement_sources(prefix: &[u8], sequence: &SequenceSpan, target: usize) -> Vec<usize> {
    let mut sources = Vec::new();
    push_replacement_source(prefix, sequence, target, 0, &mut sources);
    push_replacement_source(
        prefix,
        sequence,
        target,
        target.saturating_sub(1),
        &mut sources,
    );
    if let Some(source) = simplest_prior_item(prefix, sequence, target) {
        push_replacement_source(prefix, sequence, target, source, &mut sources);
    }
    sources
}

fn push_replacement_source(
    prefix: &[u8],
    sequence: &SequenceSpan,
    target: usize,
    source: usize,
    sources: &mut Vec<usize>,
) {
    if source >= target || sources.contains(&source) {
        return;
    }
    let Some(source_item) = sequence.items.get(source) else {
        return;
    };
    let Some(target_item) = sequence.items.get(target) else {
        return;
    };
    if !item_replacement_simplifies(prefix, source_item, target_item) {
        return;
    }
    sources.push(source);
}

fn simplest_prior_item(prefix: &[u8], sequence: &SequenceSpan, target: usize) -> Option<usize> {
    let target_item = sequence.items.get(target)?;
    (0..target)
        .filter(|index| {
            sequence
                .items
                .get(*index)
                .is_some_and(|source| item_replacement_simplifies(prefix, source, target_item))
        })
        .min_by_key(|index| {
            let item = &sequence.items[*index];
            item_simplicity_key(&prefix[item.clone()])
        })
}

fn item_replacement_simplifies(
    prefix: &[u8],
    source: &Range<usize>,
    target: &Range<usize>,
) -> bool {
    if !valid_range(prefix, source) || !valid_range(prefix, target) {
        return false;
    }
    let source_bytes = &prefix[source.clone()];
    let target_bytes = &prefix[target.clone()];
    item_simplicity_key(source_bytes) < item_simplicity_key(target_bytes)
}

fn item_simplicity_key(bytes: &[u8]) -> (usize, usize, &[u8]) {
    let nonzero = bytes.iter().filter(|byte| **byte != 0).count();
    (bytes.len(), nonzero, bytes)
}

fn scalar_lower_specs(
    prefix: &[u8],
    scalars: &[ScalarSpan],
    pressure: &[u16],
    options: CautiousOptions,
) -> Vec<ReductionSpec> {
    let mut specs = Vec::new();
    for scalar in scalars.iter().take(options.draw_limit()) {
        if !valid_scalar(prefix, scalar) {
            continue;
        }
        let current = read_scalar_rank(prefix, scalar);
        for target in scalar_targets(scalar, current) {
            specs.push(ReductionSpec {
                op: ReductionOp::set_scalar_ranks(
                    vec![(scalar.start, scalar.len(), target)],
                    target_key(target),
                ),
                bias: 0,
            });
        }
    }
    specs.sort_by_key(|spec| {
        (
            spec_pressure(pressure, spec),
            spec.start(),
            spec.len(),
            spec.target(),
        )
    });
    specs
}

fn scalar_group_specs(
    prefix: &[u8],
    scalars: &[ScalarSpan],
    pressure: &[u16],
    options: CautiousOptions,
) -> Vec<ReductionSpec> {
    let scalars: Vec<_> = scalars
        .iter()
        .take(options.draw_limit())
        .filter(|scalar| valid_scalar(prefix, scalar))
        .collect();
    let mut specs = Vec::new();
    for (index, scalar) in scalars.iter().enumerate() {
        let current = read_scalar_rank(prefix, scalar);
        if scalars[..index].iter().any(|candidate| {
            candidate.len() == scalar.len()
                && candidate.span == scalar.span
                && read_scalar_rank(prefix, candidate) == current
        }) {
            continue;
        }
        let mut group = vec![*scalar];
        for candidate in scalars.iter().skip(index + 1) {
            if candidate.len() != scalar.len() || candidate.span != scalar.span {
                continue;
            }
            let candidate_current = read_scalar_rank(prefix, candidate);
            if candidate_current == current {
                group.push(*candidate);
            }
        }
        if group.len() < 2 {
            continue;
        }
        for (target, priority) in scalar_group_targets(scalar, current) {
            let writes: Vec<_> = group
                .iter()
                .map(|scalar| (scalar.start, scalar.len(), target))
                .collect();
            let start = group.iter().map(|scalar| scalar.start).min().unwrap_or(0);
            let end = group.iter().map(|scalar| scalar.end).max().unwrap_or(start);
            specs.push(ReductionSpec {
                op: ReductionOp::set_scalar_ranks(writes, priority),
                bias: range_weight(pressure, start, end.saturating_sub(start)),
            });
        }
    }
    specs.sort_by_key(|spec| {
        (
            spec.bias + spec_pressure(pressure, spec),
            spec.target(),
            spec.start(),
            spec.len(),
        )
    });
    specs
}

#[derive(Clone, Copy)]
struct ScalarRank<'a> {
    scalar: &'a ScalarSpan,
    current: u128,
}

fn scalar_common_offset_specs(
    prefix: &[u8],
    scalars: &[ScalarSpan],
    pressure: &[u16],
    options: CautiousOptions,
) -> Vec<ReductionSpec> {
    let mut ranked: Vec<_> = scalars
        .iter()
        .take(options.draw_limit())
        .filter(|scalar| valid_scalar(prefix, scalar))
        .map(|scalar| ScalarRank {
            scalar,
            current: read_scalar_rank(prefix, scalar),
        })
        .filter(|rank| rank.current > 0)
        .collect();
    ranked.sort_by_key(|rank| (rank.scalar.len(), rank.scalar.span, rank.scalar.start));

    let mut specs = Vec::new();
    let mut start = 0;
    while start < ranked.len() {
        let len = ranked[start].scalar.len();
        let span = ranked[start].scalar.span;
        let mut end = start + 1;
        while end < ranked.len()
            && ranked[end].scalar.len() == len
            && ranked[end].scalar.span == span
        {
            end += 1;
        }
        push_scalar_common_offset_group_specs(&mut specs, &ranked[start..end], pressure);
        start = end;
    }

    specs.sort_by_key(|spec| {
        (
            spec.bias + spec_pressure(pressure, spec),
            spec.target(),
            spec.start(),
            std::cmp::Reverse(spec.simplification()),
            spec.len(),
        )
    });
    specs
}

fn push_scalar_common_offset_group_specs(
    specs: &mut Vec<ReductionSpec>,
    group: &[ScalarRank<'_>],
    pressure: &[u16],
) {
    if group.len() < 2 {
        return;
    }

    push_scalar_common_offset_cohort_specs(specs, group, pressure);
    for width in [8, 4, 3, 2] {
        if width >= group.len() {
            continue;
        }
        for start in 0..=group.len() - width {
            push_scalar_common_offset_cohort_specs(specs, &group[start..start + width], pressure);
        }
    }
}

fn push_scalar_common_offset_cohort_specs(
    specs: &mut Vec<ReductionSpec>,
    cohort: &[ScalarRank<'_>],
    _pressure: &[u16],
) {
    for (delta, priority) in scalar_common_offset_deltas(cohort) {
        let writes: Vec<_> = cohort
            .iter()
            .map(|rank| {
                (
                    rank.scalar.start,
                    rank.scalar.len(),
                    rank.current.saturating_sub(delta),
                )
            })
            .collect();
        specs.push(ReductionSpec {
            op: ReductionOp::set_scalar_ranks(writes, priority),
            bias: 0,
        });
    }
}

fn scalar_common_offset_deltas(cohort: &[ScalarRank<'_>]) -> Vec<(u128, u64)> {
    let Some(max_delta) = cohort.iter().map(|rank| rank.current).min() else {
        return Vec::new();
    };
    if max_delta == 0 {
        return Vec::new();
    }

    let mut deltas = Vec::new();
    for rank in cohort {
        for target in scalar_common_offset_targets(rank.scalar, rank.current) {
            if target >= rank.current {
                continue;
            }
            let delta = rank.current - target;
            if delta == 0
                || delta > max_delta
                || deltas
                    .iter()
                    .any(|(existing, _): &(u128, u64)| *existing == delta)
            {
                continue;
            }
            if cohort.iter().any(|candidate| {
                !scalar_target_allowed(candidate.scalar, candidate.current.saturating_sub(delta))
            }) {
                continue;
            }
            let priority = deltas.len().min(u64::MAX as usize) as u64;
            deltas.push((delta, priority));
        }
    }
    deltas
}

fn scalar_common_offset_targets(scalar: &ScalarSpan, current: u128) -> Vec<u128> {
    let mut targets = Vec::new();
    for target in scalar_group_base_targets().into_iter().chain([
        current / 2,
        current / 4,
        current / 8,
        current.saturating_sub(1),
    ]) {
        if target != current && scalar_target_allowed(scalar, target) && !targets.contains(&target)
        {
            targets.push(target);
        }
    }
    targets
}

fn draw_length_specs(
    prefix: &[u8],
    draws: &[DrawSpan],
    pressure: &[u16],
    options: CautiousOptions,
) -> Vec<ReductionSpec> {
    let mut specs = Vec::new();
    for draw in draws.iter().take(options.draw_limit()) {
        if !valid_draw(prefix, draw) {
            continue;
        }
        if draw.affinity == ByteAffinity::Zero
            && prefix[draw.start..draw.end].iter().any(|byte| *byte != 0)
        {
            specs.push(ReductionSpec {
                op: ReductionOp::zero_range(draw.start, draw.len()),
                bias: 0,
            });
        }
        for width in draw_widths(draw) {
            if draw.start + width > prefix.len() {
                continue;
            }
            let current = read_le_word(&prefix[draw.start..draw.start + width]);
            for target in small_length_targets(current, width) {
                specs.push(ReductionSpec {
                    op: ReductionOp::set_word(draw.start, width, target, Some(draw.end)),
                    bias: 0,
                });
            }
        }
    }
    specs.sort_by_key(|spec| {
        (
            spec_pressure(pressure, spec),
            spec.start(),
            spec.len(),
            spec.target(),
        )
    });
    specs
}

fn tail_trim_specs(prefix: &[u8], pressure: &[u16]) -> Vec<ReductionSpec> {
    if prefix.is_empty() {
        return Vec::new();
    }

    let mut specs = Vec::new();
    for trim in shrink_sizes_including_full(prefix.len()) {
        let start = prefix.len().saturating_sub(trim);
        specs.push(ReductionSpec {
            op: ReductionOp::delete_range(start, trim, true),
            bias: 0,
        });
    }
    specs.sort_by_key(|spec| {
        (
            spec_pressure(pressure, spec),
            std::cmp::Reverse(spec.simplification()),
            spec.start(),
        )
    });
    specs
}

fn draw_delete_specs(
    prefix: &[u8],
    draws: &[DrawSpan],
    pressure: &[u16],
    options: CautiousOptions,
) -> Vec<ReductionSpec> {
    if prefix.len() <= 1 || draws.is_empty() {
        return Vec::new();
    }

    let mut specs = Vec::new();
    for draw in draws.iter().rev().take(options.draw_limit()) {
        if draw.start == 0 || !valid_draw(prefix, draw) {
            continue;
        }
        specs.push(ReductionSpec {
            op: ReductionOp::delete_range(draw.start, draw.len(), true),
            bias: 0,
        });
    }

    for window in [32, 16, 8, 4, 3, 2] {
        if draws.len() < window {
            continue;
        }
        for chunk in draws.windows(window).rev() {
            let Some(first) = chunk.first() else {
                continue;
            };
            let Some(last) = chunk.last() else {
                continue;
            };
            if first.start == 0 || !valid_draw(prefix, first) || !valid_draw(prefix, last) {
                continue;
            }
            let end = last.end;
            if first.start >= end || end > prefix.len() {
                continue;
            }
            specs.push(ReductionSpec {
                op: ReductionOp::delete_range(first.start, end - first.start, true),
                bias: 0,
            });
        }
    }

    specs.sort_by_key(|spec| {
        (
            spec_pressure(pressure, spec),
            std::cmp::Reverse(spec.simplification()),
            std::cmp::Reverse(spec.start()),
        )
    });
    specs
}

fn weighted_block_delete_specs(prefix: &[u8], pressure: &[u16]) -> Vec<ReductionSpec> {
    if prefix.len() <= 1 {
        return Vec::new();
    }

    let mut specs = Vec::new();
    for width in shrink_sizes(prefix.len()) {
        for start in block_starts(prefix.len(), width) {
            let len = width.min(prefix.len() - start);
            if len == 0 || len >= prefix.len() {
                continue;
            }
            specs.push(ReductionSpec {
                op: ReductionOp::delete_range(start, len, true),
                bias: 0,
            });
        }
    }
    specs.sort_by_key(|spec| {
        (
            spec_pressure(pressure, spec),
            std::cmp::Reverse(spec.simplification()),
            spec.start(),
        )
    });
    specs
}

fn block_zero_specs(prefix: &[u8], pressure: &[u16]) -> Vec<ReductionSpec> {
    if prefix.is_empty() {
        return Vec::new();
    }

    let mut specs = Vec::new();
    for width in shrink_sizes_including_full(prefix.len()) {
        for start in block_starts(prefix.len(), width) {
            let len = width.min(prefix.len() - start);
            if len == 0 || prefix[start..start + len].iter().all(|byte| *byte == 0) {
                continue;
            }
            specs.push(ReductionSpec {
                op: ReductionOp::zero_range(start, len),
                bias: 0,
            });
        }
    }
    specs.sort_by_key(|spec| {
        (
            spec_pressure(pressure, spec),
            std::cmp::Reverse(spec.simplification()),
            spec.start(),
        )
    });
    specs
}

fn word_lower_specs(
    prefix: &[u8],
    draws: &[DrawSpan],
    pressure: &[u16],
    options: CautiousOptions,
) -> Vec<ReductionSpec> {
    let mut specs = Vec::new();
    for width in [8, 4, 2] {
        if prefix.len() < width {
            continue;
        }

        let mut starts = Vec::new();
        for draw in draws.iter().take(options.draw_limit()) {
            if valid_draw(prefix, draw) && draw.len() >= width && !starts.contains(&draw.start) {
                starts.push(draw.start);
            }
        }
        for start in (0..=prefix.len() - width).step_by(width) {
            if !starts.contains(&start) {
                starts.push(start);
            }
        }

        for start in starts {
            if start + width > prefix.len() {
                continue;
            }
            let current = read_le_word(&prefix[start..start + width]);
            for target in smaller_word_targets(current, width) {
                specs.push(ReductionSpec {
                    op: ReductionOp::set_word(start, width, target, None),
                    bias: 0,
                });
            }
        }
    }
    specs.sort_by_key(|spec| {
        (
            spec_pressure(pressure, spec),
            spec.len(),
            spec.start(),
            spec.target(),
        )
    });
    specs
}

fn byte_lower_specs(prefix: &[u8], pressure: &[u16]) -> Vec<ReductionSpec> {
    let mut specs = Vec::new();
    for (start, byte) in prefix.iter().copied().enumerate() {
        for value in smaller_byte_targets(byte) {
            specs.push(ReductionSpec {
                op: ReductionOp::set_byte(start, value),
                bias: 0,
            });
        }
    }
    specs.sort_by_key(|spec| (spec_pressure(pressure, spec), spec.start(), spec.target()));
    specs
}

fn repeated_value_specs(prefix: &[u8]) -> Vec<ReductionSpec> {
    let mut values = Vec::new();
    for byte in prefix {
        if *byte != 0 && !values.contains(byte) {
            values.push(*byte);
        }
    }
    values.sort_unstable_by_key(|value| {
        std::cmp::Reverse(prefix.iter().filter(|byte| *byte == value).count())
    });

    values
        .into_iter()
        .map(|value| ReductionSpec {
            op: ReductionOp::zero_repeated(value),
            bias: 0,
        })
        .collect()
}

fn dictionary_repair_specs(
    prefix: &[u8],
    dictionary: &[Vec<u8>],
    pressure: &[u16],
) -> Vec<ReductionSpec> {
    if prefix.is_empty() || dictionary.is_empty() {
        return Vec::new();
    }

    let mut specs = Vec::new();
    for (dictionary_index, value) in dictionary.iter().enumerate() {
        if value.is_empty() || value.len() > prefix.len() {
            continue;
        }
        for start in 0..=prefix.len() - value.len() {
            let current = &prefix[start..start + value.len()];
            if current == value || !replacement_simplifies(current, value) {
                continue;
            }
            specs.push(ReductionSpec {
                op: ReductionOp::replace_dictionary(start, value.len(), dictionary_index),
                bias: 0,
            });
        }
    }
    specs.sort_by_key(|spec| {
        (
            spec_pressure(pressure, spec),
            spec.start(),
            spec.len(),
            spec.target(),
        )
    });
    specs
}

fn prefix_fingerprint(prefix: &[u8]) -> PrefixFingerprint {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in prefix {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    PrefixFingerprint {
        len: prefix.len(),
        hash,
    }
}

fn range_weight(pressure: &[u16], start: usize, len: usize) -> u64 {
    if len == 0 || start >= pressure.len() {
        return 0;
    }
    let end = start.saturating_add(len).min(pressure.len());
    let sum = pressure[start..end]
        .iter()
        .fold(0_u64, |sum, value| sum + u64::from(*value));
    sum / (end - start) as u64
}

fn block_starts(len: usize, width: usize) -> Vec<usize> {
    let mut starts = Vec::new();
    if len == 0 || width == 0 {
        return starts;
    }

    let mut start = 0;
    while start < len {
        push_start(&mut starts, len, start);
        start = start.saturating_add(width);
    }

    if width > 1 {
        let mut start = width / 2;
        while start < len {
            push_start(&mut starts, len, start);
            start = start.saturating_add(width);
        }
    }

    push_start(&mut starts, len, 1);
    push_start(&mut starts, len, len / 2);
    push_start(&mut starts, len, len.saturating_sub(width));
    starts
}

fn push_start(starts: &mut Vec<usize>, len: usize, start: usize) {
    if start >= len || starts.contains(&start) {
        return;
    }
    starts.push(start);
}

fn valid_range(prefix: &[u8], range: &Range<usize>) -> bool {
    range.start < range.end && range.end <= prefix.len()
}

fn valid_draw(prefix: &[u8], draw: &DrawSpan) -> bool {
    !draw.is_empty() && draw.end <= prefix.len()
}

fn valid_scalar(prefix: &[u8], scalar: &ScalarSpan) -> bool {
    !scalar.is_empty() && scalar.end <= prefix.len() && scalar.len() <= 16
}

fn read_scalar_rank(prefix: &[u8], scalar: &ScalarSpan) -> u128 {
    let raw = read_le_u128(&prefix[scalar.start..scalar.end]);
    if scalar.span == 0 {
        raw
    } else {
        raw % scalar.span
    }
}

fn draw_widths(draw: &DrawSpan) -> Vec<usize> {
    let mut widths = Vec::new();
    let len = draw.len();
    for width in [len.min(8), 4, 2, 1] {
        if width > 0 && width <= len && !widths.contains(&width) {
            widths.push(width);
        }
    }
    widths
}

fn shrink_sizes_including_full(len: usize) -> Vec<usize> {
    let mut sizes = shrink_sizes(len);
    if len > 0 && !sizes.contains(&len) {
        sizes.insert(0, len);
    }
    sizes
}

fn shrink_sizes(len: usize) -> Vec<usize> {
    let mut sizes = Vec::new();
    for size in [
        len / 2,
        len / 4,
        len / 8,
        1024,
        512,
        256,
        128,
        64,
        32,
        16,
        8,
        4,
        3,
        2,
        1,
    ] {
        if size > 0 && size < len && !sizes.contains(&size) {
            sizes.push(size);
        }
    }
    sizes
}

fn scalar_targets(scalar: &ScalarSpan, current: u128) -> Vec<u128> {
    let mut targets = Vec::new();
    for target in scalar_base_targets().into_iter().chain([
        current / 2,
        current / 4,
        current.saturating_sub(1),
    ]) {
        if target != current && scalar_target_allowed(scalar, target) && !targets.contains(&target)
        {
            targets.push(target);
        }
    }
    targets
}

fn scalar_group_targets(scalar: &ScalarSpan, current: u128) -> Vec<(u128, u64)> {
    let mut targets = Vec::new();
    for target in scalar_group_base_targets().into_iter().chain([
        current / 2,
        current / 4,
        current.saturating_sub(1),
    ]) {
        if target != current
            && scalar_target_allowed(scalar, target)
            && !targets
                .iter()
                .any(|(existing, _): &(u128, u64)| *existing == target)
        {
            let priority = targets.len().min(u64::MAX as usize) as u64;
            targets.push((target, priority));
        }
    }
    targets
}

fn scalar_base_targets() -> Vec<u128> {
    (0..=16)
        .chain([31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1023, 1024])
        .collect()
}

fn scalar_group_base_targets() -> Vec<u128> {
    [
        9, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 31, 32, 63, 64, 127, 128, 255,
        256, 511, 512, 1023, 1024,
    ]
    .into_iter()
    .collect()
}

fn scalar_target_allowed(scalar: &ScalarSpan, target: u128) -> bool {
    (scalar.span == 0 || target < scalar.span) && target_fits_width(target, scalar.len())
}

fn target_fits_width(target: u128, width: usize) -> bool {
    width >= 16 || target < (1_u128 << (width * 8))
}

fn target_key(target: u128) -> u64 {
    target.min(u64::MAX as u128) as u64
}

fn small_length_targets(word: u64, width: usize) -> Vec<u64> {
    let max = max_word_value(width);
    let mut targets = Vec::new();
    for target in (0..=16).chain([31, 32, 63, 64, 127, 128, 255]) {
        if target <= max && target <= word && !targets.contains(&target) {
            targets.push(target);
        }
    }
    for target in [word / 2, word / 4, word.saturating_sub(1)] {
        if target < word && target <= max && !targets.contains(&target) {
            targets.push(target);
        }
    }
    targets
}

fn max_word_value(width: usize) -> u64 {
    match width {
        0 => 0,
        1 => u8::MAX as u64,
        2 => u16::MAX as u64,
        3 | 4 => u32::MAX as u64,
        _ => u64::MAX,
    }
}

fn read_le_word(bytes: &[u8]) -> u64 {
    let mut word = 0_u64;
    for (index, byte) in bytes.iter().enumerate() {
        word |= (*byte as u64) << (index * 8);
    }
    word
}

fn read_le_u128(bytes: &[u8]) -> u128 {
    let mut word = 0_u128;
    for (index, byte) in bytes.iter().take(16).enumerate() {
        word |= (*byte as u128) << (index * 8);
    }
    word
}

fn smaller_word_targets(word: u64, width: usize) -> Vec<u64> {
    if word == 0 {
        return Vec::new();
    }

    let max = max_word_value(width);
    let mut targets = Vec::new();
    for value in (0..=32)
        .chain([63, 64, 127, 128, 255, 256, 511, 512, 1023, 1024])
        .chain([
            word / 2,
            word / 4,
            word.saturating_sub(1),
            word.saturating_sub(2),
            word.saturating_sub(4),
            word.saturating_sub(8),
            word.saturating_sub(16),
            word.saturating_sub(32),
            word.saturating_sub(64),
        ])
    {
        if value < word && value <= max && !targets.contains(&value) {
            targets.push(value);
        }
    }
    targets
}

fn smaller_byte_targets(byte: u8) -> Vec<u8> {
    if byte == 0 {
        return Vec::new();
    }

    let mut targets = Vec::new();
    for value in [
        0,
        1,
        2,
        3,
        4,
        8,
        16,
        32,
        64,
        128,
        byte / 2,
        byte.saturating_sub(1),
        byte.saturating_sub(2),
        byte.saturating_sub(4),
        byte.saturating_sub(8),
        byte.saturating_sub(16),
    ] {
        if value < byte && !targets.contains(&value) {
            targets.push(value);
        }
    }
    targets
}

fn replacement_simplifies(current: &[u8], value: &[u8]) -> bool {
    let current_nonzero = current.iter().filter(|byte| **byte != 0).count();
    let value_nonzero = value.iter().filter(|byte| **byte != 0).count();
    (value_nonzero, value) < (current_nonzero, current)
}

fn truncate_specs(specs: &mut Vec<ReductionSpec>, limit: usize) {
    if specs.len() > limit {
        specs.truncate(limit);
    }
}

pub(super) fn prune_corpus(state: &mut StateCore, prune_by_worst_score: bool) -> bool {
    if state.corpus.len() <= MAX_CORPUS_LEN {
        return false;
    }

    let remove = if prune_by_worst_score {
        state
            .corpus
            .iter()
            .enumerate()
            .max_by_key(|(_, entry)| {
                MinPathScore::with_case_cost(
                    entry.case_cost,
                    entry.score,
                    entry.hit_count_weight,
                    entry.path_len,
                    entry.nonzero_bytes,
                )
            })
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
        return true;
    }

    false
}

pub(super) fn refresh_min_path_best(state: &mut StateCore) {
    let best = state
        .corpus
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            (
                index,
                MinPathScore::with_case_cost(
                    entry.case_cost,
                    entry.score,
                    entry.hit_count_weight,
                    entry.path_len,
                    entry.nonzero_bytes,
                ),
            )
        })
        .min_by(|(left_index, left_score), (right_index, right_score)| {
            left_score.cmp(right_score).then_with(|| {
                let left = &state.corpus[*left_index];
                let right = &state.corpus[*right_index];
                (left.draws.len(), left.prefix.as_slice())
                    .cmp(&(right.draws.len(), right.prefix.as_slice()))
            })
        });
    state.min_path_best = best.map(|(_, score)| score);
    state.min_path_best_index = best.map(|(index, _)| index);
}
