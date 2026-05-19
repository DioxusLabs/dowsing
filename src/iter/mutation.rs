mod add_byte;
mod delete_range;
mod delete_sequence_items;
mod drain_prefix;
mod fill_range;
mod insert_bytes;
mod insert_dictionary;
mod min_byte;
mod project_sequence_items;
mod replace_dictionary;
mod set_byte;
mod set_word;
mod sub_byte;
mod truncate;
mod xor_bit;
mod zero_range;
mod zero_repeated;

use add_byte::AddByte;
use delete_range::{DeleteRange, FirstByteAdjustment};
use delete_sequence_items::DeleteSequenceItems;
use dowsing_rng::{Trace, TraceEvent, TraceNode};
use drain_prefix::DrainPrefix;
use fill_range::FillRange;
use insert_bytes::InsertBytes;
use insert_dictionary::InsertDictionary;
use min_byte::MinByte;
use project_sequence_items::ProjectSequenceItems;
use replace_dictionary::{ReplaceDictionary, ReplaceMode};
use rustc_hash::FxHashMap;
use set_byte::SetByte;
use set_word::SetWord;
use std::{
    any::{Any, TypeId},
    fmt,
    ops::Range,
};
use sub_byte::SubByte;
use truncate::Truncate;
use xor_bit::XorBit;
use zero_range::ZeroRange;
use zero_repeated::ZeroRepeated;

pub(super) trait RngByteMutation: fmt::Debug + RngByteMutationClone + Send + Any {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, dictionary: &[Vec<u8>]) -> bool;
}

pub(super) trait RngByteMutationClone {
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

pub(super) trait RngTreeMutation: RngByteMutation + RngTreeMutationClone + Send {
    fn apply_tree(&self, trace: &mut Trace, dictionary: &[Vec<u8>]) -> bool;
}

pub(super) trait RngTreeMutationClone {
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

#[derive(Debug, Clone)]
pub(super) struct MutationWeights {
    multipliers: FxHashMap<TypeId, f64>,
}

impl Default for MutationWeights {
    fn default() -> Self {
        Self {
            multipliers: FxHashMap::default(),
        }
    }
}

impl MutationWeights {
    pub(super) fn multiplier(&self, mutation_id: TypeId) -> f64 {
        *self.multipliers.get(&mutation_id).unwrap_or(&1.0)
    }

    pub(super) fn selection_weight(&self, mutation_id: TypeId, baseline: f64) -> f64 {
        let weight = baseline * self.multiplier(mutation_id);
        if weight.is_finite() && weight > 0.0 {
            weight
        } else {
            baseline.max(1.0)
        }
    }

    pub(super) fn priority_key(&self, mutation_id: TypeId) -> u64 {
        (self.multiplier(mutation_id) * MUTATION_WEIGHT_PRIORITY_SCALE).round() as u64
    }

    pub(super) fn reward_many(&mut self, mutation_ids: &[TypeId], factor: f64) {
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

    #[cfg(test)]
    pub(super) fn set_for_test(&mut self, mutation_id: TypeId, multiplier: f64) {
        self.multipliers.insert(
            mutation_id,
            multiplier.clamp(MIN_MUTATION_WEIGHT, MAX_MUTATION_WEIGHT),
        );
    }
}

#[derive(Debug, Clone)]
pub(super) struct ReductionOp {
    start: usize,
    len: usize,
    target: u64,
    simplification: usize,
    pub(super) type_id: TypeId,
    mutator: Box<dyn RngReductionMutation>,
}

pub(super) trait RngReductionMutation:
    fmt::Debug + RngReductionMutationClone + Send
{
    fn materialize(
        &self,
        seed: u64,
        base_case: &Trace,
        base_prefix: &[u8],
        dictionary: &[Vec<u8>],
    ) -> Option<(Trace, Vec<u8>)>;
}

pub(super) trait RngReductionMutationClone {
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

#[derive(Debug, Clone)]
struct ScalarRankWrite {
    start: usize,
    width: usize,
    value: u128,
}

#[derive(Debug, Clone)]
struct SetScalarRanks {
    writes: Vec<ScalarRankWrite>,
}

impl RngReductionMutation for ByteReductionMutation {
    fn materialize(
        &self,
        seed: u64,
        _base_case: &Trace,
        base_prefix: &[u8],
        dictionary: &[Vec<u8>],
    ) -> Option<(Trace, Vec<u8>)> {
        materialize_bytes(seed, base_prefix, dictionary, self.mutator.as_ref())
    }
}

impl RngReductionMutation for TreeReductionMutation {
    fn materialize(
        &self,
        seed: u64,
        base_case: &Trace,
        base_prefix: &[u8],
        dictionary: &[Vec<u8>],
    ) -> Option<(Trace, Vec<u8>)> {
        let mut case = base_case.clone();
        if self.mutator.apply_tree(&mut case, dictionary) {
            let prefix = case.flatten_prefix();
            Some((case, prefix))
        } else {
            materialize_bytes(seed, base_prefix, dictionary, self.mutator.as_ref())
        }
    }
}

impl RngByteMutation for SetScalarRanks {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        if self.writes.is_empty() {
            return false;
        }
        for write in &self.writes {
            if write.width == 0
                || write.width > 16
                || write.start.saturating_add(write.width) > prefix.len()
            {
                return false;
            }
        }
        for write in &self.writes {
            write_le_u128(
                &mut prefix[write.start..write.start + write.width],
                write.value,
            );
        }
        true
    }
}

impl ReductionOp {
    fn byte<Mutation>(
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

    fn tree<Mutation>(
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

    pub(super) fn set_word(
        start: usize,
        width: usize,
        target: u64,
        zero_until: Option<usize>,
    ) -> Self {
        Self::byte(
            start,
            width,
            target,
            width,
            SetWord {
                start,
                width,
                value: target,
                zero_until,
            },
        )
    }

    pub(super) fn set_scalar_ranks(writes: Vec<(usize, usize, u128)>, target: u64) -> Self {
        let mut start = usize::MAX;
        let mut end = 0_usize;
        let mut simplification = 0_usize;
        let writes: Vec<_> = writes
            .into_iter()
            .map(|(write_start, width, value)| {
                start = start.min(write_start);
                end = end.max(write_start.saturating_add(width));
                simplification = simplification.saturating_add(width);
                ScalarRankWrite {
                    start: write_start,
                    width,
                    value,
                }
            })
            .collect();
        Self::byte(
            start,
            end.saturating_sub(start),
            target,
            simplification,
            SetScalarRanks { writes },
        )
    }

    pub(super) fn delete_range(start: usize, len: usize, adjust_first: bool) -> Self {
        Self::byte(
            start,
            len,
            0,
            len,
            DeleteRange {
                start,
                len,
                first_byte: if adjust_first {
                    FirstByteAdjustment::ByDeletedLen
                } else {
                    FirstByteAdjustment::None
                },
            },
        )
    }

    pub(super) fn zero_range(start: usize, len: usize) -> Self {
        Self::byte(start, len, 0, len, ZeroRange { start, len })
    }

    pub(super) fn set_byte(start: usize, value: u8) -> Self {
        Self::byte(
            start,
            1,
            value as u64,
            1,
            SetByte {
                index: start,
                value,
            },
        )
    }

    pub(super) fn zero_repeated(value: u8) -> Self {
        Self::byte(0, 0, value as u64, 1, ZeroRepeated { value })
    }

    pub(super) fn replace_dictionary(start: usize, len: usize, dictionary_index: usize) -> Self {
        Self::byte(
            start,
            len,
            dictionary_index as u64,
            len,
            ReplaceDictionary {
                start,
                len,
                dictionary_index,
                mode: ReplaceMode::Exact,
            },
        )
    }

    pub(super) fn delete_sequence_items(
        length_start: usize,
        length_width: usize,
        target_len: usize,
        start: usize,
        len: usize,
    ) -> Self {
        Self::tree(
            start,
            len,
            target_len as u64,
            len,
            DeleteSequenceItems {
                length_start,
                length_width,
                target_len,
                start,
                len,
            },
        )
    }

    pub(super) fn project_sequence_items(
        length_start: usize,
        length_width: usize,
        target_len: usize,
        replace_start: usize,
        replace_len: usize,
        items: Vec<(usize, usize)>,
    ) -> Self {
        let replacement_len = items.iter().map(|(_, len)| *len).sum::<usize>();
        Self::tree(
            replace_start,
            replace_len,
            target_len as u64,
            replace_len.saturating_sub(replacement_len),
            ProjectSequenceItems {
                length_start,
                length_width,
                target_len,
                replace_start,
                replace_len,
                items,
            },
        )
    }

    pub(super) fn start(&self) -> usize {
        self.start
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn target(&self) -> u64 {
        self.target
    }

    pub(super) fn simplification(&self) -> usize {
        self.simplification
    }

    pub(super) fn materialize(
        &self,
        seed: u64,
        base_case: &Trace,
        base_prefix: &[u8],
        dictionary: &[Vec<u8>],
    ) -> Option<(Trace, Vec<u8>)> {
        self.mutator
            .materialize(seed, base_case, base_prefix, dictionary)
    }
}

pub(super) fn set_byte(index: usize, value: u8) -> Box<dyn RngByteMutation> {
    Box::new(SetByte { index, value })
}

pub(super) fn xor_bit(index: usize, bit: u8) -> Box<dyn RngByteMutation> {
    Box::new(XorBit { index, bit })
}

pub(super) fn add_byte(index: usize, amount: u8) -> Box<dyn RngByteMutation> {
    Box::new(AddByte { index, amount })
}

pub(super) fn sub_byte(index: usize, amount: u8) -> Box<dyn RngByteMutation> {
    Box::new(SubByte { index, amount })
}

pub(super) fn min_byte(index: usize, value: u8) -> Box<dyn RngByteMutation> {
    Box::new(MinByte { index, value })
}

pub(super) fn insert_bytes(index: usize, bytes: Vec<u8>) -> Box<dyn RngByteMutation> {
    Box::new(InsertBytes { index, bytes })
}

pub(super) fn insert_dictionary(index: usize, dictionary_index: usize) -> Box<dyn RngByteMutation> {
    Box::new(InsertDictionary {
        index,
        dictionary_index,
    })
}

pub(super) fn replace_dictionary(
    start: usize,
    len: usize,
    dictionary_index: usize,
) -> Box<dyn RngByteMutation> {
    Box::new(ReplaceDictionary {
        start,
        len,
        dictionary_index,
        mode: ReplaceMode::Splice,
    })
}

pub(super) fn delete_range(
    start: usize,
    len: usize,
    leading_sub: Option<u8>,
) -> Box<dyn RngByteMutation> {
    Box::new(DeleteRange {
        start,
        len,
        first_byte: leading_sub
            .map(FirstByteAdjustment::ByValue)
            .unwrap_or(FirstByteAdjustment::None),
    })
}

pub(super) fn drain_prefix(keep_from: usize) -> Box<dyn RngByteMutation> {
    Box::new(DrainPrefix { keep_from })
}

pub(super) fn truncate(len: usize, leading_sub: Option<u8>) -> Box<dyn RngByteMutation> {
    Box::new(Truncate { len, leading_sub })
}

pub(super) fn fill_range(start: usize, bytes: Vec<u8>) -> Box<dyn RngByteMutation> {
    Box::new(FillRange { start, bytes })
}

pub(super) fn set_word(start: usize, width: usize, value: u64) -> Box<dyn RngByteMutation> {
    Box::new(SetWord {
        start,
        width,
        value,
        zero_until: None,
    })
}

fn materialize_bytes(
    seed: u64,
    base_prefix: &[u8],
    dictionary: &[Vec<u8>],
    mutation: &dyn RngByteMutation,
) -> Option<(Trace, Vec<u8>)> {
    let mut prefix = base_prefix.to_vec();
    if !mutation.apply_bytes(&mut prefix, dictionary) {
        return None;
    }
    Some((Trace::from_flat_prefix(seed, prefix.clone()), prefix))
}

fn apply_to_sequence_range(
    trace: &mut Trace,
    length_start: usize,
    length_width: usize,
    mut mutate: impl FnMut(&mut [u8], &mut Vec<TraceNode>, usize) -> bool,
) -> bool {
    let mut cursor = 0;
    if apply_to_sequence_range_in_node(
        &mut trace.root,
        &mut cursor,
        length_start,
        length_width,
        &mut mutate,
    ) {
        trace.flat = None;
        true
    } else {
        false
    }
}

fn apply_to_sequence_range_in_node(
    node: &mut TraceNode,
    cursor: &mut usize,
    length_start: usize,
    length_width: usize,
    mutate: &mut impl FnMut(&mut [u8], &mut Vec<TraceNode>, usize) -> bool,
) -> bool {
    for event in &mut node.events {
        match event {
            TraceEvent::Draw { bytes, .. } => {
                *cursor = (*cursor).saturating_add(bytes.len());
            }
            TraceEvent::Range { length, children } => {
                let event_length_start = *cursor;
                *cursor = (*cursor).saturating_add(length.len());
                if event_length_start == length_start
                    && length.len() == length_width
                    && mutate(length, children, *cursor)
                {
                    return true;
                }
                for child in children {
                    if apply_to_sequence_range_in_node(
                        child,
                        cursor,
                        length_start,
                        length_width,
                        mutate,
                    ) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn child_spans(children: &[TraceNode], mut cursor: usize) -> Vec<Range<usize>> {
    let mut spans = Vec::with_capacity(children.len());
    for child in children {
        let start = cursor;
        cursor = cursor.saturating_add(flatten_len(child));
        spans.push(start..cursor);
    }
    spans
}

fn flatten_len(node: &TraceNode) -> usize {
    let mut len = 0_usize;
    for event in &node.events {
        match event {
            TraceEvent::Draw { bytes, .. } => {
                len = len.saturating_add(bytes.len());
            }
            TraceEvent::Range { length, children } => {
                len = len.saturating_add(length.len());
                for child in children {
                    len = len.saturating_add(flatten_len(child));
                }
            }
        }
    }
    len
}

fn nonempty_extent(spans: &[Range<usize>]) -> Option<Range<usize>> {
    let mut nonempty = spans.iter().filter(|span| !span.is_empty());
    let first = nonempty.next()?;
    let mut end = first.end;
    for span in nonempty {
        end = span.end;
    }
    Some(first.start..end)
}

fn write_le_word(bytes: &mut [u8], mut word: u64) {
    for byte in bytes {
        *byte = word as u8;
        word >>= 8;
    }
}

fn write_le_u128(bytes: &mut [u8], mut word: u128) {
    for byte in bytes {
        *byte = word as u8;
        word >>= 8;
    }
}

fn shrink_first_by(prefix: &mut [u8], amount: usize) {
    let Some(first) = prefix.first_mut() else {
        return;
    };
    *first = first.saturating_sub(amount.min(u8::MAX as usize) as u8);
}

fn subtract_first(prefix: &mut [u8], amount: u8) {
    let Some(first) = prefix.first_mut() else {
        return;
    };
    *first = first.saturating_sub(amount);
}

#[cfg(test)]
mod tests {
    use super::*;
    use dowsing_rng::ByteAffinity;

    #[test]
    fn mutation_weights_reward_penalty_split_credit_and_clamp() {
        let mut weights = MutationWeights::default();
        let set_byte = TypeId::of::<SetByte>();
        let insert_bytes = TypeId::of::<InsertBytes>();

        weights.reward_many(&[set_byte], 1.25);
        assert!((weights.multiplier(set_byte) - 1.25).abs() < f64::EPSILON);

        weights.reward_many(&[set_byte, insert_bytes], 1.21);
        let split = 1.21_f64.sqrt();
        assert!((weights.multiplier(set_byte) - 1.25 * split).abs() < 1e-12);
        assert!((weights.multiplier(insert_bytes) - split).abs() < 1e-12);

        for _ in 0..128 {
            weights.reward_many(&[set_byte], 1.25);
        }
        assert_eq!(weights.multiplier(set_byte), MAX_MUTATION_WEIGHT);

        for _ in 0..256 {
            weights.reward_many(&[set_byte], 0.90);
        }
        assert_eq!(weights.multiplier(set_byte), MIN_MUTATION_WEIGHT);
    }

    #[test]
    fn tree_delete_sequence_items_updates_length_and_children() {
        let mut trace = range_trace(3, [10, 20, 30]);
        let mutation = DeleteSequenceItems {
            length_start: 0,
            length_width: 4,
            target_len: 0,
            start: 4,
            len: 3,
        };

        assert!(mutation.apply_tree(&mut trace, &[]));
        assert_eq!(trace.flat, None);
        assert_eq!(trace.flatten_prefix(), 0_u32.to_le_bytes());
        assert_range_children(&trace, 0, []);
    }

    #[test]
    fn tree_project_sequence_items_keeps_non_contiguous_children() {
        let mut trace = range_trace(4, [10, 20, 30, 40]);
        let mutation = ProjectSequenceItems {
            length_start: 0,
            length_width: 4,
            target_len: 2,
            replace_start: 4,
            replace_len: 4,
            items: vec![(4, 1), (6, 1)],
        };

        assert!(mutation.apply_tree(&mut trace, &[]));
        let mut expected = 2_u32.to_le_bytes().to_vec();
        expected.extend([10, 30]);
        assert_eq!(trace.flatten_prefix(), expected);
        assert_range_children(&trace, 2, [10, 30]);
    }

    #[test]
    fn tree_project_sequence_items_can_clone_prior_children() {
        let mut trace = range_trace(3, [1, 99, 30]);
        let mutation = ProjectSequenceItems {
            length_start: 0,
            length_width: 4,
            target_len: 3,
            replace_start: 4,
            replace_len: 3,
            items: vec![(4, 1), (4, 1), (6, 1)],
        };

        assert!(mutation.apply_tree(&mut trace, &[]));
        let mut expected = 3_u32.to_le_bytes().to_vec();
        expected.extend([1, 1, 30]);
        assert_eq!(trace.flatten_prefix(), expected);
        assert_range_children(&trace, 3, [1, 1, 30]);
    }

    #[test]
    fn tree_mutation_can_target_nested_ranges() {
        let mut trace = Trace {
            seed: 0,
            root: TraceNode {
                events: vec![TraceEvent::Range {
                    length: 1_u32.to_le_bytes().to_vec(),
                    children: vec![TraceNode {
                        events: vec![TraceEvent::Range {
                            length: 3_u32.to_le_bytes().to_vec(),
                            children: [10, 20, 30].into_iter().map(draw_node).collect(),
                        }],
                    }],
                }],
            },
            flat: None,
        };
        let mutation = DeleteSequenceItems {
            length_start: 4,
            length_width: 4,
            target_len: 0,
            start: 8,
            len: 3,
        };

        assert!(mutation.apply_tree(&mut trace, &[]));
        let mut expected = 1_u32.to_le_bytes().to_vec();
        expected.extend(0_u32.to_le_bytes());
        assert_eq!(trace.flatten_prefix(), expected);
    }

    fn range_trace(len: u32, bytes: impl IntoIterator<Item = u8>) -> Trace {
        Trace {
            seed: 0,
            root: TraceNode {
                events: vec![TraceEvent::Range {
                    length: len.to_le_bytes().to_vec(),
                    children: bytes.into_iter().map(draw_node).collect(),
                }],
            },
            flat: Some(vec![255]),
        }
    }

    fn draw_node(byte: u8) -> TraceNode {
        TraceNode {
            events: vec![TraceEvent::Draw {
                bytes: vec![byte],
                affinity: ByteAffinity::Any,
            }],
        }
    }

    fn assert_range_children<const N: usize>(trace: &Trace, len: u32, bytes: [u8; N]) {
        let Some(TraceEvent::Range { length, children }) = trace.root.events.first() else {
            panic!("expected root range");
        };
        assert_eq!(length, &len.to_le_bytes());
        assert_eq!(children.len(), bytes.len());
        for (child, byte) in children.iter().zip(bytes) {
            assert_eq!(
                child.events,
                [TraceEvent::Draw {
                    bytes: vec![byte],
                    affinity: ByteAffinity::Any,
                }]
            );
        }
    }
}
