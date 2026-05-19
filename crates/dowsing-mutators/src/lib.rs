mod add_byte;
mod copy_part;
mod delete_range;
mod delete_sequence_items;
mod drain_prefix;
mod fill_range;
mod insert_bytes;
mod insert_dictionary;
mod insert_repeated_bytes;
mod min_byte;
mod project_sequence_items;
mod replace_bytes;
mod replace_dictionary;
mod set_byte;
mod set_word;
mod shuffle_bytes;
mod sub_byte;
mod truncate;
mod xor_bit;
mod zero_range;
mod zero_repeated;

pub mod havoc;

use add_byte::AddByte;
use copy_part::{CopyPart, CopyPartMode};
use delete_range::{DeleteRange, FirstByteAdjustment};
use delete_sequence_items::DeleteSequenceItems;
use dowsing_core::{BuiltInMutationSource, MutationSource, ReductionOp, RngTraceMutation};
use dowsing_rng::{ByteAffinity, Trace, TraceEvent, TraceNode};
use drain_prefix::DrainPrefix;
use fill_range::FillRange;
use insert_bytes::InsertBytes;
use insert_dictionary::InsertDictionary;
use insert_repeated_bytes::InsertRepeatedBytes;
use min_byte::MinByte;
use project_sequence_items::ProjectSequenceItems;
use replace_bytes::ReplaceBytes;
use replace_dictionary::{ReplaceDictionary, ReplaceMode};
use set_byte::SetByte;
use set_word::SetWord;
use shuffle_bytes::ShuffleBytes;
use std::ops::Range;
use sub_byte::SubByte;
use truncate::Truncate;
use xor_bit::XorBit;
use zero_range::ZeroRange;
use zero_repeated::ZeroRepeated;

pub use havoc::{havoc_trace, mutate_trace, test_dictionary_mutation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WordEndian {
    Little,
    Big,
}

/// Built-in mutation source constructors.
pub mod mutations {
    use super::{BuiltInMutationSource, MutationSource};

    /// Random exploratory mutations suitable for coverage discovery.
    pub fn coverage_havoc() -> MutationSource {
        MutationSource::built_in(BuiltInMutationSource::CoverageHavoc)
    }

    /// Random simplifying mutations suitable for minimization fallback.
    pub fn minimizing_havoc() -> MutationSource {
        MutationSource::built_in(BuiltInMutationSource::MinimizingHavoc)
    }

    /// Deterministic semantic reductions over ranges, scalars, draws, and byte spans.
    pub fn semantic_reductions() -> MutationSource {
        MutationSource::built_in(BuiltInMutationSource::SemanticReductions)
    }
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

impl RngTraceMutation for SetScalarRanks {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        if self.writes.is_empty() {
            return false;
        }
        let prefix_len = trace.flatten_prefix().len();
        for write in &self.writes {
            if write.width == 0
                || write.width > 16
                || write.start.saturating_add(write.width) > prefix_len
            {
                return false;
            }
        }
        edit_all_trace_bytes(trace, |prefix| {
            for write in &self.writes {
                write_le_u128(
                    &mut prefix[write.start..write.start + write.width],
                    write.value,
                );
            }
        })
    }
}

/// Deterministic reduction operation constructors.
pub mod reductions {
    use super::*;

    /// Replace a little-endian word with `target`.
    pub fn set_word(
        start: usize,
        width: usize,
        target: u64,
        zero_until: Option<usize>,
    ) -> ReductionOp {
        ReductionOp::trace(
            start,
            width,
            target,
            width,
            SetWord {
                start,
                width,
                value: target,
                endian: WordEndian::Little,
                zero_until,
            },
        )
    }

    /// Replace one or more scalar rank byte spans.
    pub fn set_scalar_ranks(writes: Vec<(usize, usize, u128)>, target: u64) -> ReductionOp {
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
        ReductionOp::trace(
            start,
            end.saturating_sub(start),
            target,
            simplification,
            SetScalarRanks { writes },
        )
    }

    /// Delete a span from flattened trace bytes.
    pub fn delete_range(start: usize, len: usize, adjust_first: bool) -> ReductionOp {
        ReductionOp::trace(
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

    /// Zero a span in flattened trace bytes.
    pub fn zero_range(start: usize, len: usize) -> ReductionOp {
        ReductionOp::trace(start, len, 0, len, ZeroRange { start, len })
    }

    /// Set one byte.
    pub fn set_byte(start: usize, value: u8) -> ReductionOp {
        ReductionOp::trace(
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

    /// Zero repeated occurrences of `value`.
    pub fn zero_repeated(value: u8) -> ReductionOp {
        ReductionOp::trace(0, 0, value as u64, 1, ZeroRepeated { value })
    }

    /// Replace a span in flattened trace bytes with a dictionary value.
    pub fn replace_dictionary(start: usize, len: usize, dictionary_index: usize) -> ReductionOp {
        ReductionOp::trace(
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

    /// Delete items from a structured sequence trace.
    pub fn delete_sequence_items(
        length_start: usize,
        length_width: usize,
        target_len: usize,
        start: usize,
        len: usize,
    ) -> ReductionOp {
        ReductionOp::trace(
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

    /// Project selected items from a structured sequence trace.
    pub fn project_sequence_items(
        length_start: usize,
        length_width: usize,
        target_len: usize,
        replace_start: usize,
        replace_len: usize,
        items: Vec<(usize, usize)>,
    ) -> ReductionOp {
        let replacement_len = items.iter().map(|(_, len)| *len).sum::<usize>();
        ReductionOp::trace(
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
}

pub fn set_byte(index: usize, value: u8) -> Box<dyn RngTraceMutation> {
    Box::new(SetByte { index, value })
}

pub fn xor_bit(index: usize, bit: u8) -> Box<dyn RngTraceMutation> {
    Box::new(XorBit { index, bit })
}

pub fn add_byte(index: usize, amount: u8) -> Box<dyn RngTraceMutation> {
    Box::new(AddByte { index, amount })
}

pub fn sub_byte(index: usize, amount: u8) -> Box<dyn RngTraceMutation> {
    Box::new(SubByte { index, amount })
}

pub fn min_byte(index: usize, value: u8) -> Box<dyn RngTraceMutation> {
    Box::new(MinByte { index, value })
}

pub fn insert_bytes(index: usize, bytes: Vec<u8>) -> Box<dyn RngTraceMutation> {
    Box::new(InsertBytes { index, bytes })
}

pub fn insert_repeated_bytes(index: usize, byte: u8, len: usize) -> Box<dyn RngTraceMutation> {
    Box::new(InsertRepeatedBytes { index, byte, len })
}

pub fn insert_dictionary(index: usize, dictionary_index: usize) -> Box<dyn RngTraceMutation> {
    Box::new(InsertDictionary {
        index,
        dictionary_index,
    })
}

pub fn replace_dictionary(
    start: usize,
    len: usize,
    dictionary_index: usize,
) -> Box<dyn RngTraceMutation> {
    Box::new(ReplaceDictionary {
        start,
        len,
        dictionary_index,
        mode: ReplaceMode::Splice,
    })
}

pub fn replace_dictionary_exact(
    start: usize,
    len: usize,
    dictionary_index: usize,
) -> Box<dyn RngTraceMutation> {
    Box::new(ReplaceDictionary {
        start,
        len,
        dictionary_index,
        mode: ReplaceMode::Exact,
    })
}

pub fn replace_bytes(start: usize, len: usize, bytes: Vec<u8>) -> Box<dyn RngTraceMutation> {
    Box::new(ReplaceBytes { start, len, bytes })
}

pub fn copy_part(
    source: usize,
    target: usize,
    len: usize,
    insert: bool,
) -> Box<dyn RngTraceMutation> {
    Box::new(CopyPart {
        source,
        target,
        len,
        mode: if insert {
            CopyPartMode::Insert
        } else {
            CopyPartMode::Overwrite
        },
    })
}

pub fn delete_range(
    start: usize,
    len: usize,
    leading_sub: Option<u8>,
) -> Box<dyn RngTraceMutation> {
    Box::new(DeleteRange {
        start,
        len,
        first_byte: leading_sub
            .map(FirstByteAdjustment::ByValue)
            .unwrap_or(FirstByteAdjustment::None),
    })
}

pub fn drain_prefix(keep_from: usize) -> Box<dyn RngTraceMutation> {
    Box::new(DrainPrefix { keep_from })
}

pub fn truncate(len: usize, leading_sub: Option<u8>) -> Box<dyn RngTraceMutation> {
    Box::new(Truncate { len, leading_sub })
}

pub fn fill_range(start: usize, bytes: Vec<u8>) -> Box<dyn RngTraceMutation> {
    Box::new(FillRange { start, bytes })
}

pub fn shuffle_bytes(start: usize, bytes: Vec<u8>) -> Box<dyn RngTraceMutation> {
    Box::new(ShuffleBytes { start, bytes })
}

pub fn set_word(start: usize, width: usize, value: u64) -> Box<dyn RngTraceMutation> {
    set_word_endian(start, width, value, false)
}

pub fn set_word_endian(
    start: usize,
    width: usize,
    value: u64,
    big_endian: bool,
) -> Box<dyn RngTraceMutation> {
    Box::new(SetWord {
        start,
        width,
        value,
        endian: if big_endian {
            WordEndian::Big
        } else {
            WordEndian::Little
        },
        zero_until: None,
    })
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
        true
    } else {
        false
    }
}

fn edit_trace_bytes(
    trace: &mut Trace,
    start: usize,
    len: usize,
    edit: impl FnOnce(&mut [u8]),
) -> bool {
    let mut bytes = trace.flatten_prefix();
    if start.saturating_add(len) > bytes.len() {
        return false;
    }
    edit(&mut bytes[start..start + len]);
    write_trace_bytes(trace, &bytes)
}

fn edit_all_trace_bytes(trace: &mut Trace, edit: impl FnOnce(&mut [u8])) -> bool {
    let mut bytes = trace.flatten_prefix();
    edit(&mut bytes);
    write_trace_bytes(trace, &bytes)
}

fn replace_trace_span(trace: &mut Trace, start: usize, len: usize, replacement: &[u8]) -> bool {
    let trace_len = trace.flatten_prefix().len();
    if start.saturating_add(len) > trace_len {
        return false;
    }
    if trace_len == 0 && start == 0 && len == 0 {
        if replacement.is_empty() {
            return true;
        }
        trace.root.events.push(TraceEvent::Draw {
            bytes: replacement.to_vec(),
            affinity: ByteAffinity::Any,
        });
        return true;
    }

    let mut cursor = 0;
    splice_draw_span_in_node(&mut trace.root, &mut cursor, start, len, replacement)
}

fn splice_draw_span_in_node(
    node: &mut TraceNode,
    cursor: &mut usize,
    start: usize,
    len: usize,
    replacement: &[u8],
) -> bool {
    let end = start.saturating_add(len);
    for event in &mut node.events {
        match event {
            TraceEvent::Draw { bytes, .. } => {
                let event_start = *cursor;
                let event_end = event_start.saturating_add(bytes.len());
                if start >= event_start && end <= event_end {
                    let local_start = start - event_start;
                    let local_end = local_start + len;
                    bytes.splice(local_start..local_end, replacement.iter().copied());
                    return true;
                }
                *cursor = event_end;
            }
            TraceEvent::Range { length, children } => {
                *cursor = (*cursor).saturating_add(length.len());
                for child in children {
                    if splice_draw_span_in_node(child, cursor, start, len, replacement) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn write_trace_bytes(trace: &mut Trace, bytes: &[u8]) -> bool {
    if trace.flatten_prefix().len() != bytes.len() {
        return false;
    }
    let mut cursor = 0;
    write_trace_node_bytes(&mut trace.root, bytes, &mut cursor);
    cursor == bytes.len()
}

fn write_trace_node_bytes(node: &mut TraceNode, bytes: &[u8], cursor: &mut usize) {
    for event in &mut node.events {
        match event {
            TraceEvent::Draw { bytes: draw, .. } => {
                let end = (*cursor).saturating_add(draw.len());
                draw.copy_from_slice(&bytes[*cursor..end]);
                *cursor = end;
            }
            TraceEvent::Range { length, children } => {
                let end = (*cursor).saturating_add(length.len());
                length.copy_from_slice(&bytes[*cursor..end]);
                *cursor = end;
                for child in children {
                    write_trace_node_bytes(child, bytes, cursor);
                }
            }
        }
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

fn write_be_word(bytes: &mut [u8], mut word: u64) {
    for byte in bytes.iter_mut().rev() {
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
    use dowsing_core::MutationWeights;
    use dowsing_rng::ByteAffinity;
    use std::any::TypeId;

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
        assert_eq!(weights.multiplier(set_byte), 16.0);

        for _ in 0..256 {
            weights.reward_many(&[set_byte], 0.90);
        }
        assert_eq!(weights.multiplier(set_byte), 0.10);
    }

    #[test]
    fn byte_mutators_cover_repeated_shuffle_copy_replace_and_endian_word() {
        let mut prefix = vec![1, 2];
        assert!(apply_to_prefix(
            insert_repeated_bytes(1, 255, 4),
            &mut prefix,
            &[]
        ));
        assert_eq!(prefix, [1, 255, 255, 255, 255, 2]);

        let mut prefix = vec![1, 2, 3, 4];
        assert!(apply_to_prefix(
            shuffle_bytes(1, vec![3, 2]),
            &mut prefix,
            &[]
        ));
        assert_eq!(prefix, [1, 3, 2, 4]);

        let mut prefix = vec![1, 2, 3];
        assert!(apply_to_prefix(copy_part(0, 3, 2, true), &mut prefix, &[]));
        assert_eq!(prefix, [1, 2, 3, 1, 2]);

        let mut prefix = vec![1, 2, 3, 4];
        assert!(apply_to_prefix(copy_part(0, 2, 2, false), &mut prefix, &[]));
        assert_eq!(prefix, [1, 2, 1, 2]);

        let mut prefix = vec![1, 2, 3, 4];
        assert!(apply_to_prefix(
            replace_bytes(1, 2, vec![9]),
            &mut prefix,
            &[]
        ));
        assert_eq!(prefix, [1, 9, 4]);

        let mut prefix = vec![0, 0, 0, 0];
        assert!(apply_to_prefix(
            set_word_endian(1, 2, 0x1234, true),
            &mut prefix,
            &[]
        ));
        assert_eq!(prefix, [0, 0x12, 0x34, 0]);

        let mut prefix = vec![0, 0, 0];
        assert!(apply_to_prefix(
            replace_dictionary_exact(1, 2, 0),
            &mut prefix,
            &[vec![7, 8]]
        ));
        assert_eq!(prefix, [0, 7, 8]);
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

        assert!(mutation.apply_trace(&mut trace, &[]));
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

        assert!(mutation.apply_trace(&mut trace, &[]));
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

        assert!(mutation.apply_trace(&mut trace, &[]));
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
        };
        let mutation = DeleteSequenceItems {
            length_start: 4,
            length_width: 4,
            target_len: 0,
            start: 8,
            len: 3,
        };

        assert!(mutation.apply_trace(&mut trace, &[]));
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

    fn apply_to_prefix(
        mutation: Box<dyn RngTraceMutation>,
        prefix: &mut Vec<u8>,
        dictionary: &[Vec<u8>],
    ) -> bool {
        let mut trace = Trace {
            seed: 0,
            root: TraceNode {
                events: if prefix.is_empty() {
                    Vec::new()
                } else {
                    vec![TraceEvent::Draw {
                        bytes: prefix.clone(),
                        affinity: ByteAffinity::Any,
                    }]
                },
            },
        };
        if !mutation.apply_trace(&mut trace, dictionary) {
            return false;
        }
        *prefix = trace.flatten_prefix();
        true
    }
}
