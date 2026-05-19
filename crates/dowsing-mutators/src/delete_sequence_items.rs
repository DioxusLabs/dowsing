use super::{
    RngByteMutation, RngTreeMutation, apply_to_sequence_range, child_spans, write_le_word,
};
use dowsing_rng::{Trace, TraceNode};

#[derive(Debug, Clone)]
pub(crate) struct DeleteSequenceItems {
    pub(super) length_start: usize,
    pub(super) length_width: usize,
    pub(super) target_len: usize,
    pub(super) start: usize,
    pub(super) len: usize,
}

impl RngByteMutation for DeleteSequenceItems {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        if self.length_width == 0
            || self.length_start.saturating_add(self.length_width) > prefix.len()
            || self.len == 0
            || self.start.saturating_add(self.len) > prefix.len()
        {
            return false;
        }
        write_le_word(
            &mut prefix[self.length_start..self.length_start + self.length_width],
            self.target_len as u64,
        );
        prefix.drain(self.start..self.start + self.len);
        true
    }
}

impl RngTreeMutation for DeleteSequenceItems {
    fn apply_tree(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        apply_to_sequence_range(
            trace,
            self.length_start,
            self.length_width,
            |length, children, children_start| self.apply_range(length, children, children_start),
        )
    }
}

impl DeleteSequenceItems {
    fn apply_range(
        &self,
        length: &mut [u8],
        children: &mut Vec<TraceNode>,
        children_start: usize,
    ) -> bool {
        let spans = child_spans(children, children_start);
        let end = self.start.saturating_add(self.len);
        let mut kept = Vec::with_capacity(children.len());
        let mut deleted_start = None;
        let mut deleted_end = None;
        for (child, span) in children.iter().cloned().zip(spans.iter()) {
            let delete_child = !span.is_empty() && span.start >= self.start && span.end <= end;
            if delete_child {
                deleted_start.get_or_insert(span.start);
                deleted_end = Some(span.end);
            } else {
                kept.push(child);
            }
        }
        if deleted_start != Some(self.start)
            || deleted_end != Some(end)
            || kept.len() != self.target_len
        {
            return false;
        }
        write_le_word(length, self.target_len as u64);
        *children = kept;
        true
    }
}
