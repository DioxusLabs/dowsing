use super::{
    RngTraceMutation, apply_to_sequence_range, child_spans, nonempty_extent, write_le_word,
};
use dowsing_rng::{Trace, TraceNode};

#[derive(Debug, Clone)]
pub(crate) struct ProjectSequenceItems {
    pub(super) length_start: usize,
    pub(super) length_width: usize,
    pub(super) target_len: usize,
    pub(super) replace_start: usize,
    pub(super) replace_len: usize,
    pub(super) items: Vec<(usize, usize)>,
}

impl RngTraceMutation for ProjectSequenceItems {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        apply_to_sequence_range(
            trace,
            self.length_start,
            self.length_width,
            |length, children, children_start| self.apply_range(length, children, children_start),
        )
    }
}

impl ProjectSequenceItems {
    fn apply_range(
        &self,
        length: &mut [u8],
        children: &mut Vec<TraceNode>,
        children_start: usize,
    ) -> bool {
        let spans = child_spans(children, children_start);
        let replace_end = self.replace_start.saturating_add(self.replace_len);
        if nonempty_extent(&spans) != Some(self.replace_start..replace_end) {
            return false;
        }

        let mut projected = Vec::with_capacity(self.items.len());
        for (start, len) in &self.items {
            let end = start.saturating_add(*len);
            let Some((index, _)) = spans
                .iter()
                .enumerate()
                .find(|(_, span)| span.start == *start && span.end == end)
            else {
                return false;
            };
            projected.push(children[index].clone());
        }
        if projected.len() != self.target_len {
            return false;
        }
        write_le_word(length, self.target_len as u64);
        *children = projected;
        true
    }
}
