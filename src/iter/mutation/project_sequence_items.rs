use super::{
    RngByteMutation, RngTreeMutation, apply_to_sequence_range, child_spans, nonempty_extent,
    write_le_word,
};
use dowsing_rng::{Trace, TraceNode};

#[derive(Debug, Clone)]
pub(in crate::iter) struct ProjectSequenceItems {
    pub(super) length_start: usize,
    pub(super) length_width: usize,
    pub(super) target_len: usize,
    pub(super) replace_start: usize,
    pub(super) replace_len: usize,
    pub(super) items: Vec<(usize, usize)>,
}

impl RngByteMutation for ProjectSequenceItems {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        if self.length_width == 0
            || self.length_start.saturating_add(self.length_width) > prefix.len()
            || self.replace_start.saturating_add(self.replace_len) > prefix.len()
        {
            return false;
        }
        let mut replacement = Vec::new();
        for (start, len) in &self.items {
            if *len == 0 || start.saturating_add(*len) > prefix.len() {
                return false;
            }
            replacement.extend_from_slice(&prefix[*start..*start + *len]);
        }
        write_le_word(
            &mut prefix[self.length_start..self.length_start + self.length_width],
            self.target_len as u64,
        );
        prefix.splice(
            self.replace_start..self.replace_start + self.replace_len,
            replacement,
        );
        true
    }
}

impl RngTreeMutation for ProjectSequenceItems {
    fn apply_tree(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
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
