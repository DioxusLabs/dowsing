use super::{RngByteMutation, write_le_word};

#[derive(Debug, Clone)]
pub(in crate::iter) struct SetWord {
    pub(super) start: usize,
    pub(super) width: usize,
    pub(super) value: u64,
    pub(super) zero_until: Option<usize>,
}

impl RngByteMutation for SetWord {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        if self.start.saturating_add(self.width) > prefix.len() {
            return false;
        }
        write_le_word(&mut prefix[self.start..self.start + self.width], self.value);
        if let Some(end) = self.zero_until {
            let tail_start = self.start.saturating_add(self.width);
            if tail_start < end && end <= prefix.len() {
                prefix[tail_start..end].fill(0);
            }
        }
        true
    }
}
