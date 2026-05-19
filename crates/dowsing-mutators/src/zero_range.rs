use super::RngByteMutation;

#[derive(Debug, Clone)]
pub(crate) struct ZeroRange {
    pub(super) start: usize,
    pub(super) len: usize,
}

impl RngByteMutation for ZeroRange {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        if self.len == 0 || self.start.saturating_add(self.len) > prefix.len() {
            return false;
        }
        prefix[self.start..self.start + self.len].fill(0);
        true
    }
}
