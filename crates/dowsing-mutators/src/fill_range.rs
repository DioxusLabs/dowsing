use super::RngByteMutation;

#[derive(Debug, Clone)]
pub(crate) struct FillRange {
    pub(super) start: usize,
    pub(super) bytes: Vec<u8>,
}

impl RngByteMutation for FillRange {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        if self.start.saturating_add(self.bytes.len()) > prefix.len() {
            return false;
        }
        prefix[self.start..self.start + self.bytes.len()].copy_from_slice(&self.bytes);
        true
    }
}
