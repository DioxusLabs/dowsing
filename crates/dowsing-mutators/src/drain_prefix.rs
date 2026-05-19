use super::RngByteMutation;

#[derive(Debug, Clone)]
pub(crate) struct DrainPrefix {
    pub(super) keep_from: usize,
}

impl RngByteMutation for DrainPrefix {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        if self.keep_from > prefix.len() {
            return false;
        }
        prefix.drain(0..self.keep_from);
        true
    }
}
