use super::{RngByteMutation, subtract_first};

#[derive(Debug, Clone)]
pub(crate) struct Truncate {
    pub(super) len: usize,
    pub(super) leading_sub: Option<u8>,
}

impl RngByteMutation for Truncate {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        if self.len > prefix.len() {
            return false;
        }
        prefix.truncate(self.len);
        if let Some(amount) = self.leading_sub {
            subtract_first(prefix, amount);
        }
        true
    }
}
