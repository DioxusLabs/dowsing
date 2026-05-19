use super::{RngByteMutation, shrink_first_by, subtract_first};

#[derive(Debug, Clone, Copy)]
pub(in crate::iter) enum FirstByteAdjustment {
    None,
    ByDeletedLen,
    ByValue(u8),
}

#[derive(Debug, Clone)]
pub(in crate::iter) struct DeleteRange {
    pub(super) start: usize,
    pub(super) len: usize,
    pub(super) first_byte: FirstByteAdjustment,
}

impl RngByteMutation for DeleteRange {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        if self.len == 0 || self.start.saturating_add(self.len) > prefix.len() {
            return false;
        }
        prefix.drain(self.start..self.start + self.len);
        match self.first_byte {
            FirstByteAdjustment::None => {}
            FirstByteAdjustment::ByDeletedLen => shrink_first_by(prefix, self.len),
            FirstByteAdjustment::ByValue(amount) => subtract_first(prefix, amount),
        }
        true
    }
}
