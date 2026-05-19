use super::RngByteMutation;

#[derive(Debug, Clone)]
pub(in crate::iter) struct SubByte {
    pub(super) index: usize,
    pub(super) amount: u8,
}

impl RngByteMutation for SubByte {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        let Some(byte) = prefix.get_mut(self.index) else {
            return false;
        };
        *byte = byte.wrapping_sub(self.amount);
        true
    }
}
