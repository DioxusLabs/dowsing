use super::RngByteMutation;

#[derive(Debug, Clone)]
pub(crate) struct XorBit {
    pub(super) index: usize,
    pub(super) bit: u8,
}

impl RngByteMutation for XorBit {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        let Some(byte) = prefix.get_mut(self.index) else {
            return false;
        };
        *byte ^= 1 << self.bit;
        true
    }
}
