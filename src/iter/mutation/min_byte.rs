use super::RngByteMutation;

#[derive(Debug, Clone)]
pub(in crate::iter) struct MinByte {
    pub(super) index: usize,
    pub(super) value: u8,
}

impl RngByteMutation for MinByte {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        let Some(byte) = prefix.get_mut(self.index) else {
            return false;
        };
        *byte = (*byte).min(self.value);
        true
    }
}
