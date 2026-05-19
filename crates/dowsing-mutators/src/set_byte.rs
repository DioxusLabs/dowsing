use super::RngByteMutation;

#[derive(Debug, Clone)]
pub(crate) struct SetByte {
    pub(super) index: usize,
    pub(super) value: u8,
}

impl RngByteMutation for SetByte {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        let Some(byte) = prefix.get_mut(self.index) else {
            return false;
        };
        *byte = self.value;
        true
    }
}
