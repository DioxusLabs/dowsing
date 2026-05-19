use super::RngByteMutation;

#[derive(Debug, Clone)]
pub(crate) struct ZeroRepeated {
    pub(super) value: u8,
}

impl RngByteMutation for ZeroRepeated {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        for byte in prefix {
            if *byte == self.value {
                *byte = 0;
            }
        }
        true
    }
}
