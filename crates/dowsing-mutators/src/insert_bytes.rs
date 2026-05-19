use super::RngByteMutation;

#[derive(Debug, Clone)]
pub(crate) struct InsertBytes {
    pub(super) index: usize,
    pub(super) bytes: Vec<u8>,
}

impl RngByteMutation for InsertBytes {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, _dictionary: &[Vec<u8>]) -> bool {
        if self.index > prefix.len() {
            return false;
        }
        prefix.splice(self.index..self.index, self.bytes.iter().copied());
        true
    }
}
