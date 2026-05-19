use super::RngByteMutation;

#[derive(Debug, Clone)]
pub(in crate::iter) struct InsertDictionary {
    pub(super) index: usize,
    pub(super) dictionary_index: usize,
}

impl RngByteMutation for InsertDictionary {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, dictionary: &[Vec<u8>]) -> bool {
        let Some(bytes) = dictionary.get(self.dictionary_index) else {
            return false;
        };
        if self.index > prefix.len() {
            return false;
        }
        prefix.splice(self.index..self.index, bytes.iter().copied());
        true
    }
}
