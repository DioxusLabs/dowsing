use super::RngByteMutation;

#[derive(Debug, Clone, Copy)]
pub(in crate::iter) enum ReplaceMode {
    Exact,
    Splice,
}

#[derive(Debug, Clone)]
pub(in crate::iter) struct ReplaceDictionary {
    pub(super) start: usize,
    pub(super) len: usize,
    pub(super) dictionary_index: usize,
    pub(super) mode: ReplaceMode,
}

impl RngByteMutation for ReplaceDictionary {
    fn apply_bytes(&self, prefix: &mut Vec<u8>, dictionary: &[Vec<u8>]) -> bool {
        let Some(bytes) = dictionary.get(self.dictionary_index) else {
            return false;
        };
        if self.start.saturating_add(self.len) > prefix.len() {
            return false;
        }
        match self.mode {
            ReplaceMode::Exact => {
                if bytes.len() != self.len {
                    return false;
                }
                prefix[self.start..self.start + self.len].copy_from_slice(bytes);
            }
            ReplaceMode::Splice => {
                prefix.splice(self.start..self.start + self.len, bytes.iter().copied());
            }
        }
        true
    }
}
