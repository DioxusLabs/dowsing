use super::{RngTraceMutation, replace_trace_span};
use dowsing_rng::Trace;

#[derive(Debug, Clone)]
pub(crate) struct InsertDictionary {
    pub(super) index: usize,
    pub(super) dictionary_index: usize,
}

impl RngTraceMutation for InsertDictionary {
    fn apply_trace(&self, trace: &mut Trace, dictionary: &[Vec<u8>]) -> bool {
        let Some(bytes) = dictionary.get(self.dictionary_index) else {
            return false;
        };
        replace_trace_span(trace, self.index, 0, bytes)
    }
}
