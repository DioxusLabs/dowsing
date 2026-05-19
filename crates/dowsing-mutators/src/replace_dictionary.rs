use super::{RngTraceMutation, edit_trace_bytes, replace_trace_span};
use dowsing_rng::Trace;

#[derive(Debug, Clone, Copy)]
pub(crate) enum ReplaceMode {
    Exact,
    Splice,
}

#[derive(Debug, Clone)]
pub(crate) struct ReplaceDictionary {
    pub(super) start: usize,
    pub(super) len: usize,
    pub(super) dictionary_index: usize,
    pub(super) mode: ReplaceMode,
}

impl RngTraceMutation for ReplaceDictionary {
    fn apply_trace(&self, trace: &mut Trace, dictionary: &[Vec<u8>]) -> bool {
        let Some(bytes) = dictionary.get(self.dictionary_index) else {
            return false;
        };
        match self.mode {
            ReplaceMode::Exact => {
                if bytes.len() != self.len {
                    return false;
                }
                edit_trace_bytes(trace, self.start, self.len, |target| {
                    target.copy_from_slice(bytes);
                })
            }
            ReplaceMode::Splice => replace_trace_span(trace, self.start, self.len, bytes),
        }
    }
}
