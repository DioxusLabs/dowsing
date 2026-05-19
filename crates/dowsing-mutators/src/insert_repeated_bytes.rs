use super::{RngTraceMutation, replace_trace_span};
use dowsing_rng::Trace;

#[derive(Debug, Clone)]
pub(crate) struct InsertRepeatedBytes {
    pub(super) index: usize,
    pub(super) byte: u8,
    pub(super) len: usize,
}

impl RngTraceMutation for InsertRepeatedBytes {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        if self.len == 0 {
            return false;
        }
        let bytes = vec![self.byte; self.len];
        replace_trace_span(trace, self.index, 0, &bytes)
    }
}
