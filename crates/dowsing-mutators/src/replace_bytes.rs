use super::{RngTraceMutation, replace_trace_span};
use dowsing_rng::Trace;

#[derive(Debug, Clone)]
pub(crate) struct ReplaceBytes {
    pub(super) start: usize,
    pub(super) len: usize,
    pub(super) bytes: Vec<u8>,
}

impl RngTraceMutation for ReplaceBytes {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        replace_trace_span(trace, self.start, self.len, &self.bytes)
    }
}
