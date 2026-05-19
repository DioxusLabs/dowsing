use super::{RngTraceMutation, replace_trace_span};
use dowsing_rng::Trace;

#[derive(Debug, Clone)]
pub(crate) struct DrainPrefix {
    pub(super) keep_from: usize,
}

impl RngTraceMutation for DrainPrefix {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        replace_trace_span(trace, 0, self.keep_from, &[])
    }
}
