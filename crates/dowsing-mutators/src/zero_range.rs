use super::{RngTraceMutation, edit_trace_bytes};
use dowsing_rng::Trace;

#[derive(Debug, Clone)]
pub(crate) struct ZeroRange {
    pub(super) start: usize,
    pub(super) len: usize,
}

impl RngTraceMutation for ZeroRange {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        if self.len == 0 {
            return false;
        }
        edit_trace_bytes(trace, self.start, self.len, |bytes| bytes.fill(0))
    }
}
