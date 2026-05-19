use super::{RngTraceMutation, edit_trace_bytes};
use dowsing_rng::Trace;

#[derive(Debug, Clone)]
pub(crate) struct ShuffleBytes {
    pub(super) start: usize,
    pub(super) bytes: Vec<u8>,
}

impl RngTraceMutation for ShuffleBytes {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        if self.bytes.is_empty() {
            return false;
        }
        edit_trace_bytes(trace, self.start, self.bytes.len(), |bytes| {
            bytes.copy_from_slice(&self.bytes);
        })
    }
}
