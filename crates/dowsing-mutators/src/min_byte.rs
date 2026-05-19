use super::{RngTraceMutation, edit_trace_bytes};
use dowsing_rng::Trace;

#[derive(Debug, Clone)]
pub(crate) struct MinByte {
    pub(super) index: usize,
    pub(super) value: u8,
}

impl RngTraceMutation for MinByte {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        edit_trace_bytes(trace, self.index, 1, |bytes| {
            bytes[0] = bytes[0].min(self.value);
        })
    }
}
