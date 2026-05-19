use super::{RngTraceMutation, edit_trace_bytes};
use dowsing_rng::Trace;

#[derive(Debug, Clone)]
pub(crate) struct AddByte {
    pub(super) index: usize,
    pub(super) amount: u8,
}

impl RngTraceMutation for AddByte {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        edit_trace_bytes(trace, self.index, 1, |bytes| {
            bytes[0] = bytes[0].wrapping_add(self.amount);
        })
    }
}
