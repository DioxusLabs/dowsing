use super::{RngTraceMutation, edit_trace_bytes};
use dowsing_rng::Trace;

#[derive(Debug, Clone)]
pub(crate) struct XorBit {
    pub(super) index: usize,
    pub(super) bit: u8,
}

impl RngTraceMutation for XorBit {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        edit_trace_bytes(trace, self.index, 1, |bytes| {
            bytes[0] ^= 1 << self.bit;
        })
    }
}
