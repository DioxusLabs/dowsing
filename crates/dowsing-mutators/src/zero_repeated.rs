use super::{RngTraceMutation, edit_all_trace_bytes};
use dowsing_rng::Trace;

#[derive(Debug, Clone)]
pub(crate) struct ZeroRepeated {
    pub(super) value: u8,
}

impl RngTraceMutation for ZeroRepeated {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        edit_all_trace_bytes(trace, |bytes| {
            for byte in bytes {
                if *byte == self.value {
                    *byte = 0;
                }
            }
        })
    }
}
