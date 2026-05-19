use super::{
    RngTraceMutation, edit_all_trace_bytes, replace_trace_span, shrink_first_by, subtract_first,
};
use dowsing_rng::Trace;

#[derive(Debug, Clone, Copy)]
pub(crate) enum FirstByteAdjustment {
    None,
    ByDeletedLen,
    ByValue(u8),
}

#[derive(Debug, Clone)]
pub(crate) struct DeleteRange {
    pub(super) start: usize,
    pub(super) len: usize,
    pub(super) first_byte: FirstByteAdjustment,
}

impl RngTraceMutation for DeleteRange {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        if self.len == 0 {
            return false;
        }
        if !replace_trace_span(trace, self.start, self.len, &[]) {
            return false;
        }
        match self.first_byte {
            FirstByteAdjustment::None => {}
            FirstByteAdjustment::ByDeletedLen => {
                return edit_all_trace_bytes(trace, |bytes| shrink_first_by(bytes, self.len));
            }
            FirstByteAdjustment::ByValue(amount) => {
                return edit_all_trace_bytes(trace, |bytes| subtract_first(bytes, amount));
            }
        }
        true
    }
}
