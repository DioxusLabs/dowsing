use super::{RngTraceMutation, edit_all_trace_bytes, replace_trace_span, subtract_first};
use dowsing_rng::Trace;

#[derive(Debug, Clone)]
pub(crate) struct Truncate {
    pub(super) len: usize,
    pub(super) leading_sub: Option<u8>,
}

impl RngTraceMutation for Truncate {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        let trace_len = trace.flatten_prefix().len();
        if self.len > trace_len {
            return false;
        }
        if !replace_trace_span(trace, self.len, trace_len - self.len, &[]) {
            return false;
        }
        if let Some(amount) = self.leading_sub {
            return edit_all_trace_bytes(trace, |bytes| subtract_first(bytes, amount));
        }
        true
    }
}
