use super::{RngTraceMutation, edit_trace_bytes, replace_trace_span};
use dowsing_rng::Trace;

#[derive(Debug, Clone, Copy)]
pub(crate) enum CopyPartMode {
    Insert,
    Overwrite,
}

#[derive(Debug, Clone)]
pub(crate) struct CopyPart {
    pub(super) source: usize,
    pub(super) target: usize,
    pub(super) len: usize,
    pub(super) mode: CopyPartMode,
}

impl RngTraceMutation for CopyPart {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        let prefix = trace.flatten_prefix();
        if self.len == 0 || self.source.saturating_add(self.len) > prefix.len() {
            return false;
        }
        let bytes = prefix[self.source..self.source + self.len].to_vec();
        match self.mode {
            CopyPartMode::Insert => replace_trace_span(trace, self.target, 0, &bytes),
            CopyPartMode::Overwrite => edit_trace_bytes(trace, self.target, self.len, |target| {
                target.copy_from_slice(&bytes);
            }),
        }
    }
}
