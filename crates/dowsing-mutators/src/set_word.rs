use super::{RngTraceMutation, WordEndian, edit_all_trace_bytes, write_be_word, write_le_word};
use dowsing_rng::Trace;

#[derive(Debug, Clone)]
pub(crate) struct SetWord {
    pub(super) start: usize,
    pub(super) width: usize,
    pub(super) value: u64,
    pub(super) endian: WordEndian,
    pub(super) zero_until: Option<usize>,
}

impl RngTraceMutation for SetWord {
    fn apply_trace(&self, trace: &mut Trace, _dictionary: &[Vec<u8>]) -> bool {
        let prefix_len = trace.flatten_prefix().len();
        if self.start.saturating_add(self.width) > prefix_len {
            return false;
        }
        if let Some(end) = self.zero_until {
            let tail_start = self.start.saturating_add(self.width);
            if tail_start < end && end > prefix_len {
                return false;
            }
        }
        edit_all_trace_bytes(trace, |prefix| {
            match self.endian {
                WordEndian::Little => {
                    write_le_word(&mut prefix[self.start..self.start + self.width], self.value);
                }
                WordEndian::Big => {
                    write_be_word(&mut prefix[self.start..self.start + self.width], self.value);
                }
            }
            if let Some(end) = self.zero_until {
                let tail_start = self.start.saturating_add(self.width);
                if tail_start < end {
                    prefix[tail_start..end].fill(0);
                }
            }
        })
    }
}
