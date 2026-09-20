//! Hidden hooks used by the `spikes/snapshot-rewind` prototype.
//!
//! These let an out-of-tree supervisor observe span boundaries inside a running
//! [`CaseRng`], move a finished execution across a process boundary, and record
//! it into the shared search state from the parent. Nothing here is stable API.

use super::{
    prelude::{
        Case, CaseCost, CaseCoverage, DrawKind, DrawSpan, SemanticKind, SemanticSpan,
        SequenceItemSpan, SequenceSpan,
    },
    rng::CaseRng,
};
use crate::coverage::{CoverageCapture, CoverageId, CoverageSet, ExecutionFeedback};
use rand::{SeedableRng, rngs::SmallRng};

/// Where in the structured RNG stream a boundary was reached.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryKind {
    /// Start of one child of a [`CaseRng::range`].
    Item,
    /// Start of a [`CaseRng::variant`] draw.
    Variant,
    /// Explicit [`CaseRng::checkpoint_hint`].
    Hint,
}

/// A span boundary inside a running execution.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boundary {
    pub kind: BoundaryKind,
    /// Number of stream bytes consumed so far (the byte cursor).
    pub cursor: usize,
}

#[doc(hidden)]
pub type BoundaryHook<Capture> = Box<dyn FnMut(&mut CaseRng<Capture>, Boundary) + Send>;
#[doc(hidden)]
pub type FinishHook = Box<dyn FnMut(&DetachedExecution) + Send>;

/// The stream a candidate is a pure function of.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSpec {
    pub seed: u64,
    pub prefix: Vec<u8>,
    pub zero_tail: bool,
}

/// Everything the parent needs to record an execution that ran in another process.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq)]
pub struct DetachedExecution {
    pub(super) trace: Vec<u8>,
    pub(super) draws: Vec<DrawSpan>,
    pub(super) semantics: Vec<SemanticSpan>,
    pub(super) sequences: Vec<SequenceSpan>,
    pub(super) bytes_consumed: usize,
    pub(super) feedback: Option<ExecutionFeedback>,
    pub(super) case_cost: CaseCost,
}

impl DetachedExecution {
    pub fn trace(&self) -> &[u8] {
        &self.trace
    }

    pub fn bytes_consumed(&self) -> usize {
        self.bytes_consumed
    }

    pub fn feedback(&self) -> Option<&ExecutionFeedback> {
        self.feedback.as_ref()
    }

    pub fn case_cost(&self) -> CaseCost {
        self.case_cost
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_bytes(&mut out, &self.trace);
        put_u64(&mut out, self.draws.len() as u64);
        for span in &self.draws {
            put_u64(&mut out, span.start as u64);
            put_u64(&mut out, span.len as u64);
            out.push(match span.kind {
                DrawKind::Word => 0,
                DrawKind::Bytes => 1,
            });
        }
        put_u64(&mut out, self.semantics.len() as u64);
        for span in &self.semantics {
            put_u64(&mut out, span.start as u64);
            put_u64(&mut out, span.len as u64);
            out.push(match span.kind {
                SemanticKind::Length => 0,
                SemanticKind::Item => 1,
                SemanticKind::Variant => 2,
            });
        }
        put_u64(&mut out, self.sequences.len() as u64);
        for span in &self.sequences {
            put_u64(&mut out, span.length_start as u64);
            put_u64(&mut out, span.length_len as u64);
            put_u64(&mut out, span.items.len() as u64);
            for item in &span.items {
                put_u64(&mut out, item.start as u64);
                put_u64(&mut out, item.len as u64);
            }
        }
        put_u64(&mut out, self.bytes_consumed as u64);
        put_u64(&mut out, self.case_cost.get() as u64);
        match &self.feedback {
            None => out.push(0),
            Some(feedback) => {
                out.push(1);
                put_u64(&mut out, feedback.features.len() as u64);
                for id in feedback.features.iter() {
                    put_u64(&mut out, id.raw());
                }
                put_u64(&mut out, feedback.hit_count_weight);
                put_u64(&mut out, feedback.dictionary.len() as u64);
                for value in &feedback.dictionary {
                    put_bytes(&mut out, value);
                }
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut cursor = Reader { bytes, pos: 0 };
        let trace = cursor.bytes()?.to_vec();
        let draws = (0..cursor.u64()?)
            .map(|_| {
                let start = cursor.usize()?;
                let len = cursor.usize()?;
                let kind = match cursor.u8()? {
                    0 => DrawKind::Word,
                    1 => DrawKind::Bytes,
                    other => return Err(format!("bad draw kind {other}")),
                };
                Ok(DrawSpan::new(start, len, kind))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let semantics = (0..cursor.u64()?)
            .map(|_| {
                let start = cursor.usize()?;
                let len = cursor.usize()?;
                let kind = match cursor.u8()? {
                    0 => SemanticKind::Length,
                    1 => SemanticKind::Item,
                    2 => SemanticKind::Variant,
                    other => return Err(format!("bad semantic kind {other}")),
                };
                Ok(SemanticSpan::new(start, len, kind))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let sequences = (0..cursor.u64()?)
            .map(|_| {
                let length_start = cursor.usize()?;
                let length_len = cursor.usize()?;
                let items = (0..cursor.u64()?)
                    .map(|_| {
                        let start = cursor.usize()?;
                        let len = cursor.usize()?;
                        Ok(SequenceItemSpan { start, len })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                Ok(SequenceSpan {
                    length_start,
                    length_len,
                    items,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let bytes_consumed = cursor.usize()?;
        let case_cost = CaseCost::new(cursor.usize()?);
        let feedback = match cursor.u8()? {
            0 => None,
            1 => {
                let mut features = CoverageSet::new();
                for _ in 0..cursor.u64()? {
                    features.insert(CoverageId::new(cursor.u64()?));
                }
                let hit_count_weight = cursor.u64()?;
                let dictionary = (0..cursor.u64()?)
                    .map(|_| Ok(cursor.bytes()?.to_vec()))
                    .collect::<Result<Vec<_>, String>>()?;
                Some(ExecutionFeedback::new(
                    features,
                    hit_count_weight,
                    dictionary,
                ))
            }
            other => return Err(format!("bad feedback tag {other}")),
        };
        if cursor.pos != bytes.len() {
            return Err("trailing bytes in detached execution".to_string());
        }
        Ok(Self {
            trace,
            draws,
            semantics,
            sequences,
            bytes_consumed,
            feedback,
            case_cost,
        })
    }
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Result<u8, String> {
        let byte = *self.bytes.get(self.pos).ok_or("truncated detached execution")?;
        self.pos += 1;
        Ok(byte)
    }

    fn u64(&mut self) -> Result<u64, String> {
        let end = self.pos + 8;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or("truncated detached execution")?;
        self.pos = end;
        Ok(u64::from_le_bytes(slice.try_into().expect("8 bytes")))
    }

    fn usize(&mut self) -> Result<usize, String> {
        usize::try_from(self.u64()?).map_err(|_| "value overflows usize".to_string())
    }

    fn bytes(&mut self) -> Result<&[u8], String> {
        let len = self.usize()?;
        let end = self.pos + len;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or("truncated detached execution")?;
        self.pos = end;
        Ok(slice)
    }
}

impl<Capture: CoverageCapture> CaseRng<Capture> {
    /// Zero-byte checkpoint marker: tells a snapshotting supervisor that the
    /// setup phase is over and a snapshot here is likely worthwhile.
    pub fn checkpoint_hint(&mut self) {
        self.fire_boundary(BoundaryKind::Hint);
    }

    /// Install the boundary and finish hooks used by a detached runner.
    #[doc(hidden)]
    pub fn snapshot_install_hooks(
        &mut self,
        boundary: Option<BoundaryHook<Capture>>,
        finish: Option<FinishHook>,
    ) {
        self.boundary_hook = boundary;
        self.finish_hook = finish;
    }

    /// Remove the boundary hook (for example, after the policy decides no more snapshots are wanted).
    #[doc(hidden)]
    pub fn snapshot_clear_boundary_hook(&mut self) {
        self.boundary_hook = None;
    }

    #[doc(hidden)]
    pub fn snapshot_stream(&self) -> StreamSpec {
        StreamSpec {
            seed: self.seed,
            prefix: self.prefix.clone(),
            zero_tail: self.zero_tail,
        }
    }

    #[doc(hidden)]
    pub fn snapshot_cursor(&self) -> usize {
        self.cursor
    }

    /// Bytes consumed so far.
    #[doc(hidden)]
    pub fn snapshot_trace(&self) -> &[u8] {
        &self.trace
    }

    /// Redirect the remainder of the stream to `spec`. Only valid when the first
    /// `cursor` bytes of `spec.prefix` equal the bytes consumed so far.
    #[doc(hidden)]
    pub fn snapshot_install_stream(&mut self, spec: StreamSpec) -> Result<(), String> {
        if spec.prefix.len() < self.cursor || spec.prefix[..self.cursor] != self.trace[..] {
            return Err("stream prefix does not match consumed bytes".to_string());
        }
        self.seed = spec.seed;
        self.prefix = spec.prefix;
        self.zero_tail = spec.zero_tail;
        self.fallback = SmallRng::seed_from_u64(spec.seed);
        Ok(())
    }

    /// Record an execution that finished in another process as this candidate's result.
    #[doc(hidden)]
    pub fn snapshot_record(mut self, execution: DetachedExecution) -> Result<CaseCoverage, String> {
        self.finished = true;
        self.release_parent_token();
        self.merge_detached(execution)
    }

    /// Drop this candidate without recording anything (the detached runner died).
    #[doc(hidden)]
    pub fn snapshot_abandon(mut self) {
        self.finished = true;
        self.release_parent_token();
        let mut state = self.shared.lock().expect("search state poisoned");
        state.stats.executed += 1;
        state.active_cases = state.active_cases.saturating_sub(1);
    }

    /// Build the replayable case for a detached execution of this candidate.
    #[doc(hidden)]
    pub fn snapshot_case(&self, execution: &DetachedExecution) -> Case {
        Case {
            seed: self.seed,
            prefix: execution.trace.clone(),
            zero_tail: self.zero_tail,
            draws: execution.draws.clone(),
            semantics: execution.semantics.clone(),
            sequences: execution.sequences.clone(),
        }
    }

    fn release_parent_token(&mut self) {
        let Some(token) = self.token.take() else {
            return;
        };
        let _ = if let Some(capture) = self.local_capture.as_mut() {
            capture.discard_capture(token)
        } else {
            self.shared
                .lock()
                .expect("search state poisoned")
                .capture
                .discard_capture(token)
        };
    }
}
