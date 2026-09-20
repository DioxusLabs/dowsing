//! Type-erased access to a `CaseRng` so the supervisor thread can draw structured values without
//! knowing the coverage backend.
//!
//! Every sandbox decision goes through the public `variant`/`range`/`fill_bytes` API so
//! `cautious()` can shrink it with its existing passes: a `variant` is a 4-byte semantic span, a
//! `range` records a length span plus one item span per element, and `fill_bytes` is a byte draw
//! that zeroes under `zero_tail`.

use std::any::Any;
use std::ops::RangeInclusive;

use iterator_fuzz::CaseRng;
use iterator_fuzz::coverage::CoverageCapture;
use rand::RngCore;

pub trait Draw: Any + Send {
    /// `CaseRng::variant`.
    fn variant(&mut self, upper: usize) -> usize;
    /// A `range` of single-byte items: shrinkable in length and per byte.
    fn bytes(&mut self, len: RangeInclusive<usize>) -> Vec<u8>;
    /// Raw `fill_bytes` (one draw span).
    fn fill(&mut self, buf: &mut [u8]);
    /// Trace bytes consumed through this object.
    fn consumed(&self) -> usize;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

pub struct RngDraw<Capture: CoverageCapture> {
    rng: Option<CaseRng<Capture>>,
    consumed: usize,
}

impl<Capture: CoverageCapture> RngDraw<Capture> {
    pub fn new(rng: CaseRng<Capture>) -> Self {
        Self {
            rng: Some(rng),
            consumed: 0,
        }
    }

    /// Hand the RNG back to the harness.
    pub fn take(&mut self) -> CaseRng<Capture> {
        self.rng.take().expect("case rng already taken")
    }

    fn rng(&mut self) -> &mut CaseRng<Capture> {
        self.rng.as_mut().expect("case rng already taken")
    }
}

impl<Capture> Draw for RngDraw<Capture>
where
    Capture: CoverageCapture + Send + 'static,
    Capture::Token: Send,
{
    fn variant(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            return 0;
        }
        self.consumed += 4;
        self.rng().variant(upper)
    }

    fn bytes(&mut self, len: RangeInclusive<usize>) -> Vec<u8> {
        if len.start() != len.end() {
            self.consumed += 4;
        }
        let mut out = Vec::new();
        for mut child in self.rng().range(len) {
            let mut byte = [0u8];
            child.fill_bytes(&mut byte);
            out.push(byte[0]);
        }
        self.consumed += out.len();
        out
    }

    fn fill(&mut self, buf: &mut [u8]) {
        self.consumed += buf.len();
        self.rng().fill_bytes(buf);
    }

    fn consumed(&self) -> usize {
        self.consumed
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Convenience: pick one element of a slice by `variant`, with index 0 the realistic default.
pub fn pick<'a, T>(draw: &mut dyn Draw, items: &'a [T]) -> (usize, &'a T) {
    assert!(!items.is_empty(), "variant set must not be empty");
    let index = draw.variant(items.len());
    (index, &items[index])
}
