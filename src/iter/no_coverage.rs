use crate::coverage::{CaptureStart, CoverageCapture, ExecutionFeedback, ParallelCoverageCapture};

/// Coverage backend used when callers only want the RNG shape.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoCoverage;

impl CoverageCapture for NoCoverage {
    type Session = ();

    fn start_capture(&mut self) -> Result<CaptureStart<Self::Session>, String> {
        Ok(CaptureStart::Started(()))
    }

    fn finish_capture(&mut self, _session: Self::Session) -> Result<ExecutionFeedback, String> {
        Ok(ExecutionFeedback::default())
    }
}

impl ParallelCoverageCapture for NoCoverage {}
