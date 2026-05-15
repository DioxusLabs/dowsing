use crate::coverage::{CoverageCapture, ExecutionFeedback, ParallelCoverageCapture};

/// Coverage backend used when callers only want the RNG shape.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoCoverage;

impl CoverageCapture for NoCoverage {
    type Token = ();

    fn start_capture(&mut self) -> Result<Self::Token, String> {
        Ok(())
    }

    fn finish_capture(&mut self, _token: Self::Token) -> Result<ExecutionFeedback, String> {
        Ok(ExecutionFeedback::default())
    }
}

impl ParallelCoverageCapture for NoCoverage {}
