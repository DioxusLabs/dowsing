use crate::coverage::{CaptureStart, CoverageCapture, CoverageId, CoverageSet, ExecutionFeedback};
use dowsing_sys::llvm as sys;

/// In-process LLVM counter coverage for `curious()` and `cautious()`.
///
/// Build the harness with `RUSTFLAGS="-Cinstrument-coverage"` so LLVM exposes coverage counters
/// in the current process. Each nonzero counter becomes a coverage feature. With bucketing enabled,
/// the hit-count bucket is part of the feature ID, so changing loop counts can also guide search.
#[derive(Debug, Clone)]
pub struct LlvmCoverage {
    runtime: sys::LlvmRuntime,
    bucketing: bool,
}

impl LlvmCoverage {
    /// Initialize coverage from the current instrumented process.
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            runtime: sys::LlvmRuntime::new().map_err(|error| error.to_string())?,
            bucketing: true,
        })
    }

    /// Toggle hit-count bucketing. Enabled by default.
    pub fn with_bucketing(mut self, enabled: bool) -> Self {
        self.bucketing = enabled;
        self
    }
}

impl CoverageCapture for LlvmCoverage {
    type Session = LlvmSession;

    fn start_capture(&mut self) -> Result<CaptureStart<Self::Session>, String> {
        match self.runtime.start() {
            sys::LlvmStart::Started(inner) => Ok(CaptureStart::Started(LlvmSession { inner })),
            sys::LlvmStart::Busy => Ok(CaptureStart::Busy),
        }
    }

    fn finish_capture(&mut self, session: Self::Session) -> Result<ExecutionFeedback, String> {
        let feedback = session
            .inner
            .finish(self.bucketing)
            .map_err(|error| error.to_string())?;
        Ok(ExecutionFeedback::new(
            coverage_set(feedback.features),
            feedback.hit_count_weight,
            Vec::new(),
        ))
    }
}

#[derive(Debug)]
pub struct LlvmSession {
    inner: sys::LlvmSession,
}

/// Reset the process-wide LLVM coverage counters.
pub fn reset_llvm_counters() -> Result<(), String> {
    sys::LlvmRuntime::reset_counters().map_err(|error| error.to_string())
}

fn coverage_set(features: Vec<dowsing_sys::RawFeature>) -> CoverageSet {
    CoverageSet::from_unsorted(
        features
            .into_iter()
            .map(|feature| CoverageId::new(feature.raw()))
            .collect(),
    )
}
