use crate::coverage::{
    CaptureStart, CoverageCapture, CoverageId, CoverageSet, ExecutionFeedback,
    ParallelCoverageCapture,
};
use dowsing_sys::sancov as sys;

/// In-process LLVM SanitizerCoverage feedback for `curious()` and `cautious()`.
///
/// Build the harness with `-Cpasses=sancov-module` plus LLVM sanitizer-coverage arguments so
/// LLVM emits edge feedback and comparison callbacks. Native parallel iteration requires
/// trace-pc-guard edge feedback; inline counters are process-global and are used serially.
#[derive(Debug, Clone, Copy, Default)]
pub struct SancovCoverage {
    cmp_feedback: bool,
}

#[derive(Debug)]
pub struct SancovSession {
    inner: sys::SancovSession,
}

impl SancovCoverage {
    /// Create a SanitizerCoverage backend. If the binary is not instrumented, it yields empty
    /// coverage instead of failing so the fuzzing constructors remain simple.
    pub fn new() -> Self {
        Self { cmp_feedback: true }
    }

    /// Toggle comparison feedback. Enabled by default.
    pub fn with_cmp_feedback(mut self, enabled: bool) -> Self {
        self.cmp_feedback = enabled;
        self
    }
}

impl CoverageCapture for SancovCoverage {
    type Session = SancovSession;

    fn start_capture(&mut self) -> Result<CaptureStart<Self::Session>, String> {
        match sys::Sancov::start(sys::SancovOptions {
            cmp_feedback: self.cmp_feedback,
        }) {
            sys::SancovStart::Started(inner) => Ok(CaptureStart::Started(SancovSession { inner })),
            sys::SancovStart::Busy => Ok(CaptureStart::Busy),
        }
    }

    fn finish_capture(&mut self, session: Self::Session) -> Result<ExecutionFeedback, String> {
        let feedback = session.inner.finish();
        Ok(ExecutionFeedback::new(
            coverage_set(feedback.features),
            feedback.hit_count_weight,
            feedback.dictionary,
        ))
    }

    fn discard_capture(&mut self, session: Self::Session) -> Result<(), String> {
        session.inner.discard();
        Ok(())
    }
}

impl ParallelCoverageCapture for SancovCoverage {
    fn validate_parallel(&self) -> Result<(), String> {
        sys::Sancov::validate_parallel().map_err(|error| error.to_string())
    }
}

#[cfg(test)]
pub(crate) fn has_trace_pc_guards() -> bool {
    sys::Sancov::has_trace_pc_guards()
}

fn coverage_set(features: Vec<dowsing_sys::RawFeature>) -> CoverageSet {
    CoverageSet::from_unsorted(
        features
            .into_iter()
            .map(|feature| CoverageId::new(feature.raw()))
            .collect(),
    )
}
