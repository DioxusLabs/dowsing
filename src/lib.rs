//! Minimal coverage-guided randomness.
//!
//! Use [`curious`] to maximize coverage while discovering interesting paths, then fork a path with
//! [`CaseRng::fork_case`] and feed it to [`cautious`] to minimize the code path that still matters to
//! the harness.

mod coverage;
mod iter;
mod llvm;
mod sancov;

#[cfg(test)]
mod tests;

pub use coverage::{
    CoverageCapture, CoverageId, CoverageSet, ExecutionFeedback, ParallelCoverageCapture,
};
pub use iter::{
    Case, CaseCoverage, CaseRng, Cases, Cautious, CautiousOptions, Curious, NoCoverage,
    ParallelCases, SearchStats, SemanticKind, SequenceElement, SequenceMap, TakeRange, cautious,
    curious,
};
pub use llvm::{LlvmCoverage, reset_llvm_counters};
pub use sancov::SancovCoverage;
