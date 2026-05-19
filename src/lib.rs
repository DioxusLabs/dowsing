//! Minimal coverage-guided randomness.
//!
//! Use [`optimize`] with [`goals::MaximizeCoverage`] to discover interesting paths, then fork a path
//! with [`CaseRng::fork_case`] and feed it to [`goals::MinimizeCoverage`] to minimize the code path that
//! still matters to the harness.
//!
//! Replayable RNG trace storage lives in `dowsing-rng`; this crate layers coverage feedback and
//! search scheduling on top.

pub mod coverage;
mod iter;
mod llvm;
mod sancov;

#[cfg(test)]
mod tests;

pub mod backends {
    pub use crate::{
        iter::NoCoverage,
        llvm::{LlvmCoverage, reset_llvm_counters},
        sancov::SancovCoverage,
    };
}

pub mod tuning {
    pub use crate::iter::{CautiousOptions, SearchStats};
}

pub use backends::NoCoverage;
pub use iter::{
    CandidateSource, Case, CaseCost, CaseCoverage, CaseRng, Cases, Cautious, Curious, Goal,
    GoalConfig, MutationCandidate, MutationContext, MutationSource, Optimizer, ParallelCases,
    RangeIter, ShrinkRandom, ShrinkRange, SourceFeedback, goals, mutations, optimize,
};
#[allow(deprecated)]
pub use iter::{cautious, curious};
