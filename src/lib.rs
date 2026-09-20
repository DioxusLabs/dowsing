//! Minimal coverage-guided randomness.
//!
//! Use [`curious`] to maximize coverage while discovering interesting paths, then fork a path with
//! [`CaseRng::fork_case`] and feed it to [`cautious`] to minimize the code path that still matters to
//! the harness.

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
    Case, CaseCost, CaseCoverage, CaseRng, Cases, Cautious, ChildRng, Curious, ParallelCases,
    RangeIter, cautious, curious,
};
#[doc(hidden)]
pub use iter::snapshot_hooks;
