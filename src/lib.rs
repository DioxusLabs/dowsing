//! Minimal coverage-guided randomness.
//!
//! Use [`curious`] to maximize coverage while discovering interesting paths, then fork a path with
//! [`DemonicRng::fork_case`] and feed it to [`shy`] to minimize the code path that still matters to
//! the harness.

mod coverage;
mod iter;
mod llvm;
mod sancov;

#[cfg(test)]
mod tests;

pub use coverage::{CoverageCapture, CoverageId, CoverageSet, ParallelCoverageCapture};
pub use iter::{
    DemonicCase, DemonicCoverage, DemonicParIter, DemonicRng, DemonicTake, NoCoverage, curious, shy,
};
pub use llvm::{LlvmCoverage, reset_llvm_counters};
pub use sancov::SancovCoverage;
