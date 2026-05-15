//! Minimal coverage-guided randomness.
//!
//! Use [`curious`] to maximize coverage while discovering interesting paths, then fork a path with
//! [`DemonicRng::fork_case`] and feed it to [`shy`] to minimize the code path that still matters to
//! the harness.

mod coverage;
mod iter;
mod llvm;
mod parallel;
mod sancov;

#[cfg(test)]
mod tests;

pub use coverage::{CoverageCapture, CoverageId, CoverageSet};
pub use iter::{DemonicCase, DemonicCoverage, DemonicRng, NoCoverage, curious, shy};
pub use llvm::{LlvmCoverage, reset_llvm_counters};
pub use parallel::{RayonShard, rayon_shards, rayon_shards_from};
pub use sancov::SancovCoverage;
