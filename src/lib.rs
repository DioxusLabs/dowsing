//! Deterministic mutation-sequence fuzzing with invariant replay and cost-aware reduction.
//!
//! The core workflow is:
//! 1. Sample printable mutations with `rand`'s [`Distribution`](rand::distr::Distribution) trait.
//! 2. Replay each mutation list from a clean state and check invariants after each step.
//! 3. If replay fails, reduce the operation list using a caller-provided cost model.
//!
//! This is meant for state-machine bugs where normal unit tests miss ordering edge cases, but the
//! whole failure can be reproduced from a list of small operations.

mod coverage;
mod coverage_guided;
mod pipeline;
mod reduce;

#[cfg(feature = "llvm-coverage")]
pub mod llvm_coverage;
#[cfg(feature = "rayon")]
pub mod parallel;

#[cfg(test)]
mod tests;

pub use coverage::*;
pub use coverage_guided::*;
pub use pipeline::*;
pub use reduce::*;
