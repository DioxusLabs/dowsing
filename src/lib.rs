//! Minimal coverage-guided randomness.
//!
//! Use [`optimize`] with [`goals::MaximizeCoverage`] to discover interesting paths, then fork a path
//! with [`CaseRng::fork_case`] and feed it to [`goals::MinimizeCoverage`] to minimize the code path that
//! still matters to the harness.
//!
//! Replayable RNG trace storage lives in `dowsing-rng`; this crate layers coverage feedback and
//! search scheduling on top.

pub mod coverage;
mod llvm;
mod sancov;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod iter {
    pub(crate) use dowsing_mutators::test_dictionary_mutation;
}

pub mod backends {
    pub use crate::{
        coverage::NoCoverage,
        llvm::{LlvmCoverage, reset_llvm_counters},
        sancov::SancovCoverage,
    };
}

pub mod tuning {
    pub use dowsing_optimizers::{CautiousOptions, SearchStats};
}

pub use backends::NoCoverage;
pub use dowsing_core::{
    BuiltInMutationSource, CandidateSource, Case, MutationCandidate, MutationContext,
    MutationSource, SourceFeedback,
};
pub use dowsing_mutators::mutations;
pub use dowsing_optimizers::{
    CaseCost, CaseCoverage, Cases, Goal, GoalConfig, SearchStats, ShrinkRandom, ShrinkRange, goals,
};
pub type CaseRng<Capture = sancov::SancovCoverage> = dowsing_optimizers::CaseRng<Capture>;
pub type Cautious<Capture = sancov::SancovCoverage> = dowsing_optimizers::Cautious<Capture>;
pub type Curious<Capture = sancov::SancovCoverage> = dowsing_optimizers::Curious<Capture>;
pub type Optimizer<G = goals::MaximizeCoverage, Capture = sancov::SancovCoverage> =
    dowsing_optimizers::Optimizer<G, Capture>;
pub type ParallelCases<Capture = sancov::SancovCoverage> =
    dowsing_optimizers::ParallelCases<Capture>;
pub type RangeIter<'a, Capture = sancov::SancovCoverage> =
    dowsing_optimizers::RangeIter<'a, Capture>;

/// Build a generalized optimizer for `goal` with the default sancov backend.
pub fn optimize<G>(goal: G) -> Optimizer<G, sancov::SancovCoverage>
where
    G: Goal,
{
    dowsing_optimizers::optimize_with(goal, sancov::SancovCoverage::new())
}

/// Coverage-maximizing RNG iterator with the default sancov backend.
#[deprecated(note = "use optimize(goals::MaximizeCoverage)")]
pub fn curious() -> Curious<sancov::SancovCoverage> {
    dowsing_optimizers::curious_with(sancov::SancovCoverage::new())
}

/// Code-path-minimizing RNG iterator with the default sancov backend.
#[deprecated(note = "use optimize(goals::MinimizeCoverage)")]
pub fn cautious() -> Cautious<sancov::SancovCoverage> {
    dowsing_optimizers::cautious_with(sancov::SancovCoverage::new())
}
