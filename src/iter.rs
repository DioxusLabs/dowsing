mod api;
mod mutate;
mod mutation;
mod no_coverage;
mod optimize;
mod prelude;
mod rng;
mod run;
mod shrink;

pub use api::{Cases, ParallelCases};
#[cfg(test)]
pub(crate) use mutate::test_dictionary_mutation;
pub use no_coverage::NoCoverage;
pub use optimize::{
    CandidateSource, Goal, GoalConfig, MutationCandidate, MutationContext, MutationSource,
    Optimizer, SourceFeedback, goals, mutations,
};
pub use prelude::{
    Case, CaseCost, CaseCoverage, Cautious, CautiousOptions, Curious, SearchStats, optimize,
};
#[allow(deprecated)]
pub use prelude::{cautious, curious};
pub use rng::{CaseRng, RangeIter, ShrinkRandom, ShrinkRange};
