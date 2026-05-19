//! Backend-neutral optimizers for dowsing.

mod api;
mod optimize;
mod prelude;
mod rng;
mod run;
mod shrink;

pub use api::{Cases, ParallelCases};
pub use dowsing_core::{
    BuiltInMutationSource, CandidateSource, MutationCandidate, MutationContext, MutationSource,
    NoCoverage, SourceFeedback,
};
pub use dowsing_mutators::mutations;
pub use optimize::{Goal, GoalConfig, Optimizer, goals};
pub use prelude::{
    CaseCost, CaseCoverage, Cautious, CautiousOptions, Curious, SearchStats, cautious_with,
    curious_with, optimize, optimize_with,
};
#[allow(deprecated)]
pub use prelude::{cautious, curious};
pub use rng::{CaseRng, RangeIter, ShrinkRandom, ShrinkRange};
