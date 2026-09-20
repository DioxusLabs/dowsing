mod api;
mod mutate;
mod no_coverage;
mod prelude;
mod rng;
mod run;
mod shrink;

pub use api::{Cases, ParallelCases};
#[cfg(test)]
pub(crate) use mutate::test_dictionary_mutation;
pub use no_coverage::NoCoverage;
pub use prelude::{
    Case, CaseCost, CaseCoverage, Cautious, CautiousOptions, Curious, RawCase, RawSequence,
    RawSpan, SearchStats, cautious, curious,
};
pub use rng::{CaseRng, ChildRng, RangeIter};
