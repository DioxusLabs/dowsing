//! Deterministic mutation-sequence fuzzing with invariant replay and cost-aware reduction.
//!
//! The core workflow is:
//! 1. Sample printable mutations with `rand`'s [`Distribution`] trait.
//! 2. Replay each mutation list from a clean state and check invariants after each step.
//! 3. If replay fails, reduce the operation list using a caller-provided cost model.
//!
//! This is meant for state-machine bugs where normal unit tests miss ordering edge cases, but the
//! whole failure can be reproduced from a list of small operations.

use rand::{Rng, SeedableRng, distr::Distribution, rngs::SmallRng};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::Debug,
    fs::{self, File},
    io::{self, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
};

include!("pipeline.rs");
include!("coverage.rs");
include!("coverage_guided.rs");
include!("reduce.rs");
include!("llvm_coverage.rs");
include!("parallel.rs");
include!("tests.rs");
