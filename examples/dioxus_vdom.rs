//! Fuzz the Dioxus VirtualDom's **keyed list** diff path by streaming
//! incremental mutations into a tracking tree and asserting it stays
//! structurally equal to a fresh rebuild over the same model state.
//!
//! The component is intentionally narrow: a single keyed list of `Row`
//! components, each of which contains a nested keyed list. Every fuzz op
//! goes through `diff_keyed_children` somewhere.
//!
//! Run with `cargo run --release --example dioxus_vdom --features "dioxus rayon"`.
//!
//! Coverage-guided:
//!
//! ```sh
//! RUSTFLAGS="-Cinstrument-coverage" \
//!   FUZZ_COVERAGE=1 FUZZ_SEEDS=128 FUZZ_STEPS=128 FUZZ_COVERAGE_CASES=64 \
//!   cargo run --example dioxus_vdom --features "dioxus rayon llvm-coverage"
//! ```
#![allow(non_snake_case)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;

use dioxus::prelude::*;
use dioxus_core::{
    AttributeValue, ElementId, Mutations, ScopeId, Template, TemplateAttribute, TemplateNode,
    VirtualDom, WriteMutations,
};
use iterator_fuzz::{
    CaseIteratorExt, Fuzzer, Step, llvm_coverage::LlvmCoverage, parallel::ParCaseIteratorExt,
    replay_ops,
};
use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};
use rayon::iter::ParallelIterator;

// ---------- Model ---------------------------------------------------------------------------

include!("dioxus_vdom/model.rs");
include!("dioxus_vdom/tracking.rs");
include!("dioxus_vdom/runner.rs");
