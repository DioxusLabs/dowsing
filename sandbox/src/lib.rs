//! dowsing-sandbox: deterministic tree search over decisions for real Linux processes.
//!
//! See `docs/DESIGN.md`. A [`Session`] supervises one target process (ptrace + seccomp
//! `RET_TRACE`), runs exactly one thread at a time, answers clocks/sleeps/futexes/entropy
//! itself, and can snapshot/restore the process with soft-dirty page tracking. A
//! [`tree::Search`] explores the tree of decisions from restored states.

pub mod ptrace;
pub mod seccomp;
pub mod session;
pub mod shm;
pub mod snapshot;
pub mod tree;
pub mod world;

pub use session::{Event, Options, Session};
pub use tree::{Budget, Search, Stats};
pub use world::{Decision, Kind, Outcome};
