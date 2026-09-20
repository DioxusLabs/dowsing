//! dowsing-sandbox: deterministic tree search over decisions for real Linux processes.
//!
//! See `docs/DESIGN.md`. A [`Session`] supervises one target process (ptrace + seccomp
//! `RET_TRACE`), runs exactly one thread at a time, and hands every syscall that touches the
//! outside world to a [`model::Model`] (time, entropy, network) whose state lives in the
//! supervisor; the process can be snapshotted and restored with soft-dirty page tracking. A
//! [`tree::Search`] explores the tree of decisions from restored states.
//!
//! Module map:
//!
//! | layer | modules |
//! |---|---|
//! | process control | [`ptrace`], [`seccomp`], [`snapshot`], [`shm`] |
//! | core | [`session`] (lifecycle, events, schedule loop, snapshots), [`sched`], [`world`] |
//! | model boundary | [`model`] (`Model`, `Cx`, `Emu`, `Filter`, `Prior`) |
//! | models | [`models::time`], [`models::entropy`], [`models::net`] (+ `Protocol`, `Http1`) |
//! | verdicts | [`oracle`] |
//! | search | [`tree`] |

pub mod model;
pub mod models;
pub mod oracle;
pub mod ptrace;
pub mod sched;
pub mod seccomp;
pub mod session;
pub mod shm;
pub mod snapshot;
pub mod tree;
pub mod world;

pub use models::net;
pub use session::{Event, Options, Session};
pub use tree::{Budget, Search, Stats};
pub use world::{Decision, Kind, Outcome, Point};
