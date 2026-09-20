//! Deterministic, fuzzer-controlled scheduling of multithreaded Linux targets.
//!
//! * [`supervisor`]: ptrace + seccomp control plane, futex emulation, edge-budget preemption.
//! * [`shm`]: the mapping shared with the target and the [`shm::ShmCoverage`] dowsing backend.
//! * [`dowsing`]: `CaseRng` -> [`supervisor::Scheduler`] adapter.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

pub mod dowsing;
pub mod ptrace;
pub mod seccomp;
pub mod shm;
pub mod supervisor;

pub use dowsing::{CaseScheduler, MAX_DECISIONS};
pub use shm::{Shm, ShmCoverage};
pub use supervisor::{
    BUDGET_TABLE, Decision, FifoScheduler, Outcome, PointKind, RunReport, Scheduler, Supervisor,
    TraceEvent,
};
