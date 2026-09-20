//! Deterministic virtual-time sandbox spike for dowsing.
//!
//! A target program is spawned under `ptrace` with a seccomp filter that traps only the
//! time-related syscalls.  The supervisor answers clock reads from a virtual clock, turns sleeps
//! and timed waits into parked threads, and advances the virtual clock only when every supervised
//! thread is blocked (or when the fuzzer decides to jump).  Non-determinism is drawn from a
//! dowsing [`iterator_fuzz::CaseRng`] so that `curious()` can explore time and `cautious()` can
//! shrink a failing schedule back toward natural behaviour.
//!
//! Linux x86-64 only.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

pub mod clock;
pub mod coverage;
pub mod ptrace;
pub mod sandbox;
pub mod seccomp;
mod waits;

pub use coverage::SandboxCoverage;
pub use sandbox::{Decisions, Outcome, RunReport, Sandbox, StopStats};
