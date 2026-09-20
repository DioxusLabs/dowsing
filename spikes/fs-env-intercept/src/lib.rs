//! `fs-env-intercept`: a seccomp user-notification sandbox that lets dowsing supply files,
//! directories, symlinks, environment variables, entropy and process identity to an unmodified
//! target running on the fuzz thread.
//!
//! See `DESIGN.md` for the rationale and `README.md` for the measured numbers.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

pub mod bpf;
pub mod draw;
pub mod entropy;
pub mod env;
pub mod fs;
pub mod identity;
pub mod mem;
pub mod notif;
pub mod spec;
pub mod supervisor;
pub mod vfs;

pub use draw::Draw;
pub use spec::{Content, EntropySpec, EnvSpec, IdentitySpec, NodeSpec, Spec, Uname};
pub use supervisor::{CaseReport, Sandbox};
