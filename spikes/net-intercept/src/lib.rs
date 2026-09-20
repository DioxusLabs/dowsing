//! `net-intercept`: seccomp user-notification supervision of a forked target's networking, with
//! every remote peer played by dowsing's `CaseRng`.
//!
//! Layers (bottom up):
//! - [`notif`]: uapi wrappers (seccomp ioctls, pidfd, process_vm_*).
//! - [`bpf`]: the classic-BPF filter (fd >= 1000 discriminates fake sockets from files).
//! - [`child`]: fork + filter install + listener handoff + notification loop.
//! - [`fake_socket`], [`peer_model`], [`dns`], [`supervisor`]: the network emulation.
//! - [`coverage`]: `ChildCoverage`, a `CoverageCapture` that reads sancov feedback the child
//!   serialised into a `MAP_SHARED` region.
//! - [`sandbox`]: `Sandbox::run(&mut CaseRng, target) -> Verdict`, the harness entry point.

pub mod bpf;
pub mod child;
pub mod coverage;
pub mod dns;
pub mod fake_socket;
pub mod notif;
pub mod peer_model;
pub mod sandbox;
pub mod supervisor;

pub use child::{ExitStatus, Features, probe_features};
pub use coverage::ChildCoverage;
pub use peer_model::{ByteSource, PayloadGen, PeerEvent, random_payload};
pub use sandbox::{Outcome, Sandbox, SandboxConfig, Verdict};
