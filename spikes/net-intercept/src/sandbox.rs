//! `Sandbox::run(&mut CaseRng, target) -> Verdict`: fork the target, supervise its networking,
//! and report what happened.

use std::{io, time::Duration};

use iterator_fuzz::{CaseRng, coverage::CoverageCapture};

use crate::{
    bpf,
    child::{self, ExitStatus},
    coverage::{ChildCoverage, ChildReport},
    peer_model::{PayloadGen, random_payload},
    supervisor::NetSupervisor,
};

pub struct SandboxConfig {
    /// Upper bound of the `range` that drives the exchange (number of peer decisions).
    pub max_events: usize,
    /// Wall-clock budget per case; the child is SIGKILLed after it.
    pub timeout: Duration,
    pub sync_wake_up: bool,
    /// Print every peer decision / unhandled syscall as it happens.
    pub verbose: bool,
    /// Silence the child's panic message (the harness reports it from the verdict instead).
    pub quiet_child: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_events: 16,
            timeout: Duration::from_secs(2),
            sync_wake_up: true,
            verbose: false,
            quiet_child: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Target returned normally.
    Ok,
    /// Target panicked (caught in the child); message if available.
    Panicked(Option<String>),
    /// Child died by signal (SIGSEGV, SIGABRT from `panic=abort`, ...).
    Signaled(i32),
    /// Child exited with a nonzero code without a caught panic.
    Exited(i32),
    /// Case budget exceeded.
    TimedOut,
    /// The supervisor itself failed.
    SupervisorError(String),
}

impl Outcome {
    pub fn is_bug(&self) -> bool {
        matches!(self, Outcome::Panicked(_) | Outcome::Signaled(_) | Outcome::Exited(_))
    }
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub outcome: Outcome,
    /// Human-readable peer decisions in order.
    pub transcript: Vec<String>,
    /// Number of `range` items consumed (the cost handed to `coverage_with_cost`).
    pub decisions: usize,
    pub unhandled: Vec<String>,
    /// Notifications handled / of which continued into the kernel.
    pub syscalls: u64,
    pub continued: u64,
    pub sync_wake_up: bool,
    /// Bytes the target sent per fake fd.
    pub sent: Vec<(i32, Vec<u8>)>,
    pub coverage_features: usize,
}

impl Verdict {
    pub fn transcript_string(&self) -> String {
        self.transcript.join("\n")
    }
}

pub struct Sandbox {
    config: SandboxConfig,
    coverage: ChildCoverage,
    /// Called once per case; the generator is moved into that case's supervisor.
    payload_factory: Box<dyn Fn() -> PayloadGen>,
}

impl Sandbox {
    pub fn new(config: SandboxConfig) -> io::Result<Self> {
        Ok(Self {
            config,
            coverage: ChildCoverage::new()?,
            payload_factory: Box::new(random_payload),
        })
    }

    /// Replace the `Data` payload generator (a factory so each case gets a fresh closure).
    pub fn with_payload(mut self, factory: impl Fn() -> PayloadGen + 'static) -> Self {
        self.payload_factory = Box::new(factory);
        self
    }

    /// The `CoverageCapture` to hand to `curious().with_coverage(...)`.
    pub fn coverage(&self) -> ChildCoverage {
        self.coverage.clone()
    }

    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Run one case: fork `target`, play its peers from `rng`, and report.
    pub fn run<C: CoverageCapture>(&mut self, rng: &mut CaseRng<C>, target: impl FnOnce()) -> Verdict {
        // CaseRng starts capture lazily on the first draw: make sure that happens in the parent,
        // before fork, so the shared region is reset for this case.
        let _ = rng.variant(1);
        let events = rng.range(0..=self.config.max_events);
        let payload = (self.payload_factory)();
        let mut sup = NetSupervisor::new(events, payload, self.config.verbose);

        let coverage = self.coverage.clone();
        let quiet = self.config.quiet_child;
        let spawned = child::spawn(&bpf::network_rules(), self.config.sync_wake_up, move || {
            if quiet {
                std::panic::set_hook(Box::new(|_| {}));
            }
            let panicked = coverage.child_run(target);
            if panicked { 101 } else { 0 }
        });
        let mut spawned = match spawned {
            Ok(s) => s,
            Err(e) => {
                return Verdict {
                    outcome: Outcome::SupervisorError(format!("spawn failed: {e}")),
                    transcript: Vec::new(),
                    decisions: 0,
                    unhandled: Vec::new(),
                    syscalls: 0,
                    continued: 0,
                    sync_wake_up: false,
                    sent: Vec::new(),
                    coverage_features: 0,
                };
            }
        };
        let sync_wake_up = spawned.sync_wake_up;
        let status = spawned.serve(self.config.timeout, |n| sup.handle(n));
        let (_, report): (_, ChildReport) = self.coverage.read();
        let outcome = match status {
            Ok(ExitStatus::Exited(0)) => Outcome::Ok,
            Ok(ExitStatus::Exited(101)) => Outcome::Panicked(report.panic_message.clone()),
            Ok(ExitStatus::Exited(code)) => Outcome::Exited(code),
            Ok(ExitStatus::Signaled(sig)) => Outcome::Signaled(sig),
            Ok(ExitStatus::TimedOut) => Outcome::TimedOut,
            Err(e) => Outcome::SupervisorError(e.to_string()),
        };
        let sent = sup.sent();
        Verdict {
            outcome,
            transcript: std::mem::take(&mut sup.transcript),
            decisions: sup.decisions,
            unhandled: std::mem::take(&mut sup.unhandled),
            syscalls: sup.syscalls,
            continued: sup.continued,
            sync_wake_up,
            sent,
            coverage_features: report.feature_count,
        }
    }
}
