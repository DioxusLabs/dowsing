//! Out-of-process coverage + RNG bridge for dowsing (`iterator-fuzz`).
//!
//! The supervisor runs `curious()`/`cautious()` unchanged. Each case is executed by a
//! separate target process: the supervisor pre-fills the child's whole random byte budget in
//! shared memory, the child replays it through an ordinary `CaseRng`, and reports the consumed
//! prefix, structured spans, verdict, and SanitizerCoverage feedback back through the same
//! region. See `DESIGN.md` for the rationale and `README.md` for how to run the demo.

pub mod child;
pub mod shm;
pub mod supervisor;

/// File descriptor numbers the child inherits (AFL uses 198/199 for the same purpose).
pub const SHM_FD: i32 = 197;
pub const CTL_FD: i32 = 198;
pub const STATUS_FD: i32 = 199;

/// Environment variable that tells a target binary it is being supervised.
pub const MODE_ENV: &str = "COVERAGE_BRIDGE_MODE";
pub const MODE_FORK: &str = "fork";
pub const MODE_EXEC: &str = "exec";

/// Control-pipe request asking the forkserver to exit.
pub const REQUEST_EXIT: u32 = u32::MAX;

/// Result of one harness invocation in the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub failed: bool,
    pub cost: u64,
}

impl Verdict {
    pub const OK: Self = Self {
        failed: false,
        cost: 0,
    };

    pub fn ok() -> Self {
        Self::OK
    }

    pub fn failed() -> Self {
        Self {
            failed: true,
            cost: 0,
        }
    }

    pub fn with_cost(mut self, cost: u64) -> Self {
        self.cost = cost;
        self
    }
}

/// Which supervision mode a target binary was started in, decoded from the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildMode {
    Fork,
    Exec,
}

impl ChildMode {
    pub fn from_env() -> Option<Self> {
        match std::env::var(MODE_ENV).ok()?.as_str() {
            MODE_FORK => Some(Self::Fork),
            MODE_EXEC => Some(Self::Exec),
            _ => None,
        }
    }
}
