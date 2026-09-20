//! Supervisor-owned state of one execution: everything about the target that is not memory or
//! registers. Plain data, cloned into every snapshot and swapped back on restore.
//!
//! [`World`] is the composition: the scheduler ([`crate::sched::Sched`]), the path's coverage
//! and trace, the decision log, the oracle's evidence, and one field per installed model.

use crate::{
    model::{Coverage, Ext, ModelId},
    models::{entropy::Entropy, net::Net},
    oracle::Oracle,
    ptrace::Pid,
    sched::Sched,
};
use std::fmt;

pub use crate::model::WORLD_THREAD;
pub use crate::sched::{Thread, ThreadState};

/// Choices of a `Chunk` decision: deliver the rest, half of it, all but the last byte, or one
/// byte. The two edge splits are the segment boundaries real stacks mishandle: a body (or a
/// frame) whose last byte arrives late, and a header parser fed one byte at a time.
pub const CHUNK_CHOICES: u32 = 4;

/// A `Budget` decision's choice is the exact number of instrumented edges the thread runs
/// before it is preempted; 0 = run to its next natural stop. `n` is this bound.
pub const BUDGET_MAX: u32 = 1 << 24;

/// The decision vocabulary. Small and closed on purpose: a decision sequence is the test case,
/// and replay and shrinking only need to know a decision's arity, not its meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// Which runnable thread runs next, which timer fires, or which external event happens.
    Schedule,
    /// How many coverage edges the chosen thread runs before forced preemption (exact).
    Budget,
    /// The target's own `dowsing_target_rt::variant(n)`.
    Variant,
    /// Which corpus input an external actor (a peer) feeds the target.
    Payload,
    /// How much of its remaining input the actor delivers in one piece.
    Chunk,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Kind::Schedule => "sched",
            Kind::Budget => "budget",
            Kind::Variant => "variant",
            Kind::Payload => "payload",
            Kind::Chunk => "chunk",
        })
    }
}

/// One decision: `choice < n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Decision {
    pub kind: Kind,
    pub n: u32,
    pub choice: u32,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}/{}", self.kind, self.choice, self.n)
    }
}

/// A run's terminal state. The target process is still alive and fully stopped afterwards
/// (`exit_group` is not executed, crash signals are not delivered), so any snapshot stays
/// restorable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Outcome {
    Exited(i32),
    Signaled(i32),
    Deadlock {
        waiting: Vec<usize>,
    },
    /// The running thread did not reach a stop within the watchdog.
    Timeout,
    /// A thread panicked (the default hook's message appeared on stderr); the process may
    /// have survived it, as a runtime that catches task panics does.
    Panic,
    /// Every thread waits on the outside world and these peers' complete requests are
    /// unanswered with their connections still open.
    Hang {
        clients: Vec<usize>,
    },
    /// A protocol-level failure in what the target sent (e.g. an HTTP 5xx status).
    Protocol(String),
    /// Every thread waits on the outside world and the peers are done: a server's normal
    /// end state.
    Quiescent,
}

impl Outcome {
    pub fn is_ok(&self) -> bool {
        matches!(self, Outcome::Exited(0) | Outcome::Quiescent)
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Exited(code) => write!(f, "exit({code})"),
            Outcome::Signaled(sig) => write!(f, "signal({sig})"),
            Outcome::Deadlock { waiting } => write!(f, "deadlock(threads {waiting:?})"),
            Outcome::Timeout => write!(f, "timeout"),
            Outcome::Panic => write!(f, "panic"),
            Outcome::Hang { clients } => write!(f, "hang(clients {clients:?})"),
            Outcome::Protocol(what) => write!(f, "protocol({what})"),
            Outcome::Quiescent => write!(f, "quiescent"),
        }
    }
}

/// Where a thread's segment ended (see [`TraceEvent`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Point {
    Start,
    Clone,
    ThreadStart,
    FutexWait,
    FutexNoWait,
    FutexWake,
    FutexWoken,
    Timeout,
    Yield,
    Sleep,
    Woke,
    Clock,
    Getrandom,
    Variant,
    Preempt,
    Exit,
    ExitGroup,
    Signal(i32),
    Accept,
    EpollWait,
    EpollReady,
    EpollWoken,
    Wake,
    IoWait,
    IoWoken,
    Connect,
    ClientSend,
    ClientClose,
    /// Stopped because an oracle ended the run (e.g. a 5xx response).
    Oracle,
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Point::Signal(sig) => write!(f, "signal({sig})"),
            other => write!(f, "{}", format!("{other:?}").to_lowercase()),
        }
    }
}

/// One entry of the schedule trace: `thread` ran `edges` instrumented edges, the last of them
/// `guard`, and stopped at `point`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceEvent {
    pub thread: usize,
    pub point: Point,
    pub edges: u64,
    pub guard: u32,
}

/// One option of a `Schedule` decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Candidate {
    /// Resume this runnable thread.
    Run(usize),
    /// Advance the clock to this waiter's deadline and wake it with a timeout.
    Fire(usize),
    /// The world acts (a model injects an event).
    Ext(Ext),
}

/// A decision the session is waiting on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pending {
    Schedule {
        candidates: Vec<Candidate>,
    },
    Budget {
        thread: usize,
    },
    Variant {
        thread: usize,
        n: u32,
    },
    /// A model's own decision about one of its actors; answered by `Model::choose`.
    Model {
        model: ModelId,
        kind: Kind,
        actor: usize,
        n: u32,
    },
}

impl Pending {
    pub fn kind(&self) -> Kind {
        match self {
            Pending::Schedule { .. } => Kind::Schedule,
            Pending::Budget { .. } => Kind::Budget,
            Pending::Variant { .. } => Kind::Variant,
            Pending::Model { kind, .. } => *kind,
        }
    }

    pub fn n(&self) -> u32 {
        match self {
            Pending::Schedule { candidates } => candidates.len() as u32,
            Pending::Budget { .. } => BUDGET_MAX,
            Pending::Variant { n, .. } | Pending::Model { n, .. } => *n,
        }
    }
}

#[derive(Clone)]
pub struct World {
    pub sched: Sched,
    pub cov: Coverage,
    pub trace: Vec<TraceEvent>,
    pub decisions: Vec<Decision>,
    pub pending: Option<Pending>,
    pub outcome: Option<Outcome>,
    pub oracle: Oracle,
    pub entropy: Entropy,
    pub net: Net,
}

impl World {
    pub fn new(leader: Pid, net: Net) -> Self {
        Self {
            sched: Sched::new(leader),
            cov: Coverage::default(),
            trace: Vec::new(),
            decisions: Vec::new(),
            pending: None,
            outcome: None,
            oracle: Oracle::default(),
            entropy: Entropy::default(),
            net,
        }
    }

    pub fn trace_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::hash::DefaultHasher::new();
        self.trace.hash(&mut h);
        self.outcome.hash(&mut h);
        h.finish()
    }
}
