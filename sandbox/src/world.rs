//! Supervisor-owned state of one execution: everything about the target that is not memory or
//! registers. Plain data, cloned into every snapshot and swapped back on restore.

use crate::{ptrace::Pid, shm::Bitmap};
use std::fmt;

/// Edge budgets selectable at a `Budget` decision; index 0 = run to the next syscall.
pub const BUDGET_TABLE: &[u32] = &[0, 1, 2, 4, 8, 16, 32, 64, 128, 512];

/// Virtual `CLOCK_MONOTONIC` at process start (1 s, so it is never zero).
pub const CLOCK_START_NS: u64 = 1_000_000_000;
/// Virtual time consumed by one clock read.
pub const CLOCK_TICK_NS: u64 = 1_000;
/// Virtual `CLOCK_REALTIME` base: 2026-01-01T00:00:00Z.
pub const REALTIME_BASE_NS: u64 = 1_767_225_600 * 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// Which runnable thread runs next (or which timed waiter's timeout fires).
    Schedule,
    /// How many coverage edges the chosen thread may run before forced preemption.
    Budget,
    /// The target's own `dowsing_target_rt::variant(n)`.
    Variant,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Kind::Schedule => "sched",
            Kind::Budget => "budget",
            Kind::Variant => "variant",
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
}

impl Outcome {
    pub fn is_ok(&self) -> bool {
        matches!(self, Outcome::Exited(0))
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Exited(code) => write!(f, "exit({code})"),
            Outcome::Signaled(sig) => write!(f, "signal({sig})"),
            Outcome::Deadlock { waiting } => write!(f, "deadlock(threads {waiting:?})"),
            Outcome::Timeout => write!(f, "timeout"),
        }
    }
}

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
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Point::Signal(sig) => write!(f, "signal({sig})"),
            other => write!(f, "{}", format!("{other:?}").to_lowercase()),
        }
    }
}

/// One entry of the schedule trace: `thread` ran `edges` instrumented edges and stopped at `point`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceEvent {
    pub thread: usize,
    pub point: Point,
    pub edges: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// In a ptrace stop, runnable.
    Stopped,
    Running,
    /// Emulated futex wait; the syscall was skipped with `rax = 0` already written.
    FutexWait {
        addr: u64,
        val: u32,
        bitset: u32,
        deadline: Option<u64>,
        seq: u64,
    },
    /// Emulated `nanosleep`.
    Sleep {
        deadline: u64,
        seq: u64,
    },
    /// Called `exit`; the syscall was skipped and the task is frozen forever. Kept so that
    /// snapshots taken while it was alive stay restorable.
    Parked,
}

impl ThreadState {
    pub fn deadline(&self) -> Option<u64> {
        match self {
            ThreadState::FutexWait { deadline, .. } => *deadline,
            ThreadState::Sleep { deadline, .. } => Some(*deadline),
            _ => None,
        }
    }

    pub fn seq(&self) -> u64 {
        match self {
            ThreadState::FutexWait { seq, .. } | ThreadState::Sleep { seq, .. } => *seq,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Thread {
    pub tid: Pid,
    pub state: ThreadState,
    /// `CLONE_CHILD_CLEARTID` address: zeroed and woken when the thread exits.
    pub clear_tid: u64,
    /// `child_tid` of a `clone` this thread is in the middle of.
    pub pending_clone_ctid: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Candidate {
    /// Resume this runnable thread.
    Run(usize),
    /// Advance the clock to this waiter's deadline and wake it with a timeout.
    Fire(usize),
}

/// A decision the session is waiting on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pending {
    Schedule { candidates: Vec<Candidate> },
    Budget { thread: usize },
    Variant { thread: usize, n: u32 },
}

impl Pending {
    pub fn kind(&self) -> Kind {
        match self {
            Pending::Schedule { .. } => Kind::Schedule,
            Pending::Budget { .. } => Kind::Budget,
            Pending::Variant { .. } => Kind::Variant,
        }
    }

    pub fn n(&self) -> u32 {
        match self {
            Pending::Schedule { candidates } => candidates.len() as u32,
            Pending::Budget { .. } => BUDGET_TABLE.len() as u32,
            Pending::Variant { n, .. } => *n,
        }
    }
}

#[derive(Clone)]
pub struct World {
    pub threads: Vec<Thread>,
    pub current: Option<usize>,
    pub last_ran: Option<usize>,
    pub clock_ns: u64,
    pub wait_seq: u64,
    pub entropy_seq: u64,
    /// Coverage bits set along this path.
    pub coverage: Bitmap,
    pub edges: u64,
    pub edges_at_last_event: u64,
    pub trace: Vec<TraceEvent>,
    pub decisions: Vec<Decision>,
    pub pending: Option<Pending>,
    pub outcome: Option<Outcome>,
}

impl World {
    pub fn new(leader: Pid) -> Self {
        Self {
            threads: vec![Thread {
                tid: leader,
                state: ThreadState::Stopped,
                clear_tid: 0,
                pending_clone_ctid: 0,
            }],
            current: None,
            last_ran: None,
            clock_ns: CLOCK_START_NS,
            wait_seq: 0,
            entropy_seq: 0,
            coverage: Bitmap::default(),
            edges: 0,
            edges_at_last_event: 0,
            trace: Vec::new(),
            decisions: Vec::new(),
            pending: None,
            outcome: None,
        }
    }

    pub fn thread_index(&self, tid: Pid) -> Option<usize> {
        self.threads.iter().position(|t| t.tid == tid)
    }

    pub fn runnable(&self) -> Vec<usize> {
        self.threads
            .iter()
            .enumerate()
            .filter(|(_, t)| t.state == ThreadState::Stopped)
            .map(|(i, _)| i)
            .collect()
    }

    pub fn timed_waiters(&self) -> Vec<usize> {
        let mut v: Vec<(u64, u64, usize)> = self
            .threads
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.state.deadline().map(|d| (d, t.state.seq(), i)))
            .collect();
        v.sort();
        v.into_iter().map(|(_, _, i)| i).collect()
    }

    pub fn waiters(&self) -> Vec<usize> {
        self.threads
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                matches!(
                    t.state,
                    ThreadState::FutexWait { .. } | ThreadState::Sleep { .. }
                )
            })
            .map(|(i, _)| i)
            .collect()
    }

    pub fn trace_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::hash::DefaultHasher::new();
        self.trace.hash(&mut h);
        self.outcome.hash(&mut h);
        h.finish()
    }
}
