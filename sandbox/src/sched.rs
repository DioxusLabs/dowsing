//! The scheduler's state: the thread table, which thread runs, and virtual time. One thread runs
//! at a time; every other thread is in a ptrace stop, either runnable or waiting on a futex, a
//! sleep, or something a model owns.

use crate::{
    model::ModelId,
    ptrace::{Pid, Regs},
};

/// Virtual `CLOCK_MONOTONIC` at process start (1 s, so it is never zero).
pub const CLOCK_START_NS: u64 = 1_000_000_000;
/// Virtual time consumed by one clock read.
pub const CLOCK_TICK_NS: u64 = 1_000;
/// Virtual `CLOCK_REALTIME` base: 2026-01-01T00:00:00Z.
pub const REALTIME_BASE_NS: u64 = 1_767_225_600 * 1_000_000_000;
/// Timeouts fired with nothing else happening before an idle run is declared over.
pub const MAX_IDLE_FIRES: u32 = 256;

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
    /// A blocking operation `model` owns (its entry registers in `Thread::blocked`) that would
    /// block; the model retries it when its world changes, or it times out at `deadline`.
    Wait {
        model: ModelId,
        deadline: Option<u64>,
        seq: u64,
    },
}

impl ThreadState {
    pub fn deadline(&self) -> Option<u64> {
        match self {
            ThreadState::FutexWait { deadline, .. } | ThreadState::Wait { deadline, .. } => {
                *deadline
            }
            ThreadState::Sleep { deadline, .. } => Some(*deadline),
            _ => None,
        }
    }

    pub fn seq(&self) -> u64 {
        match self {
            ThreadState::FutexWait { seq, .. }
            | ThreadState::Sleep { seq, .. }
            | ThreadState::Wait { seq, .. } => *seq,
            _ => 0,
        }
    }

    /// Waiting for something only the modelled outside world can provide.
    pub fn waits_on_world(&self) -> bool {
        matches!(self, ThreadState::Wait { .. })
    }

    pub fn is_waiting(&self) -> bool {
        matches!(
            self,
            ThreadState::FutexWait { .. } | ThreadState::Sleep { .. } | ThreadState::Wait { .. }
        )
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
    /// Entry registers of the syscall a `Wait` retries.
    pub blocked: Option<Regs>,
}

impl Thread {
    pub fn new(tid: Pid) -> Self {
        Self {
            tid,
            state: ThreadState::Stopped,
            clear_tid: 0,
            pending_clone_ctid: 0,
            blocked: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Sched {
    pub threads: Vec<Thread>,
    pub current: Option<usize>,
    pub last_ran: Option<usize>,
    /// Virtual `CLOCK_MONOTONIC`; advances only by clock reads and fired timers.
    pub clock_ns: u64,
    /// Orders waiters of equal deadline (FIFO).
    pub wait_seq: u64,
    /// Timeouts fired with nothing runnable since the last time a thread ran or the world
    /// acted; bounds the virtual time an idle server with periodic timers can burn.
    pub idle_fires: u32,
}

impl Sched {
    pub fn new(leader: Pid) -> Self {
        Self {
            threads: vec![Thread::new(leader)],
            current: None,
            last_ran: None,
            clock_ns: CLOCK_START_NS,
            wait_seq: 0,
            idle_fires: 0,
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

    /// Threads with a deadline, earliest first.
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
            .filter(|(_, t)| t.state.is_waiting())
            .map(|(i, _)| i)
            .collect()
    }

    pub fn any_running(&self) -> bool {
        self.threads.iter().any(|t| t.state == ThreadState::Running)
    }

    pub fn next_seq(&mut self) -> u64 {
        self.wait_seq += 1;
        self.wait_seq
    }

    /// Every read advances the clock by one tick so a program that computes
    /// `deadline = now + 0` and re-reads the clock observes progress.
    pub fn clock_read(&mut self, clock: i32) -> u64 {
        self.clock_ns += CLOCK_TICK_NS;
        match clock {
            libc::CLOCK_REALTIME | libc::CLOCK_REALTIME_COARSE | libc::CLOCK_TAI => {
                REALTIME_BASE_NS + (self.clock_ns - CLOCK_START_NS)
            }
            _ => self.clock_ns,
        }
    }

    /// A `CLOCK_REALTIME` instant as a monotonic deadline.
    pub fn realtime_to_monotonic(ns: u64) -> u64 {
        ns.saturating_sub(REALTIME_BASE_NS)
            .saturating_add(CLOCK_START_NS)
    }
}
