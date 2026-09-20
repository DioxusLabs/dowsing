//! The boundary between the supervisor core and the models of the outside world.
//!
//! The core owns the process: ptrace, the thread table and scheduler, futex/clone/exit,
//! coverage, snapshots and the decision log. Everything the target could observe *about the
//! world* (clocks, entropy, sockets, later files and environment) is a [`Model`]: plain data
//! that lives in [`crate::world::World`] and is cloned into every snapshot, plus the syscall
//! semantics over that data. A model
//!
//! - declares which syscalls the single seccomp filter must stop for it ([`Model::FILTER`]);
//! - emulates a stopped syscall against its state ([`Model::syscall`]), through a [`Cx`] that
//!   exposes the target's memory and registers and the scheduler's thread table;
//! - may offer *events*: things the world could do on its own (a peer connecting, bytes
//!   arriving) that the search schedules next to the target's threads ([`Model::events`],
//!   [`Model::act`]);
//! - may own decision kinds of its own ([`Model::choose`]), e.g. which corpus input a peer
//!   sends;
//! - may report a failure that only it can see once the target is idle ([`Model::idle`]).
//!
//! Models never talk to each other or to the search directly; the search sees only
//! [`Candidate`]s tagged with a [`Prior`] class and decisions tagged with a [`Kind`].

use crate::{
    ptrace::{self, Pid, Regs},
    sched::Sched,
    session::Options,
    shm::{Bitmap, Shm},
    world::{Kind, Outcome, Pending, Point, ThreadState, TraceEvent},
};
use std::io;

/// Descriptors handed out by models are numbered from here so the seccomp filter can tell them
/// from the kernel's by the first syscall argument alone.
pub const VFD_BASE: i32 = 4096;

/// `TraceEvent::thread` of an event caused by the world (a model acting) rather than a thread.
pub const WORLD_THREAD: usize = usize::MAX;

/// Identifies a model in candidates, pending decisions and wait states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ModelId {
    Time,
    Entropy,
    Net,
}

/// What the seccomp filter stops for one model. Both lists are syscall numbers; `vfd` ones
/// stop only when `arg0 >= VFD_BASE`.
#[derive(Debug, Clone, Copy)]
pub struct Filter {
    pub always: &'static [libc::c_long],
    pub vfd: &'static [libc::c_long],
}

impl Filter {
    pub const EMPTY: Filter = Filter {
        always: &[],
        vfd: &[],
    };

    pub fn traces(&self, nr: libc::c_long) -> bool {
        self.always.contains(&nr) || self.vfd.contains(&nr)
    }
}

/// Result of emulating one syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emu {
    /// Skipped with this result; the thread runs on (nothing another thread can observe changed).
    Ret(i64),
    /// Skipped with this result; the thread stops here as a schedule point.
    Stop(i64, Point),
    /// Skipped (the result is written when the wait ends); the thread waits in `state` until
    /// the model completes it or its deadline fires. The model keeps what it needs to retry
    /// in `Thread::blocked`.
    Wait(ThreadState, Point),
    /// Not modelled: the kernel runs it and the run is reported as uncontrolled.
    Pass,
    /// Touches only kernel state and cannot block: the kernel runs it, nothing to report.
    Kernel,
}

/// How the rollout policy ranks an external event against the target's threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Prior {
    /// The next step of an existing actor (a peer's next delivery): its own PCT priority,
    /// demoted when the search splits its input.
    Actor(usize),
    /// A new actor appears (a peer connects): one priority per rollout.
    Spawn,
    /// Only when nothing else can happen (a peer hangs up); the search tries it earlier as an
    /// untried sibling.
    Last,
}

/// An event a model can inject, as offered to the scheduler. `op` and `actor` mean whatever
/// the owning model says; the core only routes the event back to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ext {
    pub model: ModelId,
    pub op: u8,
    pub actor: u32,
    pub prior: Prior,
}

/// A source of observable nondeterminism, emulated by the supervisor.
pub trait Model {
    const ID: ModelId;
    const FILTER: Filter;

    /// A seccomp stop on one of `FILTER`'s syscalls by `thread`, whose entry registers are
    /// `regs`. The core applies the returned [`Emu`].
    fn syscall(&mut self, cx: &mut Cx, thread: usize, regs: &Regs) -> io::Result<Emu>;

    /// Events the world could inject now, offered as schedule candidates.
    fn events(&self, _cx: &Cx) -> Vec<Ext> {
        Vec::new()
    }

    /// The scheduler picked one of this model's events.
    fn act(&mut self, _cx: &mut Cx, ev: Ext) -> io::Result<()> {
        Err(io::Error::other(format!("{ev:?}: model has no events")))
    }

    /// Answer one of this model's own pending decisions (`Pending::Model`).
    fn choose(&mut self, _cx: &mut Cx, kind: Kind, _actor: usize, _choice: u32) -> io::Result<()> {
        Err(io::Error::other(format!("{kind}: model has no decisions")))
    }

    /// Nothing is runnable and no timer is left to fire: a failure only this model can see.
    fn idle(&self, _cx: &Cx) -> Option<Outcome> {
        None
    }
}

/// The core, as seen by a model during one call: the target's memory and registers, the
/// scheduler's thread table, and the run's trace and verdict.
pub struct Cx<'a> {
    pub leader: Pid,
    pub opts: &'a Options,
    pub sched: &'a mut Sched,
    pub pending: &'a mut Option<Pending>,
    pub outcome: &'a mut Option<Outcome>,
    pub uncontrolled: &'a mut Vec<String>,
    pub(crate) rec: Recorder<'a>,
}

/// The parts of the core that turn a stop into a trace event: the coverage mapping, the
/// path's coverage and trace, and the stderr pipe (for the panic oracle).
pub(crate) struct Recorder<'a> {
    pub shm: &'a Shm,
    pub cov: &'a mut Coverage,
    pub trace: &'a mut Vec<TraceEvent>,
    pub new_coverage: &'a mut Vec<u32>,
    pub stderr: &'a mut crate::oracle::Stderr,
    pub oracle: &'a mut crate::oracle::Oracle,
}

/// Coverage state of one path (mirrors the shared mapping at the last trace event).
#[derive(Clone, Default)]
pub struct Coverage {
    /// Bits set along this path.
    pub bitmap: Bitmap,
    /// Total instrumented edges executed.
    pub edges: u64,
    pub edges_at_last_event: u64,
    /// Id of the most recently executed edge.
    pub guard: u32,
}

impl Cx<'_> {
    /// Close the segment the running thread just executed with a trace event at `point`.
    pub fn record(&mut self, thread: usize, point: Point) {
        self.rec.stderr.poll(self.rec.oracle);
        let cov = &mut *self.rec.cov;
        let edges_now = self.rec.shm.edges();
        let edges = edges_now - cov.edges_at_last_event;
        cov.edges_at_last_event = edges_now;
        cov.edges = edges_now;
        let guard = self.rec.shm.guard();
        cov.guard = guard;
        let fresh = self.rec.shm.drain_bitmap(&mut cov.bitmap);
        self.rec.new_coverage.extend(fresh);
        self.rec.trace.push(TraceEvent {
            thread,
            point,
            edges,
            guard,
        });
        if self.opts.verbose {
            eprintln!("[sandbox] T{thread} ran {edges} edges -> {point}");
        }
    }

    /// Stop `thread` (which was running, or is being answered) at a schedule point.
    pub fn stop_here(&mut self, thread: usize, point: Point) {
        self.sched.threads[thread].state = ThreadState::Stopped;
        if self.sched.current == Some(thread) {
            self.sched.current = None;
        }
        self.record(thread, point);
    }

    /// Complete a stopped thread's skipped syscall with `value` (it stays stopped).
    pub fn set_return(&mut self, thread: usize, value: i64) -> io::Result<()> {
        let tid = self.sched.threads[thread].tid;
        let mut regs = ptrace::getregs(tid)?;
        regs.rax = value as u64;
        regs.orig_rax = u64::MAX;
        ptrace::setregs(tid, &regs)
    }

    /// End a thread's wait: write `value`, make it runnable, record `point`.
    pub fn wake(&mut self, thread: usize, value: i64, point: Point) -> io::Result<()> {
        self.set_return(thread, value)?;
        let t = &mut self.sched.threads[thread];
        t.blocked = None;
        t.state = ThreadState::Stopped;
        self.record(thread, point);
        Ok(())
    }

    pub fn now(&self) -> u64 {
        self.sched.clock_ns
    }

    pub fn read_mem(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        ptrace::read_mem(self.leader, addr, buf)
    }

    pub fn write_mem(&self, addr: u64, buf: &[u8]) -> io::Result<()> {
        ptrace::write_mem(self.leader, addr, buf)
    }

    pub fn read_u32(&self, addr: u64) -> io::Result<u32> {
        ptrace::read_u32(self.leader, addr)
    }

    pub fn read_u64(&self, addr: u64) -> io::Result<u64> {
        ptrace::read_u64(self.leader, addr)
    }

    pub fn write_u32(&self, addr: u64, v: u32) -> io::Result<()> {
        ptrace::write_u32(self.leader, addr, v)
    }

    pub fn write_u64(&self, addr: u64, v: u64) -> io::Result<()> {
        ptrace::write_u64(self.leader, addr, v)
    }

    /// `struct timespec` at `addr` as nanoseconds (0 for a null pointer).
    pub fn read_timespec_ns(&self, addr: u64) -> io::Result<u64> {
        if addr == 0 {
            return Ok(0);
        }
        let secs = self.read_u64(addr)? as i64;
        let nanos = self.read_u64(addr + 8)? as i64;
        Ok((secs.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nanos.max(0) as u64))
    }

    pub fn write_timespec(&self, addr: u64, ns: u64) -> io::Result<()> {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&((ns / 1_000_000_000) as i64).to_ne_bytes());
        buf[8..].copy_from_slice(&((ns % 1_000_000_000) as i64).to_ne_bytes());
        self.write_mem(addr, &buf)
    }

    /// Note a syscall the model left to the kernel.
    pub fn uncontrolled(&mut self, msg: String) {
        self.uncontrolled.push(msg);
    }
}
