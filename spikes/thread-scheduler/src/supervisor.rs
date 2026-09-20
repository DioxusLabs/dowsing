//! The supervisor: forks/execs a target with the seccomp filter, seizes it with ptrace and then
//! lets exactly one thread run at a time. Every stop of the running thread is a *scheduling
//! point*; a [`Scheduler`] decides which stopped thread runs next and for how many edges.
//!
//! Futex WAIT/WAKE are emulated (the syscall is skipped with `orig_rax = -1` and the return value
//! is written into `rax` at the seccomp stop, which the x86_64 entry path preserves for nr == -1).

use crate::{
    ptrace::{self, Pid, Regs, WaitEvent},
    seccomp,
    shm::{ENV_SHM_FD, MARKER_MAGIC, MARKER_SYSCALL, Shm},
};
use std::{
    ffi::CString,
    fmt,
    hash::{Hash, Hasher},
    io,
    os::fd::AsRawFd,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Edge budgets selectable at a scheduling point; index 0 = no preemption.
pub const BUDGET_TABLE: &[u32] = &[
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 1024, 2048, 4096,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointKind {
    Start,
    Clone,
    ThreadStart,
    FutexWait,
    FutexNoWait,
    FutexWake,
    FutexWoken,
    FutexTimeout,
    Yield,
    Sleep,
    Getrandom,
    Preempt,
    Exit,
    Signal(i32),
}

impl fmt::Display for PointKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PointKind::Signal(sig) => write!(f, "signal({sig})"),
            other => write!(f, "{}", format!("{other:?}").to_lowercase()),
        }
    }
}

/// One entry of the schedule trace: thread `thread` ran `edges` instrumented edges and then
/// stopped at `kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceEvent {
    pub thread: usize,
    pub kind: PointKind,
    pub edges: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Index into the candidate list (`0` = keep running the current / lowest-index thread).
    pub pick: usize,
    /// Index into [`BUDGET_TABLE`] (`0` = run to the next syscall).
    pub budget: usize,
}

/// Source of scheduling decisions.
pub trait Scheduler {
    /// `candidates` is the number of runnable threads (>= 2); the current thread, if runnable,
    /// is candidate 0, the rest follow in creation order.
    fn decide(&mut self, candidates: usize) -> Decision;
    /// Bytes to answer a `getrandom(len)` with.
    fn random_bytes(&mut self, len: usize) -> Vec<u8>;
}

/// Always run the current/lowest-index thread to its next syscall.
pub struct FifoScheduler;

impl Scheduler for FifoScheduler {
    fn decide(&mut self, _candidates: usize) -> Decision {
        Decision { pick: 0, budget: 0 }
    }
    fn random_bytes(&mut self, len: usize) -> Vec<u8> {
        vec![0x42; len]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Exited(i32),
    Signaled(i32),
    /// No thread runnable, no running thread, emulated futex waiters remain.
    Deadlock {
        waiting_threads: Vec<usize>,
    },
    /// The running thread did not stop within the watchdog timeout.
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
            Outcome::Deadlock { waiting_threads } => {
                write!(f, "deadlock(waiting threads {waiting_threads:?})")
            }
            Outcome::Timeout => write!(f, "timeout"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunReport {
    pub outcome: Outcome,
    pub trace: Vec<TraceEvent>,
    pub decisions: Vec<Decision>,
    /// Number of ptrace stops handled (scheduling points + bookkeeping stops).
    pub stops: usize,
    pub edges: u64,
    pub threads: usize,
    pub wall: Duration,
    pub uncontrolled: Vec<String>,
    pub stderr: String,
}

impl RunReport {
    pub fn trace_hash(&self) -> u64 {
        let mut hasher = std::hash::DefaultHasher::new();
        self.trace.hash(&mut hasher);
        self.outcome.to_string().hash(&mut hasher);
        hasher.finish()
    }

    pub fn non_zero_decisions(&self) -> usize {
        self.decisions
            .iter()
            .map(|d| usize::from(d.pick != 0) + usize::from(d.budget != 0))
            .sum()
    }

    pub fn scheduling_points(&self) -> usize {
        self.trace.len()
    }

    /// Human readable schedule.
    pub fn describe(&self) -> String {
        let mut out = String::new();
        for (i, ev) in self.trace.iter().enumerate() {
            out.push_str(&format!(
                "  {i:>3}: T{} ran {:>6} edges -> {}\n",
                ev.thread, ev.edges, ev.kind
            ));
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Created by the parent's clone but its initial stop has not been seen yet.
    Starting,
    /// In a ptrace stop, ready to be resumed.
    Stopped,
    Running,
    /// Emulated futex wait (syscall skipped, `rax` already set to 0).
    FutexWait {
        addr: u64,
        val: u32,
        bitset: u32,
        timed: bool,
        seq: u64,
    },
    /// Passed `PTRACE_EVENT_EXIT`, waiting for the kernel to reap it.
    Exiting,
    Exited,
}

#[derive(Debug)]
struct Thread {
    tid: Pid,
    state: State,
    /// Signal to deliver on the next resume.
    pending_signal: i32,
}

static ALARM_FIRED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_alarm(_sig: libc::c_int) {
    ALARM_FIRED.store(true, Ordering::SeqCst);
}

fn install_alarm_handler() {
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_alarm as extern "C" fn(libc::c_int) as usize;
        action.sa_flags = 0; // no SA_RESTART: waitpid must fail with EINTR
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut());
    }
}

pub struct Supervisor {
    shm: Rc<Shm>,
    program: CString,
    args: Vec<CString>,
    pub watchdog: Duration,
    pub verbose: bool,
    /// Capture the target's stderr into the report instead of letting it through.
    pub capture_stderr: bool,
}

struct Run<'s, S: Scheduler> {
    sup: &'s Supervisor,
    sched: &'s mut S,
    leader: Pid,
    threads: Vec<Thread>,
    current: Option<usize>,
    last_ran: Option<usize>,
    trace: Vec<TraceEvent>,
    decisions: Vec<Decision>,
    stops: usize,
    edges_at_last_event: u64,
    futex_seq: u64,
    uncontrolled: Vec<String>,
    /// Initial stops of threads whose clone event has not been processed yet.
    orphan_stops: Vec<Pid>,
    outcome: Option<Outcome>,
}

impl Supervisor {
    pub fn new(shm: Rc<Shm>, program: &str, args: &[String]) -> Self {
        Self {
            shm,
            program: CString::new(program).expect("program path"),
            args: args
                .iter()
                .map(|a| CString::new(a.as_str()).expect("arg"))
                .collect(),
            watchdog: Duration::from_secs(5),
            verbose: false,
            capture_stderr: true,
        }
    }

    pub fn shm(&self) -> &Rc<Shm> {
        &self.shm
    }

    /// Run the target once under `sched`.
    pub fn run<S: Scheduler>(&self, sched: &mut S) -> io::Result<RunReport> {
        install_alarm_handler();
        let start = Instant::now();
        self.shm.clear();
        let (leader, stderr_fd) = self.spawn()?;
        let mut run = Run {
            sup: self,
            sched,
            leader,
            threads: vec![Thread {
                tid: leader,
                state: State::Stopped,
                pending_signal: 0,
            }],
            current: None,
            last_ran: None,
            trace: Vec::new(),
            decisions: Vec::new(),
            stops: 0,
            edges_at_last_event: 0,
            futex_seq: 0,
            uncontrolled: Vec::new(),
            orphan_stops: Vec::new(),
            outcome: None,
        };
        let outcome = match run.main_loop() {
            Ok(outcome) => outcome,
            Err(err) => {
                run.kill_all();
                return Err(err);
            }
        };
        let stderr = read_all_fd(stderr_fd);
        Ok(RunReport {
            outcome,
            trace: run.trace,
            decisions: run.decisions,
            stops: run.stops,
            edges: self.shm.edges(),
            threads: run.threads.len(),
            wall: start.elapsed(),
            uncontrolled: run.uncontrolled,
            stderr,
        })
    }

    /// fork + (seccomp, SIGSTOP) + exec. Returns the child pid (stopped, seized, at its exec
    /// event already consumed) and a pipe fd for its stderr.
    fn spawn(&self) -> io::Result<(Pid, Option<libc::c_int>)> {
        let program = std::path::Path::new(self.program.to_str().unwrap_or_default());
        if !program.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "target binary {} not found (run build-targets.sh and pass the path)",
                    program.display()
                ),
            ));
        }
        let mut argv: Vec<*const libc::c_char> = Vec::with_capacity(self.args.len() + 2);
        argv.push(self.program.as_ptr());
        argv.extend(self.args.iter().map(|a| a.as_ptr()));
        argv.push(std::ptr::null());
        let env_shm = CString::new(format!("{ENV_SHM_FD}={}", self.shm.fd().as_raw_fd())).unwrap();
        // Keep the parent's environment (PATH etc.) plus our variable.
        let mut envp_owned: Vec<CString> = std::env::vars_os()
            .filter(|(k, _)| k != ENV_SHM_FD)
            .map(|(k, v)| {
                use std::os::unix::ffi::OsStrExt;
                let mut bytes = k.as_bytes().to_vec();
                bytes.push(b'=');
                bytes.extend_from_slice(v.as_bytes());
                CString::new(bytes).unwrap()
            })
            .collect();
        envp_owned.push(env_shm);
        let mut envp: Vec<*const libc::c_char> = envp_owned.iter().map(|e| e.as_ptr()).collect();
        envp.push(std::ptr::null());

        let mut stderr_pipe = [-1 as libc::c_int; 2];
        if self.capture_stderr
            && unsafe { libc::pipe2(stderr_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // Child: only async-signal-safe calls from here on.
            unsafe {
                if self.capture_stderr {
                    libc::dup2(stderr_pipe[1], 2);
                }
                if seccomp::install().is_err() {
                    libc::_exit(126);
                }
                libc::kill(libc::getpid(), libc::SIGSTOP);
                libc::execve(self.program.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        if self.capture_stderr {
            unsafe { libc::close(stderr_pipe[1]) };
        }

        // Wait for the self-SIGSTOP, seize, clear the group-stop with SIGCONT.
        let mut status = 0;
        if unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) } != pid {
            return Err(io::Error::last_os_error());
        }
        if !libc::WIFSTOPPED(status) {
            return Err(io::Error::other(format!(
                "child did not stop before exec (status {status:#x})"
            )));
        }
        ptrace::seize(pid, ptrace::SEIZE_OPTIONS)?;
        // Seizing a group-stopped task makes it report PTRACE_EVENT_STOP.
        match ptrace::wait_pid(pid)? {
            WaitEvent::GroupStop { .. } | WaitEvent::Event { .. } => {}
            other => {
                return Err(io::Error::other(format!(
                    "unexpected event after seize: {other:?}"
                )));
            }
        }
        unsafe { libc::kill(pid, libc::SIGCONT) };
        ptrace::cont(pid, 0)?;
        // Consume the SIGCONT delivery stop and the exec event, in whatever order they come.
        let mut seen_exec = false;
        let mut seen_cont = false;
        while !(seen_exec && seen_cont) {
            match ptrace::wait_pid(pid)? {
                WaitEvent::Signal { sig, .. } if sig == libc::SIGCONT => {
                    seen_cont = true;
                    if !seen_exec {
                        ptrace::cont(pid, 0)?;
                    }
                }
                WaitEvent::Event { event, .. } if event == libc::PTRACE_EVENT_EXEC => {
                    seen_exec = true;
                    if !seen_cont {
                        ptrace::cont(pid, 0)?;
                    }
                }
                WaitEvent::GroupStop { .. } => {
                    ptrace::cont(pid, 0)?;
                }
                WaitEvent::Event { event, .. } if event == libc::PTRACE_EVENT_STOP => {
                    // SIGCONT re-traps a seized, group-stopped tracee.
                    ptrace::cont(pid, 0)?;
                }
                WaitEvent::Exited { code, .. } => {
                    return Err(io::Error::other(format!(
                        "target exited with {code} before exec (seccomp install failed?)"
                    )));
                }
                WaitEvent::Event { event, .. } if event == libc::PTRACE_EVENT_SECCOMP => {
                    // The only traced syscall reachable before exec is exit_group from the
                    // child's `_exit(127)` after a failed execve.
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    return Err(io::Error::other("execve of target failed"));
                }
                other => {
                    return Err(io::Error::other(format!(
                        "unexpected event before exec: {other:?}"
                    )));
                }
            }
        }
        Ok((
            pid,
            if self.capture_stderr {
                Some(stderr_pipe[0])
            } else {
                None
            },
        ))
    }
}

fn read_all_fd(fd: Option<libc::c_int>) -> String {
    let Some(fd) = fd else {
        return String::new();
    };
    use std::io::Read;
    let mut file = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

const CRASH_SIGNALS: &[i32] = &[
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGABRT,
    libc::SIGTRAP,
    libc::SIGSYS,
];

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_CMD_MASK: u64 = !(128 | 256);

impl<S: Scheduler> Run<'_, S> {
    fn log(&self, msg: impl FnOnce() -> String) {
        if self.sup.verbose {
            eprintln!("[sup] {}", msg());
        }
    }

    fn thread_index(&self, tid: Pid) -> Option<usize> {
        self.threads.iter().position(|t| t.tid == tid)
    }

    fn kill_all(&mut self) {
        unsafe {
            libc::kill(self.leader, libc::SIGKILL);
        }
        // Reap everything we still own.
        loop {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
            if pid <= 0 {
                break;
            }
            if libc::WIFSTOPPED(status) {
                let _ = ptrace::cont(pid, 0);
            }
        }
    }

    fn record(&mut self, thread: usize, kind: PointKind) {
        let edges_now = self.sup.shm.edges();
        let edges = edges_now - self.edges_at_last_event;
        self.edges_at_last_event = edges_now;
        self.trace.push(TraceEvent {
            thread,
            kind,
            edges,
        });
        self.log(|| format!("T{thread} ran {edges} edges -> {kind}"));
    }

    fn runnable(&self) -> Vec<usize> {
        self.threads
            .iter()
            .enumerate()
            .filter(|(_, t)| t.state == State::Stopped)
            .map(|(i, _)| i)
            .collect()
    }

    fn main_loop(&mut self) -> io::Result<Outcome> {
        loop {
            if let Some(outcome) = self.outcome.take() {
                return Ok(outcome);
            }
            if self.current.is_none() {
                let busy = self
                    .threads
                    .iter()
                    .any(|t| matches!(t.state, State::Running | State::Exiting | State::Starting));
                if !busy {
                    match self.schedule()? {
                        Some(outcome) => return Ok(outcome),
                        None => continue,
                    }
                }
            }
            self.wait_and_handle()?;
        }
    }

    /// Choose and resume the next thread. Returns `Some(outcome)` when the run is over.
    fn schedule(&mut self) -> io::Result<Option<Outcome>> {
        let runnable = self.runnable();
        if runnable.is_empty() {
            return self.handle_idle();
        }
        let mut candidates = Vec::with_capacity(runnable.len());
        if let Some(last) = self.last_ran
            && runnable.contains(&last)
        {
            candidates.push(last);
        }
        candidates.extend(
            runnable
                .iter()
                .copied()
                .filter(|i| Some(*i) != self.last_ran),
        );
        let decision = if candidates.len() >= 2 {
            let mut d = self.sched.decide(candidates.len());
            d.pick = d.pick.min(candidates.len() - 1);
            d.budget = d.budget.min(BUDGET_TABLE.len() - 1);
            self.decisions.push(d);
            d
        } else {
            Decision { pick: 0, budget: 0 }
        };
        let chosen = candidates[decision.pick];
        let budget = BUDGET_TABLE[decision.budget];
        self.log(|| {
            format!(
                "schedule: candidates {candidates:?} pick {} budget {budget} -> T{chosen}",
                decision.pick
            )
        });
        self.resume(chosen, budget)?;
        Ok(None)
    }

    fn resume(&mut self, index: usize, budget: u32) -> io::Result<()> {
        self.sup.shm.set_budget(budget);
        let thread = &mut self.threads[index];
        let sig = std::mem::replace(&mut thread.pending_signal, 0);
        ptrace::cont(thread.tid, sig)?;
        thread.state = State::Running;
        self.current = Some(index);
        self.last_ran = Some(index);
        Ok(())
    }

    /// Nothing runnable and nothing running: wake timed-out waiters, re-check futex words, or
    /// declare a deadlock.
    fn handle_idle(&mut self) -> io::Result<Option<Outcome>> {
        let waiters: Vec<usize> = self
            .threads
            .iter()
            .enumerate()
            .filter(|(_, t)| matches!(t.state, State::FutexWait { .. }))
            .map(|(i, _)| i)
            .collect();
        if waiters.is_empty() {
            // Every thread exited but we did not see the leader's exit status yet.
            self.wait_and_handle()?;
            return Ok(None);
        }
        if self.recheck_futex_words()? {
            return Ok(None);
        }
        // Virtual time: a timed wait only expires when nothing else can make progress.
        let timed = waiters
            .iter()
            .copied()
            .filter_map(|i| match self.threads[i].state {
                State::FutexWait {
                    timed: true, seq, ..
                } => Some((seq, i)),
                _ => None,
            })
            .min();
        if let Some((_, index)) = timed {
            self.set_return(index, -libc::ETIMEDOUT as i64)?;
            self.threads[index].state = State::Stopped;
            self.record(index, PointKind::FutexTimeout);
            return Ok(None);
        }
        let outcome = Outcome::Deadlock {
            waiting_threads: waiters,
        };
        self.kill_all();
        Ok(Some(outcome))
    }

    /// The kernel side of `CLONE_CHILD_CLEARTID` (and any pass-through waker) changes futex
    /// words without our knowledge; wake waiters whose word no longer matches. Returns whether
    /// anything was woken.
    fn recheck_futex_words(&mut self) -> io::Result<bool> {
        let mut woke = false;
        for i in 0..self.threads.len() {
            if let State::FutexWait { addr, val, .. } = self.threads[i].state {
                let value = ptrace::read_u32(self.leader, addr)?;
                if value != val {
                    self.threads[i].state = State::Stopped;
                    self.record(i, PointKind::FutexWoken);
                    woke = true;
                }
            }
        }
        Ok(woke)
    }

    fn set_return(&mut self, index: usize, value: i64) -> io::Result<()> {
        let tid = self.threads[index].tid;
        let mut regs = ptrace::getregs(tid)?;
        regs.rax = value as u64;
        ptrace::setregs(tid, &regs)
    }

    fn wait_and_handle(&mut self) -> io::Result<()> {
        unsafe {
            ALARM_FIRED.store(false, Ordering::SeqCst);
            libc::alarm(self.sup.watchdog.as_secs().max(1) as u32);
        }
        let event = ptrace::wait_any();
        unsafe {
            libc::alarm(0);
        }
        let event = match event {
            Ok(event) => event,
            Err(err)
                if err.kind() == io::ErrorKind::Interrupted
                    && ALARM_FIRED.load(Ordering::SeqCst) =>
            {
                self.log(|| "watchdog fired".to_string());
                self.kill_all();
                self.outcome = Some(Outcome::Timeout);
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        self.stops += 1;
        self.handle_event(event)
    }

    fn handle_event(&mut self, event: WaitEvent) -> io::Result<()> {
        match event {
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_SECCOMP => {
                let index = self.thread_index(pid).ok_or_else(|| {
                    io::Error::other(format!("seccomp stop from unknown tid {pid}"))
                })?;
                self.handle_seccomp(index)
            }
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_CLONE => {
                let parent = self.thread_index(pid).ok_or_else(|| {
                    io::Error::other(format!("clone event from unknown tid {pid}"))
                })?;
                let child_tid = ptrace::geteventmsg(pid)? as Pid;
                let child_index = self.threads.len();
                let already_stopped =
                    if let Some(pos) = self.orphan_stops.iter().position(|t| *t == child_tid) {
                        self.orphan_stops.swap_remove(pos);
                        true
                    } else {
                        false
                    };
                self.threads.push(Thread {
                    tid: child_tid,
                    state: if already_stopped {
                        State::Stopped
                    } else {
                        State::Starting
                    },
                    pending_signal: 0,
                });
                if !already_stopped {
                    // Make the schedule independent of the clone-event/initial-stop race.
                    match ptrace::wait_pid(child_tid)? {
                        WaitEvent::Event { .. } | WaitEvent::GroupStop { .. } => {}
                        other => {
                            return Err(io::Error::other(format!(
                                "unexpected first event from new thread {child_tid}: {other:?}"
                            )));
                        }
                    }
                    self.stops += 1;
                    self.threads[child_index].state = State::Stopped;
                }
                self.threads[parent].state = State::Stopped;
                self.current = None;
                self.record(parent, PointKind::Clone);
                self.record(child_index, PointKind::ThreadStart);
                Ok(())
            }
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_EXIT => {
                let Some(index) = self.thread_index(pid) else {
                    // A thread we never registered (clone raced with exit_group); let it die.
                    ptrace::cont(pid, 0)?;
                    return Ok(());
                };
                let was_current = self.current == Some(index);
                self.threads[index].state = State::Exiting;
                ptrace::cont(pid, 0)?;
                if was_current {
                    self.current = None;
                    self.record(index, PointKind::Exit);
                }
                if pid != self.leader {
                    // Wait for the kernel to finish this thread (CLEARTID + futex wake) so the
                    // joiner's wake-up is deterministic.
                    loop {
                        match ptrace::wait_pid(pid)? {
                            WaitEvent::Exited { .. } | WaitEvent::Killed { .. } => break,
                            WaitEvent::Event { .. }
                            | WaitEvent::GroupStop { .. }
                            | WaitEvent::Signal { .. }
                            | WaitEvent::Syscall { .. } => {
                                ptrace::cont(pid, 0)?;
                            }
                        }
                    }
                    self.stops += 1;
                    self.threads[index].state = State::Exited;
                    self.recheck_futex_words()?;
                }
                Ok(())
            }
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_STOP => {
                match self.thread_index(pid) {
                    Some(index) => {
                        // Initial stop of a thread whose clone event we already handled, or a
                        // PTRACE_INTERRUPT-style stop: treat as runnable.
                        if self.threads[index].state == State::Starting
                            || self.threads[index].state == State::Running
                        {
                            self.threads[index].state = State::Stopped;
                            if self.current == Some(index) {
                                self.current = None;
                            }
                        }
                    }
                    None => self.orphan_stops.push(pid),
                }
                Ok(())
            }
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_EXEC => {
                ptrace::cont(pid, 0)
            }
            WaitEvent::Event { pid, event } => {
                self.uncontrolled
                    .push(format!("ptrace event {event} on tid {pid}"));
                ptrace::cont(pid, 0)
            }
            WaitEvent::Syscall { pid } => {
                // We never use PTRACE_SYSCALL; treat like a plain stop.
                ptrace::cont(pid, 0)
            }
            WaitEvent::GroupStop { pid, .. } => ptrace::cont(pid, 0),
            WaitEvent::Signal { pid, sig } => {
                let Some(index) = self.thread_index(pid) else {
                    return ptrace::cont(pid, sig);
                };
                if CRASH_SIGNALS.contains(&sig) {
                    // Deliver synchronously: the thread stops for good.
                    self.threads[index].pending_signal = sig;
                    self.threads[index].state = State::Stopped;
                    if self.current == Some(index) {
                        self.current = None;
                    }
                    self.record(index, PointKind::Signal(sig));
                    Ok(())
                } else if sig == libc::SIGCONT || sig == libc::SIGSTOP {
                    ptrace::cont(pid, 0)
                } else {
                    // Asynchronous signal: deliver immediately, keep running.
                    ptrace::cont(pid, sig)
                }
            }
            WaitEvent::Exited { pid, code } => self.thread_gone(pid, Outcome::Exited(code)),
            WaitEvent::Killed { pid, sig } => self.thread_gone(pid, Outcome::Signaled(sig)),
        }
    }

    fn thread_gone(&mut self, pid: Pid, outcome: Outcome) -> io::Result<()> {
        if pid == self.leader {
            // Reap remaining threads (they are already dead or dying).
            for t in &mut self.threads {
                t.state = State::Exited;
            }
            self.outcome = Some(outcome);
            return Ok(());
        }
        if let Some(index) = self.thread_index(pid) {
            if self.current == Some(index) {
                self.current = None;
            }
            self.threads[index].state = State::Exited;
            self.recheck_futex_words()?;
        }
        Ok(())
    }

    /// Skip the syscall the thread is stopped at and make it return `value`.
    fn skip_syscall(&mut self, tid: Pid, regs: &mut Regs, value: i64) -> io::Result<()> {
        regs.orig_rax = u64::MAX;
        regs.rax = value as u64;
        ptrace::setregs(tid, regs)
    }

    fn handle_seccomp(&mut self, index: usize) -> io::Result<()> {
        let tid = self.threads[index].tid;
        let mut regs = ptrace::getregs(tid)?;
        let nr = regs.orig_rax as i64;
        let stop_here = |this: &mut Self, kind: PointKind| {
            this.threads[index].state = State::Stopped;
            if this.current == Some(index) {
                this.current = None;
            }
            this.record(index, kind);
        };
        match nr {
            n if n == libc::SYS_futex => self.handle_futex(index, &mut regs),
            n if n == libc::SYS_clone || n == libc::SYS_clone3 => {
                // Let it run; the PTRACE_EVENT_CLONE stop follows immediately.
                ptrace::cont(tid, 0)
            }
            n if n == libc::SYS_sched_yield => {
                self.skip_syscall(tid, &mut regs, 0)?;
                stop_here(self, PointKind::Yield);
                Ok(())
            }
            n if n == libc::SYS_nanosleep || n == libc::SYS_clock_nanosleep => {
                self.skip_syscall(tid, &mut regs, 0)?;
                stop_here(self, PointKind::Sleep);
                Ok(())
            }
            n if n == libc::SYS_getrandom => {
                let buf = regs.rdi;
                let len = regs.rsi as usize;
                let bytes = self.sched.random_bytes(len.min(4096));
                ptrace::write_mem(self.leader, buf, &bytes)?;
                self.skip_syscall(tid, &mut regs, bytes.len() as i64)?;
                stop_here(self, PointKind::Getrandom);
                Ok(())
            }
            n if n == MARKER_SYSCALL && regs.rdi == MARKER_MAGIC => {
                self.skip_syscall(tid, &mut regs, 0)?;
                stop_here(self, PointKind::Preempt);
                Ok(())
            }
            n if n == libc::SYS_exit || n == libc::SYS_exit_group => {
                // Runs to PTRACE_EVENT_EXIT next.
                ptrace::cont(tid, 0)
            }
            // Non-blocking poll (std's startup fd check) cannot reorder anything.
            n if n == libc::SYS_poll && regs.rdx == 0 => ptrace::cont(tid, 0),
            n => {
                self.uncontrolled
                    .push(format!("syscall {n} passed through on T{index}"));
                ptrace::cont(tid, 0)
            }
        }
    }

    fn handle_futex(&mut self, index: usize, regs: &mut Regs) -> io::Result<()> {
        let tid = self.threads[index].tid;
        let addr = regs.rdi;
        let op = regs.rsi;
        let val = regs.rdx as u32;
        let timeout = regs.r10;
        let val3 = regs.r9 as u32;
        match op & FUTEX_CMD_MASK {
            FUTEX_WAIT | FUTEX_WAIT_BITSET => {
                let current = ptrace::read_u32(self.leader, addr)?;
                if current != val {
                    self.skip_syscall(tid, regs, -(libc::EAGAIN as i64))?;
                    self.threads[index].state = State::Stopped;
                    self.current = None;
                    self.record(index, PointKind::FutexNoWait);
                    return Ok(());
                }
                // Wake returns 0.
                self.skip_syscall(tid, regs, 0)?;
                let bitset = if op & FUTEX_CMD_MASK == FUTEX_WAIT_BITSET {
                    val3
                } else {
                    u32::MAX
                };
                self.futex_seq += 1;
                self.threads[index].state = State::FutexWait {
                    addr,
                    val,
                    bitset,
                    timed: timeout != 0,
                    seq: self.futex_seq,
                };
                self.current = None;
                self.record(index, PointKind::FutexWait);
                Ok(())
            }
            FUTEX_WAKE | FUTEX_WAKE_BITSET => {
                let mask = if op & FUTEX_CMD_MASK == FUTEX_WAKE_BITSET {
                    val3
                } else {
                    u32::MAX
                };
                let max = val as usize;
                let mut waiters: Vec<(u64, usize)> = self
                    .threads
                    .iter()
                    .enumerate()
                    .filter_map(|(i, t)| match t.state {
                        State::FutexWait {
                            addr: waddr,
                            bitset,
                            seq,
                            ..
                        } if waddr == addr && (bitset & mask) != 0 => Some((seq, i)),
                        _ => None,
                    })
                    .collect();
                waiters.sort();
                let woken: Vec<usize> = waiters.into_iter().take(max).map(|(_, i)| i).collect();
                self.skip_syscall(tid, regs, woken.len() as i64)?;
                self.threads[index].state = State::Stopped;
                self.current = None;
                self.record(index, PointKind::FutexWake);
                for waiter in woken {
                    self.threads[waiter].state = State::Stopped;
                    self.record(waiter, PointKind::FutexWoken);
                }
                Ok(())
            }
            other => {
                self.uncontrolled
                    .push(format!("futex op {other} passed through on T{index}"));
                ptrace::cont(tid, 0)
            }
        }
    }
}
