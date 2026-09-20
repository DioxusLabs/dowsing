//! A live target process under the supervisor. The session runs the target until it needs a
//! decision ([`Event::Decision`]) or terminates ([`Event::Done`]); the caller answers with
//! [`Session::choose`]. At every decision point all target threads are ptrace-stopped, so the
//! session can [`Session::snapshot`] the process and later [`Session::restore`] it.
//!
//! Skipped syscalls are the uniform stop shape: a thread left stopped always has
//! `orig_rax = -1` semantics ("continue at `rip` with these registers"), which is what makes
//! registers captured at one stop valid to load at another.

use crate::{
    ptrace::{self, Pid, Regs, WaitEvent},
    seccomp,
    shm::{ENV_SHM_FD, MARKER_MAGIC, MARKER_SYSCALL, MARKER_VARIANT, Shm},
    snapshot::{self, MapOp, Mapping, PAGE, Snapshot, SnapshotId, Store, ThreadRegs},
    world::*,
};
use std::{
    collections::HashSet,
    ffi::CString,
    io::{self, Read},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Decision { kind: Kind, n: u32 },
    Done(Outcome),
}

#[derive(Debug, Clone, Default)]
pub struct RestoreStats {
    pub pages_written: usize,
    pub map_ops: usize,
    pub threads: usize,
    pub wall: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct SnapshotStats {
    pub pages_copied: usize,
    pub wall: Duration,
}

pub struct Options {
    pub watchdog: Duration,
    pub verbose: bool,
    pub capture_stderr: bool,
    /// Send the target's stdout to `/dev/null`.
    pub silence_stdout: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            watchdog: Duration::from_secs(3),
            verbose: false,
            capture_stderr: true,
            silence_stdout: true,
        }
    }
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
        action.sa_flags = 0;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut());
    }
}

const CRASH_SIGNALS: &[i32] = &[
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGABRT,
    libc::SIGSYS,
];

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_CLOCK_REALTIME: u64 = 256;
const FUTEX_CMD_MASK: u64 = !(128 | 256);
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const TIMER_ABSTIME: u64 = 1;

pub struct Session {
    shm: Shm,
    leader: Pid,
    opts: Options,
    stderr: Option<OwnedFd>,
    /// Address of a `syscall` instruction in the target (for injected syscalls).
    syscall_insn: u64,
    pub world: World,
    pub store: Store,
    /// Snapshot the live soft-dirty bits are relative to.
    head: Option<SnapshotId>,
    /// Kernel tasks that exist but are not in `world.threads` (created on another branch).
    zombies: Vec<Pid>,
    orphan_stops: Vec<Pid>,
    pub stops: usize,
    pub uncontrolled: Vec<String>,
    /// Coverage bits first seen on this path since the last `take_new_coverage`.
    new_coverage: Vec<u32>,
    pub alive: bool,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.kill_all();
    }
}

impl Session {
    /// fork + seccomp + exec, then run to the exec stop with the vDSO hidden and ASLR off.
    pub fn spawn(program: &str, args: &[String], opts: Options) -> io::Result<Self> {
        install_alarm_handler();
        let path = std::path::Path::new(program);
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("target binary {program} not found"),
            ));
        }
        let shm = Shm::new()?;
        let program_c = CString::new(program).expect("program path");
        let args_c: Vec<CString> = args
            .iter()
            .map(|a| CString::new(a.as_str()).expect("arg"))
            .collect();
        let mut argv: Vec<*const libc::c_char> = vec![program_c.as_ptr()];
        argv.extend(args_c.iter().map(|a| a.as_ptr()));
        argv.push(std::ptr::null());
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
        envp_owned.push(CString::new(format!("{ENV_SHM_FD}={}", shm.fd().as_raw_fd())).unwrap());
        let mut envp: Vec<*const libc::c_char> = envp_owned.iter().map(|e| e.as_ptr()).collect();
        envp.push(std::ptr::null());

        let mut stderr_pipe = [-1 as libc::c_int; 2];
        if opts.capture_stderr
            && unsafe { libc::pipe2(stderr_pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) }
                != 0
        {
            return Err(io::Error::last_os_error());
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            unsafe {
                if opts.capture_stderr {
                    libc::dup2(stderr_pipe[1], 2);
                }
                if opts.silence_stdout {
                    let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
                    if null >= 0 {
                        libc::dup2(null, 1);
                    }
                }
                libc::personality(libc::ADDR_NO_RANDOMIZE as libc::c_ulong);
                if seccomp::install().is_err() {
                    libc::_exit(126);
                }
                libc::kill(libc::getpid(), libc::SIGSTOP);
                libc::execve(program_c.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        let stderr = if opts.capture_stderr {
            unsafe { libc::close(stderr_pipe[1]) };
            Some(unsafe { OwnedFd::from_raw_fd(stderr_pipe[0]) })
        } else {
            None
        };

        let mut status = 0;
        if unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) } != pid {
            return Err(io::Error::last_os_error());
        }
        if !libc::WIFSTOPPED(status) {
            return Err(io::Error::other(format!(
                "child did not stop before exec ({status:#x})"
            )));
        }
        ptrace::seize(pid, ptrace::SEIZE_OPTIONS)?;
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
        let (mut seen_exec, mut seen_cont) = (false, false);
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
                    let regs = ptrace::getregs(pid)?;
                    ptrace::hide_vdso_in_auxv(pid, regs.rsp)?;
                    if !seen_cont {
                        ptrace::cont(pid, 0)?;
                    }
                }
                WaitEvent::GroupStop { .. } => ptrace::cont(pid, 0)?,
                WaitEvent::Event { event, .. } if event == libc::PTRACE_EVENT_STOP => {
                    ptrace::cont(pid, 0)?
                }
                WaitEvent::Exited { code, .. } => {
                    return Err(io::Error::other(format!(
                        "target exited with {code} before exec"
                    )));
                }
                WaitEvent::Event { event, .. } if event == libc::PTRACE_EVENT_SECCOMP => {
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
        // The leader is stopped at the exec event; the first stop after resuming it is a
        // seccomp stop, which gives us a syscall instruction address.
        let mut session = Session {
            shm,
            leader: pid,
            opts,
            stderr,
            syscall_insn: 0,
            world: World::new(pid),
            store: Store::default(),
            head: None,
            zombies: Vec::new(),
            orphan_stops: Vec::new(),
            stops: 0,
            uncontrolled: Vec::new(),
            new_coverage: Vec::new(),
            alive: true,
        };
        session.world.threads[0].state = ThreadState::Stopped;
        session.record(0, Point::Start);
        Ok(session)
    }

    pub fn leader(&self) -> Pid {
        self.leader
    }

    pub fn shm(&self) -> &Shm {
        &self.shm
    }

    /// Stderr the target wrote since the last call.
    pub fn take_stderr(&mut self) -> String {
        let Some(fd) = &self.stderr else {
            return String::new();
        };
        let mut file = unsafe { std::fs::File::from_raw_fd(fd.as_raw_fd()) };
        let mut buf = Vec::new();
        let _ = file.read_to_end(&mut buf);
        std::mem::forget(file);
        String::from_utf8_lossy(&buf).into_owned()
    }

    pub fn take_new_coverage(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.new_coverage)
    }

    fn log(&self, msg: impl FnOnce() -> String) {
        if self.opts.verbose {
            eprintln!("[sandbox] {}", msg());
        }
    }

    fn kill_all(&mut self) {
        if !self.alive {
            return;
        }
        self.alive = false;
        unsafe {
            libc::kill(self.leader, libc::SIGKILL);
        }
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

    fn record(&mut self, thread: usize, point: Point) {
        let edges_now = self.shm.edges();
        let edges = edges_now - self.world.edges_at_last_event;
        self.world.edges_at_last_event = edges_now;
        self.world.edges = edges_now;
        let fresh = self.shm.drain_bitmap(&mut self.world.coverage);
        self.new_coverage.extend(fresh);
        self.world.trace.push(TraceEvent {
            thread,
            point,
            edges,
        });
        self.log(|| format!("T{thread} ran {edges} edges -> {point}"));
    }

    // ----------------------------------------------------------------------------------------
    // Decision loop
    // ----------------------------------------------------------------------------------------

    /// Run until the next decision or the end of the run.
    pub fn step(&mut self) -> io::Result<Event> {
        loop {
            if let Some(outcome) = &self.world.outcome {
                return Ok(Event::Done(outcome.clone()));
            }
            if let Some(p) = &self.world.pending {
                return Ok(Event::Decision {
                    kind: p.kind(),
                    n: p.n(),
                });
            }
            if self.world.current.is_none() {
                let busy = self
                    .world
                    .threads
                    .iter()
                    .any(|t| t.state == ThreadState::Running);
                if !busy {
                    self.schedule()?;
                    continue;
                }
            }
            self.wait_and_handle()?;
        }
    }

    /// Answer the pending decision.
    pub fn choose(&mut self, choice: u32) -> io::Result<()> {
        let pending = self
            .world
            .pending
            .take()
            .ok_or_else(|| io::Error::other("choose() without a pending decision"))?;
        let n = pending.n();
        let choice = choice.min(n.saturating_sub(1));
        self.world.decisions.push(Decision {
            kind: pending.kind(),
            n,
            choice,
        });
        match pending {
            Pending::Schedule { candidates } => {
                self.apply_candidate(candidates[choice as usize], true)
            }
            Pending::Budget { thread } => self.resume(thread, BUDGET_TABLE[choice as usize]),
            Pending::Variant { thread, .. } => {
                self.set_return(thread, choice as i64)?;
                self.world.threads[thread].state = ThreadState::Stopped;
                Ok(())
            }
        }
    }

    /// Decisions made since the root.
    pub fn decisions(&self) -> &[Decision] {
        &self.world.decisions
    }

    fn schedule(&mut self) -> io::Result<()> {
        let runnable = self.world.runnable();
        let mut candidates: Vec<Candidate> = Vec::new();
        if let Some(last) = self.world.last_ran
            && runnable.contains(&last)
        {
            candidates.push(Candidate::Run(last));
        }
        candidates.extend(
            runnable
                .iter()
                .copied()
                .filter(|i| Some(*i) != self.world.last_ran)
                .map(Candidate::Run),
        );
        if candidates.is_empty() {
            return self.handle_idle();
        }
        candidates.extend(self.world.timed_waiters().into_iter().map(Candidate::Fire));
        if candidates.len() >= 2 {
            self.world.pending = Some(Pending::Schedule { candidates });
            return Ok(());
        }
        self.apply_candidate(candidates[0], false)
    }

    fn apply_candidate(&mut self, candidate: Candidate, contended: bool) -> io::Result<()> {
        match candidate {
            Candidate::Run(thread) => {
                let others = self.world.runnable().iter().any(|i| *i != thread);
                if contended && others {
                    self.world.pending = Some(Pending::Budget { thread });
                    Ok(())
                } else {
                    self.resume(thread, 0)
                }
            }
            Candidate::Fire(thread) => self.fire_timeout(thread),
        }
    }

    fn fire_timeout(&mut self, thread: usize) -> io::Result<()> {
        let state = self.world.threads[thread].state;
        let deadline = state.deadline().expect("fire on untimed thread");
        self.world.clock_ns = self.world.clock_ns.max(deadline);
        let ret = match state {
            ThreadState::FutexWait { .. } => -(libc::ETIMEDOUT as i64),
            _ => 0,
        };
        self.set_return(thread, ret)?;
        self.world.threads[thread].state = ThreadState::Stopped;
        self.record(thread, Point::Timeout);
        Ok(())
    }

    fn resume(&mut self, index: usize, budget: u32) -> io::Result<()> {
        self.shm.set_budget(budget);
        let tid = self.world.threads[index].tid;
        ptrace::cont(tid, 0)?;
        self.world.threads[index].state = ThreadState::Running;
        self.world.current = Some(index);
        self.world.last_ran = Some(index);
        Ok(())
    }

    /// Nothing runnable: the earliest timeout fires, or the run is deadlocked.
    fn handle_idle(&mut self) -> io::Result<()> {
        if self.recheck_futex_words()? {
            return Ok(());
        }
        if let Some(first) = self.world.timed_waiters().first().copied() {
            return self.fire_timeout(first);
        }
        let waiting = self.world.waiters();
        if waiting.is_empty() {
            return Err(io::Error::other("no threads left but no outcome"));
        }
        self.world.outcome = Some(Outcome::Deadlock { waiting });
        Ok(())
    }

    /// Kernel-side writes to futex words (none expected now that thread exit is emulated), plus
    /// wake-ups we emulate ourselves: wake waiters whose word no longer matches.
    fn recheck_futex_words(&mut self) -> io::Result<bool> {
        let mut woke = false;
        for i in 0..self.world.threads.len() {
            if let ThreadState::FutexWait { addr, val, .. } = self.world.threads[i].state {
                let value = ptrace::read_u32(self.leader, addr)?;
                if value != val {
                    self.set_return(i, 0)?;
                    self.world.threads[i].state = ThreadState::Stopped;
                    self.record(i, Point::FutexWoken);
                    woke = true;
                }
            }
        }
        Ok(woke)
    }

    fn set_return(&mut self, index: usize, value: i64) -> io::Result<()> {
        let tid = self.world.threads[index].tid;
        let mut regs = ptrace::getregs(tid)?;
        regs.rax = value as u64;
        regs.orig_rax = u64::MAX;
        ptrace::setregs(tid, &regs)
    }

    fn wait_and_handle(&mut self) -> io::Result<()> {
        unsafe {
            ALARM_FIRED.store(false, Ordering::SeqCst);
            libc::alarm(self.opts.watchdog.as_secs().max(1) as u32);
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
                return self.watchdog_fired();
            }
            Err(err) => return Err(err),
        };
        self.stops += 1;
        self.handle_event(event)
    }

    /// Stop the running thread where it is and end the run with `Timeout`.
    fn watchdog_fired(&mut self) -> io::Result<()> {
        let Some(index) = self.world.current else {
            return Err(io::Error::other("watchdog fired with no running thread"));
        };
        let tid = self.world.threads[index].tid;
        ptrace::interrupt(tid)?;
        match ptrace::wait_pid(tid)? {
            WaitEvent::Event { .. }
            | WaitEvent::GroupStop { .. }
            | WaitEvent::Signal { .. }
            | WaitEvent::Syscall { .. } => {}
            other => return Err(io::Error::other(format!("interrupt: unexpected {other:?}"))),
        }
        // A PTRACE_INTERRUPT stop inside a syscall would resume that syscall; the skipped shape
        // keeps the thread restorable.
        let mut regs = ptrace::getregs(tid)?;
        if regs.orig_rax != u64::MAX {
            regs.orig_rax = u64::MAX;
            regs.rax = -(libc::EINTR as i64) as u64;
            ptrace::setregs(tid, &regs)?;
        }
        self.world.threads[index].state = ThreadState::Stopped;
        self.world.current = None;
        self.record(index, Point::Preempt);
        self.world.outcome = Some(Outcome::Timeout);
        Ok(())
    }

    fn handle_event(&mut self, event: WaitEvent) -> io::Result<()> {
        match event {
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_SECCOMP => {
                let index = self.world.thread_index(pid).ok_or_else(|| {
                    io::Error::other(format!("seccomp stop from unknown tid {pid}"))
                })?;
                self.handle_seccomp(index)
            }
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_CLONE => {
                let parent = self.world.thread_index(pid).ok_or_else(|| {
                    io::Error::other(format!("clone event from unknown tid {pid}"))
                })?;
                let child_tid = ptrace::geteventmsg(pid)? as Pid;
                let already_stopped =
                    if let Some(pos) = self.orphan_stops.iter().position(|t| *t == child_tid) {
                        self.orphan_stops.swap_remove(pos);
                        true
                    } else {
                        false
                    };
                if !already_stopped {
                    match ptrace::wait_pid(child_tid)? {
                        WaitEvent::Event { .. } | WaitEvent::GroupStop { .. } => {}
                        other => {
                            return Err(io::Error::other(format!(
                                "unexpected first event from new thread {child_tid}: {other:?}"
                            )));
                        }
                    }
                    self.stops += 1;
                }
                // Run the parent to its syscall-exit stop so `rax` holds the child tid and the
                // stop has the uniform "continue at rip" shape.
                ptrace::syscall(pid, 0)?;
                loop {
                    match ptrace::wait_pid(pid)? {
                        WaitEvent::Syscall { .. } => break,
                        WaitEvent::Event { .. } | WaitEvent::GroupStop { .. } => {
                            ptrace::syscall(pid, 0)?
                        }
                        other => {
                            return Err(io::Error::other(format!(
                                "clone exit: unexpected {other:?}"
                            )));
                        }
                    }
                }
                self.stops += 1;
                let mut regs = ptrace::getregs(pid)?;
                regs.orig_rax = u64::MAX;
                ptrace::setregs(pid, &regs)?;
                let ctid = std::mem::take(&mut self.world.threads[parent].pending_clone_ctid);
                let child_index = self.world.threads.len();
                self.world.threads.push(Thread {
                    tid: child_tid,
                    state: ThreadState::Stopped,
                    clear_tid: ctid,
                    pending_clone_ctid: 0,
                });
                self.world.threads[parent].state = ThreadState::Stopped;
                self.world.current = None;
                self.record(parent, Point::Clone);
                self.record(child_index, Point::ThreadStart);
                Ok(())
            }
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_EXIT => {
                // Only reachable if something bypassed our exit emulation; report and let it go.
                self.uncontrolled.push(format!("real exit of tid {pid}"));
                ptrace::cont(pid, 0)
            }
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_STOP => {
                match self.world.thread_index(pid) {
                    Some(index) => {
                        if self.world.threads[index].state == ThreadState::Running {
                            self.world.threads[index].state = ThreadState::Stopped;
                            if self.world.current == Some(index) {
                                self.world.current = None;
                            }
                        }
                    }
                    None => self.orphan_stops.push(pid),
                }
                Ok(())
            }
            WaitEvent::Event { pid, event } => {
                self.uncontrolled
                    .push(format!("ptrace event {event} on tid {pid}"));
                ptrace::cont(pid, 0)
            }
            WaitEvent::Syscall { pid } => ptrace::cont(pid, 0),
            WaitEvent::GroupStop { pid, .. } => ptrace::cont(pid, 0),
            WaitEvent::Signal { pid, sig } => {
                let Some(index) = self.world.thread_index(pid) else {
                    return ptrace::cont(pid, sig);
                };
                if CRASH_SIGNALS.contains(&sig) {
                    if self.opts.verbose {
                        let regs = ptrace::getregs(pid)?;
                        let stderr = self.take_stderr();
                        eprintln!(
                            "[sandbox] T{index} tid {pid} signal {sig} at rip {:#x} orig_rax {} rax {:#x} rsp {:#x}\n{stderr}",
                            regs.rip, regs.orig_rax as i64, regs.rax, regs.rsp
                        );
                    }
                    // Not delivered: the thread stays stopped and restorable.
                    self.world.threads[index].state = ThreadState::Stopped;
                    self.world.current = None;
                    self.normalize_stop(pid)?;
                    self.record(index, Point::Signal(sig));
                    self.world.outcome = Some(Outcome::Signaled(sig));
                    Ok(())
                } else if sig == libc::SIGCONT || sig == libc::SIGSTOP || sig == libc::SIGTRAP {
                    ptrace::cont(pid, 0)
                } else {
                    ptrace::cont(pid, sig)
                }
            }
            WaitEvent::Exited { pid, code } => self.process_gone(pid, Outcome::Exited(code)),
            WaitEvent::Killed { pid, sig } => self.process_gone(pid, Outcome::Signaled(sig)),
        }
    }

    fn process_gone(&mut self, pid: Pid, outcome: Outcome) -> io::Result<()> {
        if pid == self.leader {
            self.alive = false;
            return Err(io::Error::other(format!(
                "target process died ({outcome}); the session cannot be restored"
            )));
        }
        if let Some(index) = self.world.thread_index(pid) {
            self.uncontrolled
                .push(format!("thread {index} died: {outcome}"));
            self.world.threads[index].state = ThreadState::Parked;
            if self.world.current == Some(index) {
                self.world.current = None;
            }
        }
        Ok(())
    }

    /// If `tid` is stopped inside a syscall entry (a signal arrived at a seccomp stop), turn
    /// the stop into the skipped shape.
    fn normalize_stop(&mut self, tid: Pid) -> io::Result<()> {
        let mut regs = ptrace::getregs(tid)?;
        if regs.orig_rax != u64::MAX {
            regs.orig_rax = u64::MAX;
            ptrace::setregs(tid, &regs)?;
        }
        Ok(())
    }

    fn skip_syscall(&self, tid: Pid, regs: &mut Regs, value: i64) -> io::Result<()> {
        regs.orig_rax = u64::MAX;
        regs.rax = value as u64;
        ptrace::setregs(tid, regs)
    }

    fn stop_here(&mut self, index: usize, point: Point) {
        self.world.threads[index].state = ThreadState::Stopped;
        if self.world.current == Some(index) {
            self.world.current = None;
        }
        self.record(index, point);
    }

    fn handle_seccomp(&mut self, index: usize) -> io::Result<()> {
        let tid = self.world.threads[index].tid;
        let mut regs = ptrace::getregs(tid)?;
        if self.syscall_insn == 0 {
            let insn = regs.rip - 2;
            let mut bytes = [0u8; 2];
            ptrace::read_mem(self.leader, insn, &mut bytes)?;
            if bytes == [0x0f, 0x05] {
                self.syscall_insn = insn;
            }
        }
        let nr = regs.orig_rax as i64;
        match nr {
            n if n == libc::SYS_futex => self.handle_futex(index, &mut regs),
            n if n == libc::SYS_clone || n == libc::SYS_clone3 => {
                let ctid = if n == libc::SYS_clone {
                    if regs.rdi & CLONE_CHILD_CLEARTID != 0 {
                        regs.r10
                    } else {
                        0
                    }
                } else {
                    let flags = ptrace::read_u64(self.leader, regs.rdi)?;
                    if flags & CLONE_CHILD_CLEARTID != 0 {
                        ptrace::read_u64(self.leader, regs.rdi + 16)?
                    } else {
                        0
                    }
                };
                self.world.threads[index].pending_clone_ctid = ctid;
                ptrace::cont(tid, 0)
            }
            n if n == libc::SYS_sched_yield => {
                self.skip_syscall(tid, &mut regs, 0)?;
                self.stop_here(index, Point::Yield);
                Ok(())
            }
            n if n == libc::SYS_nanosleep || n == libc::SYS_clock_nanosleep => {
                let (req, absolute) = if n == libc::SYS_nanosleep {
                    (regs.rdi, false)
                } else {
                    (regs.rdx, regs.rsi & TIMER_ABSTIME != 0)
                };
                let dur = self.read_timespec_ns(req)?;
                let deadline = if absolute {
                    dur
                } else {
                    self.world.clock_ns.saturating_add(dur)
                };
                self.skip_syscall(tid, &mut regs, 0)?;
                self.world.wait_seq += 1;
                self.world.threads[index].state = ThreadState::Sleep {
                    deadline,
                    seq: self.world.wait_seq,
                };
                self.world.current = None;
                self.record(index, Point::Sleep);
                Ok(())
            }
            n if n == libc::SYS_clock_gettime => {
                let ns = self.clock_read(regs.rdi as i64);
                self.write_timespec(regs.rsi, ns)?;
                self.skip_syscall(tid, &mut regs, 0)?;
                self.stop_here(index, Point::Clock);
                Ok(())
            }
            n if n == libc::SYS_gettimeofday => {
                let ns = self.clock_read(libc::CLOCK_REALTIME as i64);
                if regs.rdi != 0 {
                    let mut buf = [0u8; 16];
                    buf[..8].copy_from_slice(&((ns / 1_000_000_000) as i64).to_ne_bytes());
                    buf[8..].copy_from_slice(&(((ns % 1_000_000_000) / 1000) as i64).to_ne_bytes());
                    ptrace::write_mem(self.leader, regs.rdi, &buf)?;
                }
                self.skip_syscall(tid, &mut regs, 0)?;
                self.stop_here(index, Point::Clock);
                Ok(())
            }
            n if n == libc::SYS_time => {
                let secs = (self.clock_read(libc::CLOCK_REALTIME as i64) / 1_000_000_000) as i64;
                if regs.rdi != 0 {
                    ptrace::write_u64(self.leader, regs.rdi, secs as u64)?;
                }
                self.skip_syscall(tid, &mut regs, secs)?;
                self.stop_here(index, Point::Clock);
                Ok(())
            }
            n if n == libc::SYS_getrandom => {
                let len = (regs.rsi as usize).min(4096);
                self.world.entropy_seq += 1;
                let mut bytes = vec![0u8; len];
                let mut s = self.world.entropy_seq.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
                for b in &mut bytes {
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    *b = s as u8;
                }
                ptrace::write_mem(self.leader, regs.rdi, &bytes)?;
                self.skip_syscall(tid, &mut regs, len as i64)?;
                self.stop_here(index, Point::Getrandom);
                Ok(())
            }
            n if n == MARKER_SYSCALL && regs.rdi == MARKER_MAGIC => match regs.rsi {
                MARKER_VARIANT => {
                    let nchoices = (regs.rdx as u32).max(1);
                    self.skip_syscall(tid, &mut regs, 0)?;
                    self.world.threads[index].state = ThreadState::Stopped;
                    self.world.current = None;
                    self.record(index, Point::Variant);
                    if nchoices >= 2 {
                        self.world.pending = Some(Pending::Variant {
                            thread: index,
                            n: nchoices,
                        });
                    }
                    Ok(())
                }
                _ => {
                    self.skip_syscall(tid, &mut regs, 0)?;
                    self.stop_here(index, Point::Preempt);
                    Ok(())
                }
            },
            // Refused: an rseq registration is per-task kernel state the snapshot cannot carry,
            // and the kernel would write cpu ids into the TCB behind our back. glibc treats
            // ENOSYS as "old kernel" and never retries.
            n if n == libc::SYS_rseq => {
                self.skip_syscall(tid, &mut regs, -(libc::ENOSYS as i64))?;
                ptrace::cont(tid, 0)
            }
            // Memory that exists in the current snapshot is kept (as PROT_NONE) instead of
            // unmapped, so restoring it is an mprotect plus the pages dirtied since, not a
            // rewrite of the whole range. Costs address space until the process exits.
            n if n == libc::SYS_munmap => {
                if self.retained(regs.rdi, regs.rsi) {
                    regs.orig_rax = libc::SYS_mprotect as u64;
                    regs.rdx = libc::PROT_NONE as u64;
                    ptrace::setregs(tid, &regs)?;
                }
                ptrace::cont(tid, 0)
            }
            n if n == libc::SYS_exit => {
                // Emulate the kernel side of thread exit and freeze the task.
                self.skip_syscall(tid, &mut regs, 0)?;
                self.world.threads[index].state = ThreadState::Parked;
                self.world.current = None;
                self.record(index, Point::Exit);
                let ctid = self.world.threads[index].clear_tid;
                if ctid != 0 {
                    ptrace::write_u32(self.leader, ctid, 0)?;
                    self.wake(ctid, u32::MAX, usize::MAX);
                }
                Ok(())
            }
            n if n == libc::SYS_exit_group => {
                self.skip_syscall(tid, &mut regs, 0)?;
                self.world.threads[index].state = ThreadState::Stopped;
                self.world.current = None;
                self.record(index, Point::ExitGroup);
                self.world.outcome = Some(Outcome::Exited((regs.rdi & 0xff) as i32));
                Ok(())
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

    /// Every read advances the clock by one tick so a program that computes
    /// `deadline = now + 0` and re-reads the clock observes progress.
    fn clock_read(&mut self, clock: i64) -> u64 {
        self.world.clock_ns += CLOCK_TICK_NS;
        match clock as i32 {
            libc::CLOCK_REALTIME | libc::CLOCK_REALTIME_COARSE | libc::CLOCK_TAI => {
                REALTIME_BASE_NS + (self.world.clock_ns - CLOCK_START_NS)
            }
            _ => self.world.clock_ns,
        }
    }

    fn read_timespec_ns(&self, addr: u64) -> io::Result<u64> {
        if addr == 0 {
            return Ok(0);
        }
        let secs = ptrace::read_u64(self.leader, addr)? as i64;
        let nanos = ptrace::read_u64(self.leader, addr + 8)? as i64;
        Ok((secs.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nanos.max(0) as u64))
    }

    fn write_timespec(&self, addr: u64, ns: u64) -> io::Result<()> {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&((ns / 1_000_000_000) as i64).to_ne_bytes());
        buf[8..].copy_from_slice(&((ns % 1_000_000_000) as i64).to_ne_bytes());
        ptrace::write_mem(self.leader, addr, &buf)
    }

    /// Wake up to `max` emulated waiters on `addr` matching `mask`, oldest first. Returns how many.
    fn wake(&mut self, addr: u64, mask: u32, max: usize) -> usize {
        let mut waiters: Vec<(u64, usize)> = self
            .world
            .threads
            .iter()
            .enumerate()
            .filter_map(|(i, t)| match t.state {
                ThreadState::FutexWait {
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
        for waiter in &woken {
            self.world.threads[*waiter].state = ThreadState::Stopped;
            self.record(*waiter, Point::FutexWoken);
        }
        woken.len()
    }

    fn handle_futex(&mut self, index: usize, regs: &mut Regs) -> io::Result<()> {
        let tid = self.world.threads[index].tid;
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
                    self.stop_here(index, Point::FutexNoWait);
                    return Ok(());
                }
                let bitset_op = op & FUTEX_CMD_MASK == FUTEX_WAIT_BITSET;
                let deadline = if timeout == 0 {
                    None
                } else {
                    let ts = self.read_timespec_ns(timeout)?;
                    Some(if bitset_op {
                        // Absolute; realtime deadlines are converted to the monotonic clock.
                        if op & FUTEX_CLOCK_REALTIME != 0 {
                            ts.saturating_sub(REALTIME_BASE_NS)
                                .saturating_add(CLOCK_START_NS)
                        } else {
                            ts
                        }
                    } else {
                        self.world.clock_ns.saturating_add(ts)
                    })
                };
                self.skip_syscall(tid, regs, 0)?;
                self.world.wait_seq += 1;
                self.world.threads[index].state = ThreadState::FutexWait {
                    addr,
                    val,
                    bitset: if bitset_op { val3 } else { u32::MAX },
                    deadline,
                    seq: self.world.wait_seq,
                };
                self.world.current = None;
                self.record(index, Point::FutexWait);
                Ok(())
            }
            FUTEX_WAKE | FUTEX_WAKE_BITSET => {
                let mask = if op & FUTEX_CMD_MASK == FUTEX_WAKE_BITSET {
                    val3
                } else {
                    u32::MAX
                };
                self.world.threads[index].state = ThreadState::Stopped;
                self.world.current = None;
                self.record(index, Point::FutexWake);
                let woken = self.wake(addr, mask, val as usize);
                self.skip_syscall(tid, regs, woken as i64)?;
                Ok(())
            }
            other => {
                self.uncontrolled
                    .push(format!("futex op {other} passed through on T{index}"));
                ptrace::cont(tid, 0)
            }
        }
    }

    // ----------------------------------------------------------------------------------------
    // Snapshots
    // ----------------------------------------------------------------------------------------

    fn all_stopped(&self) -> bool {
        self.world.current.is_none()
            && !self
                .world
                .threads
                .iter()
                .any(|t| t.state == ThreadState::Running)
    }

    fn retained(&self, start: u64, len: u64) -> bool {
        let Some(head) = self.head else {
            return false;
        };
        let end = start.saturating_add(len);
        self.store.snapshots[head]
            .maps
            .iter()
            .any(|m| m.snapshotted() && m.is_anon() && m.start < end && start < m.end)
    }

    fn heap_end(maps: &[Mapping]) -> u64 {
        maps.iter()
            .find(|m| m.path == "[heap]")
            .map(|m| m.end)
            .unwrap_or(0)
    }

    /// Capture the current state. Only valid at a decision point or after `Done`.
    pub fn snapshot(&mut self) -> io::Result<(SnapshotId, SnapshotStats)> {
        if !self.all_stopped() {
            return Err(io::Error::other("snapshot while a thread is running"));
        }
        let start = Instant::now();
        let maps = snapshot::read_maps(self.leader)?;
        let scan = snapshot::scan_pagemap(self.leader, &maps)?;
        let addrs: &[u64] = if self.head.is_none() {
            &scan.present
        } else {
            &scan.dirty
        };
        let mut pages = self.store.read_pages(self.leader, addrs, self.head)?;
        if let Some(head) = self.head {
            let zero = self.store.zero_page();
            for &a in &scan.absent {
                if self
                    .store
                    .lookup(head, a)
                    .is_some_and(|p| p.iter().any(|b| *b != 0))
                {
                    pages.insert(a, zero.clone());
                }
            }
        }
        let pages_copied = pages.len();
        let mut regs = Vec::new();
        for t in &self.world.threads {
            if t.state == ThreadState::Parked {
                continue;
            }
            regs.push(ThreadRegs {
                tid: t.tid,
                regs: ptrace::getregs(t.tid)?,
                xstate: ptrace::getregset(t.tid, ptrace::NT_X86_XSTATE)?,
            });
        }
        let depth = self
            .head
            .map(|h| self.store.snapshots[h].depth + 1)
            .unwrap_or(0);
        let id = self.store.push(Snapshot {
            parent: self.head,
            depth,
            pages,
            regs,
            world: self.world.clone(),
            brk: Self::heap_end(&maps),
            maps,
        });
        snapshot::clear_soft_dirty(self.leader)?;
        self.head = Some(id);
        Ok((
            id,
            SnapshotStats {
                pages_copied,
                wall: start.elapsed(),
            },
        ))
    }

    pub fn head(&self) -> Option<SnapshotId> {
        self.head
    }

    /// Return the process to snapshot `id`.
    pub fn restore(&mut self, id: SnapshotId) -> io::Result<RestoreStats> {
        if !self.all_stopped() {
            return Err(io::Error::other("restore while a thread is running"));
        }
        let start = Instant::now();
        let head = self
            .head
            .ok_or_else(|| io::Error::other("restore without a snapshot"))?;
        let live_maps = snapshot::read_maps(self.leader)?;
        let scan = snapshot::scan_pagemap(self.leader, &live_maps)?;

        // 1. mapping table
        let ops = snapshot::plan_maps(
            &live_maps,
            Self::heap_end(&live_maps),
            &self.store.snapshots[id].maps,
            self.store.snapshots[id].brk,
        )
        .map_err(|e| io::Error::other(format!("snapshot {id} unrestorable: {e}")))?;
        let live_brk = Self::heap_end(&live_maps);
        for op in &ops {
            self.inject_map_op(op)?;
        }

        // 2. pages: soft-dirty since `head`, everything copied on either side of the two
        // snapshots' common ancestor, and every page of a range the map ops just brought
        // back (the scan above could not see it; the kernel gave us zeros).
        let mut dirty: HashSet<u64> = scan.dirty.iter().copied().collect();
        dirty.extend(self.store.differing_pages(head, id));
        let mut fresh_ranges: Vec<(u64, u64)> = Vec::new();
        for op in &ops {
            match op {
                MapOp::Mmap { start, len, .. } => fresh_ranges.push((*start, *start + *len)),
                MapOp::Brk { end } if *end > live_brk => fresh_ranges.push((live_brk, *end)),
                _ => {}
            }
        }
        let fresh = fresh_ranges
            .iter()
            .flat_map(|(s, e)| (*s..*e).step_by(PAGE as usize));
        for a in scan.absent.iter().copied().chain(fresh) {
            if self
                .store
                .lookup(id, a)
                .is_some_and(|p| p.iter().any(|b| *b != 0))
            {
                dirty.insert(a);
            }
        }
        let snap_maps = &self.store.snapshots[id].maps;
        let absent: HashSet<u64> = scan.absent.iter().copied().collect();
        let mut written = 0;
        let mut dirty: Vec<u64> = dirty.into_iter().collect();
        dirty.sort_unstable();
        let zero = [0u8; PAGE as usize];
        for addr in dirty {
            if !snap_maps
                .iter()
                .any(|m| m.snapshotted() && m.contains(addr))
            {
                continue;
            }
            let content: &[u8] = match self.store.lookup(id, addr) {
                Some(page) => &page[..],
                None => &zero,
            };
            // An absent page already reads as zero; writing zeros would only allocate it.
            if absent.contains(&addr) && content.iter().all(|b| *b == 0) {
                continue;
            }
            ptrace::write_mem(self.leader, addr, content)?;
            written += 1;
        }

        // 3. registers
        let snap = &self.store.snapshots[id];
        for tr in &snap.regs {
            let mut regs = tr.regs;
            regs.orig_rax = u64::MAX;
            ptrace::setregs(tr.tid, &regs)?;
            ptrace::setregset(tr.tid, ptrace::NT_X86_XSTATE, &tr.xstate)?;
        }
        let snap_tids: HashSet<Pid> = snap.world.threads.iter().map(|t| t.tid).collect();
        for t in &self.world.threads {
            if !snap_tids.contains(&t.tid) && !self.zombies.contains(&t.tid) {
                self.zombies.push(t.tid);
            }
        }

        // 4. world + shared mapping
        self.world = snap.world.clone();
        self.shm.set_budget(0);
        self.shm.set_edges(self.world.edges);
        self.shm.drain_bitmap(&mut crate::shm::Bitmap::default());
        self.new_coverage.clear();
        snapshot::clear_soft_dirty(self.leader)?;
        self.head = Some(id);
        Ok(RestoreStats {
            pages_written: written,
            map_ops: ops.len(),
            threads: snap.regs.len(),
            wall: start.elapsed(),
        })
    }

    /// Execute one mmap-family syscall inside the (stopped) leader.
    fn inject_map_op(&mut self, op: &MapOp) -> io::Result<()> {
        let (nr, args): (i64, [u64; 6]) = match *op {
            MapOp::Munmap { start, len } => (libc::SYS_munmap, [start, len, 0, 0, 0, 0]),
            MapOp::Mmap { start, len, prot } => (
                libc::SYS_mmap,
                [
                    start,
                    len,
                    prot as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as u64,
                    u64::MAX,
                    0,
                ],
            ),
            MapOp::Mprotect { start, len, prot } => {
                (libc::SYS_mprotect, [start, len, prot as u64, 0, 0, 0])
            }
            MapOp::Brk { end } => (libc::SYS_brk, [end, 0, 0, 0, 0, 0]),
        };
        let ret = self.inject_syscall(nr, args)?;
        let ok = match op {
            MapOp::Brk { end } => ret as u64 == *end,
            MapOp::Mmap { start, .. } => ret as u64 == *start,
            _ => ret == 0,
        };
        if !ok {
            return Err(io::Error::other(format!("injected {op:?} returned {ret}")));
        }
        Ok(())
    }

    fn inject_syscall(&mut self, nr: i64, args: [u64; 6]) -> io::Result<i64> {
        if self.syscall_insn == 0 {
            return Err(io::Error::other("no syscall instruction address known yet"));
        }
        let tid = self.leader;
        let saved = ptrace::getregs(tid)?;
        let mut regs = saved;
        regs.orig_rax = u64::MAX;
        regs.rip = self.syscall_insn;
        regs.rax = nr as u64;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
        ptrace::setregs(tid, &regs)?;
        let mut result = None;
        for _ in 0..4 {
            ptrace::singlestep(tid)?;
            match ptrace::wait_pid(tid)? {
                WaitEvent::Signal { sig, .. } if sig == libc::SIGTRAP => {}
                // A traced syscall stops here before executing; rax is still -ENOSYS.
                WaitEvent::Event { event, .. } if event == libc::PTRACE_EVENT_SECCOMP => continue,
                WaitEvent::Event { .. } | WaitEvent::Syscall { .. } => {}
                other => return Err(io::Error::other(format!("inject: unexpected {other:?}"))),
            }
            let now = ptrace::getregs(tid)?;
            if now.rip == self.syscall_insn + 2 {
                result = Some(now.rax as i64);
                break;
            }
        }
        let mut restore = saved;
        restore.orig_rax = u64::MAX;
        ptrace::setregs(tid, &restore)?;
        result.ok_or_else(|| io::Error::other("injected syscall did not execute"))
    }
}
