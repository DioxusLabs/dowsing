//! A live target process under the supervisor. The session runs the target until it needs a
//! decision ([`Event::Decision`]) or terminates ([`Event::Done`]); the caller answers with
//! [`Session::choose`]. At every decision point all target threads are ptrace-stopped, so the
//! session can [`Session::snapshot`] the process and later [`Session::restore`] it.
//!
//! Skipped syscalls are the uniform stop shape: a thread left stopped always has
//! `orig_rax = -1` semantics ("continue at `rip` with these registers"), which is what makes
//! registers captured at one stop valid to load at another.
//!
//! The session is the core: process lifecycle (this file), the ptrace event stream and the
//! scheduler's own syscalls ([`events`]), the schedule loop ([`schedule`]) and snapshots
//! ([`snapshot`]). Every other syscall is handed to a [`Model`] through a [`Cx`].

mod events;
mod schedule;
mod snapshot;

use crate::{
    model::{Cx, Emu, Model, ModelId, Recorder},
    models::{Entropy, Net, Time, net::Protocol},
    oracle::Stderr,
    ptrace::{self, Pid, Regs, WaitEvent},
    seccomp,
    shm::{ENV_SHM_FD, Shm},
    snapshot::{SnapshotId, Store},
    world::*,
};
use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
    time::Duration,
};

pub use snapshot::{RestoreStats, SnapshotStats};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Decision { kind: Kind, n: u32 },
    Done(Outcome),
}

pub struct Options {
    pub watchdog: Duration,
    pub verbose: bool,
    pub capture_stderr: bool,
    /// Send the target's stdout to `/dev/null`.
    pub silence_stdout: bool,
    /// Modelled clients that may connect to the target's listener over a run.
    pub max_clients: usize,
    /// Requests a client may send (a `Payload` decision picks one). Empty = one default GET.
    pub requests: Vec<Vec<u8>>,
    /// Framing and verdicts of what the clients exchange with the target.
    pub protocol: Arc<dyn Protocol>,
    /// CPUs `sched_getaffinity` reports (runtimes size their thread pools by it).
    pub cpus: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            watchdog: Duration::from_secs(3),
            verbose: false,
            capture_stderr: true,
            silence_stdout: true,
            max_clients: 0,
            requests: Vec::new(),
            protocol: Arc::new(crate::models::net::Http1),
            cpus: 2,
        }
    }
}

/// The seccomp program every session installs: the core's syscalls plus the models'.
pub fn filter() -> seccomp::Program {
    seccomp::Program::compose(&[seccomp::CORE, Time::FILTER, Entropy::FILTER, Net::FILTER])
}

pub struct Session {
    shm: Shm,
    leader: Pid,
    opts: Options,
    stderr: Stderr,
    /// Address of a `syscall` instruction in the target (for injected syscalls).
    syscall_insn: u64,
    pub world: World,
    time: Time,
    pub store: Store,
    /// Snapshot the live soft-dirty bits are relative to.
    head: Option<SnapshotId>,
    /// Kernel tasks that exist but are not in `world.sched.threads` (created on another branch).
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

/// The models, borrowed apart from the [`Cx`] they act through.
struct Models<'a> {
    time: &'a mut Time,
    entropy: &'a mut Entropy,
    net: &'a mut Net,
}

impl Session {
    /// fork + seccomp + exec, then run to the exec stop with the vDSO hidden and ASLR off.
    pub fn spawn(program: &str, args: &[String], opts: Options) -> io::Result<Self> {
        events::install_alarm_handler();
        let path = std::path::Path::new(program);
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("target binary {program} not found"),
            ));
        }
        let shm = Shm::new()?;
        let filter = filter();
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
                if seccomp::install(&filter).is_err() {
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
        let net = Net::with(
            opts.max_clients,
            opts.requests.clone(),
            opts.protocol.clone(),
        );
        let mut session = Session {
            shm,
            leader: pid,
            world: World::new(pid, net),
            time: Time,
            opts,
            stderr: Stderr::new(stderr),
            syscall_insn: 0,
            store: Store::default(),
            head: None,
            zombies: Vec::new(),
            orphan_stops: Vec::new(),
            stops: 0,
            uncontrolled: Vec::new(),
            new_coverage: Vec::new(),
            alive: true,
        };
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
        self.stderr.take(&mut self.world.oracle)
    }

    pub fn take_new_coverage(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.new_coverage)
    }

    /// Decisions made since the root.
    pub fn decisions(&self) -> &[Decision] {
        &self.world.decisions
    }

    /// Guard ids of the instrumented edges numbered `start..end` (global edge indices), as far
    /// back as the target's guard log still holds them.
    pub fn guards(&self, start: u64, end: u64) -> Vec<u32> {
        self.shm.guards(start, end)
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

    /// The core as the models see it, and the models, borrowed disjointly.
    fn split(&mut self) -> (Cx<'_>, Models<'_>) {
        let World {
            sched,
            cov,
            trace,
            pending,
            outcome,
            oracle,
            entropy,
            net,
            ..
        } = &mut self.world;
        let cx = Cx {
            leader: self.leader,
            opts: &self.opts,
            sched,
            pending,
            outcome,
            uncontrolled: &mut self.uncontrolled,
            rec: Recorder {
                shm: &self.shm,
                cov,
                trace,
                new_coverage: &mut self.new_coverage,
                stderr: &mut self.stderr,
                oracle,
            },
        };
        let models = Models {
            time: &mut self.time,
            entropy,
            net,
        };
        (cx, models)
    }

    fn cx(&mut self) -> Cx<'_> {
        self.split().0
    }

    fn record(&mut self, thread: usize, point: Point) {
        self.cx().record(thread, point);
    }

    fn stop_here(&mut self, thread: usize, point: Point) {
        self.cx().stop_here(thread, point);
    }

    fn set_return(&mut self, thread: usize, value: i64) -> io::Result<()> {
        self.cx().set_return(thread, value)
    }

    fn skip_syscall(&self, tid: Pid, regs: &mut Regs, value: i64) -> io::Result<()> {
        regs.orig_rax = u64::MAX;
        regs.rax = value as u64;
        ptrace::setregs(tid, regs)
    }

    // ----------------------------------------------------------------------------------------
    // Models
    // ----------------------------------------------------------------------------------------

    /// Which model the seccomp filter stopped for, if any.
    fn model_for(nr: i64) -> Option<ModelId> {
        if Time::FILTER.traces(nr) {
            Some(ModelId::Time)
        } else if Entropy::FILTER.traces(nr) {
            Some(ModelId::Entropy)
        } else if Net::FILTER.traces(nr) {
            Some(ModelId::Net)
        } else {
            None
        }
    }

    /// A seccomp stop on `model`'s syscall by `index`.
    fn model_syscall(&mut self, model: ModelId, index: usize, regs: Regs) -> io::Result<()> {
        let (mut cx, m) = self.split();
        let emu = match model {
            ModelId::Time => m.time.syscall(&mut cx, index, &regs)?,
            ModelId::Entropy => m.entropy.syscall(&mut cx, index, &regs)?,
            ModelId::Net => m.net.syscall(&mut cx, index, &regs)?,
        };
        self.apply_emu(index, regs, emu)
    }

    fn apply_emu(&mut self, index: usize, mut regs: Regs, emu: Emu) -> io::Result<()> {
        let tid = self.world.sched.threads[index].tid;
        match emu {
            Emu::Ret(value) => {
                self.skip_syscall(tid, &mut regs, value)?;
                if self.world.outcome.is_some() {
                    self.stop_here(index, Point::Oracle);
                    Ok(())
                } else {
                    ptrace::cont(tid, 0)
                }
            }
            Emu::Stop(value, point) => {
                self.skip_syscall(tid, &mut regs, value)?;
                self.stop_here(index, point);
                Ok(())
            }
            Emu::Wait(state, point) => {
                let entry = regs;
                self.skip_syscall(tid, &mut regs, 0)?;
                let t = &mut self.world.sched.threads[index];
                t.blocked = Some(entry);
                t.state = state;
                self.world.sched.current = None;
                self.record(index, point);
                Ok(())
            }
            Emu::Pass => {
                self.uncontrolled.push(format!(
                    "syscall {} passed through on T{index}",
                    regs.orig_rax as i64
                ));
                ptrace::cont(tid, 0)
            }
            Emu::Kernel => ptrace::cont(tid, 0),
        }
    }

    /// Events every model could inject now.
    fn model_events(&mut self) -> Vec<Candidate> {
        let (cx, m) = self.split();
        let mut ev: Vec<Candidate> = Vec::new();
        ev.extend(m.time.events(&cx).into_iter().map(Candidate::Ext));
        ev.extend(m.entropy.events(&cx).into_iter().map(Candidate::Ext));
        ev.extend(m.net.events(&cx).into_iter().map(Candidate::Ext));
        ev
    }

    fn model_act(&mut self, ev: crate::model::Ext) -> io::Result<()> {
        let (mut cx, m) = self.split();
        match ev.model {
            ModelId::Time => m.time.act(&mut cx, ev),
            ModelId::Entropy => m.entropy.act(&mut cx, ev),
            ModelId::Net => m.net.act(&mut cx, ev),
        }
    }

    fn model_choose(
        &mut self,
        model: ModelId,
        kind: Kind,
        actor: usize,
        choice: u32,
    ) -> io::Result<()> {
        let (mut cx, m) = self.split();
        match model {
            ModelId::Time => m.time.choose(&mut cx, kind, actor, choice),
            ModelId::Entropy => m.entropy.choose(&mut cx, kind, actor, choice),
            ModelId::Net => m.net.choose(&mut cx, kind, actor, choice),
        }
    }

    /// The first failure any model sees in the idle state.
    fn model_idle(&mut self) -> Option<Outcome> {
        let (cx, m) = self.split();
        m.time
            .idle(&cx)
            .or_else(|| m.entropy.idle(&cx))
            .or_else(|| m.net.idle(&cx))
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
            if self.world.sched.current.is_none() && !self.world.sched.any_running() {
                self.schedule()?;
                continue;
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
            Pending::Budget { thread } => self.resume(thread, choice),
            Pending::Variant { thread, .. } => {
                self.set_return(thread, choice as i64)?;
                self.world.sched.threads[thread].state = ThreadState::Stopped;
                Ok(())
            }
            Pending::Model {
                model, kind, actor, ..
            } => self.model_choose(model, kind, actor, choice),
        }
    }
}
