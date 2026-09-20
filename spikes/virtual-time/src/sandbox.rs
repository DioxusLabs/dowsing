//! The supervisor: spawns the target under ptrace+seccomp, virtualises time, parks blocked
//! threads and draws scheduling decisions from a dowsing `CaseRng`.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    hash::{DefaultHasher, Hasher},
    io,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use iterator_fuzz::{CaseRng, coverage::CoverageCapture};
use libc::{pid_t, user_regs_struct};
use rand::RngCore;

use crate::{
    clock::{self, VirtualClock},
    coverage::SharedSlot,
    ptrace,
    seccomp::{self, ANNOUNCE_NR},
    waits::{self, Restart, Wait, WaitKind},
};

const QUANTUM_TABLE_NS: [u64; 4] = [1_000, 100, 10_000, 1_000_000];
const MAGNITUDE_TABLE_NS: [u64; 6] = [
    1_000_000,
    10_000_000,
    100_000_000,
    clock::NANOS,
    10 * clock::NANOS,
    60 * clock::NANOS,
];
const REALTIME_STEP_NS: i64 = 3600 * clock::NANOS as i64;
const FUTEX_CMD_MASK: u64 = !(libc::FUTEX_PRIVATE_FLAG | libc::FUTEX_CLOCK_REALTIME) as u64;
const SYSCALL_INSN_LEN: u64 = 2;
/// Scratch bytes for zero timespecs live this far below the tracee's stack pointer (well past
/// the 128-byte red zone) until an injected scratch page exists.
const SCRATCH_BELOW_RSP: u64 = 512;

/// One scheduling decision drawn from the `CaseRng`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jump {
    /// 0 = advance to the earliest deadline (natural), 1 = jump to the latest deadline,
    /// 2 = overshoot the earliest deadline by `magnitude`, 3 = natural + realtime step.
    pub kind: u8,
    pub magnitude: u8,
}

/// Everything the run drew from the fuzzer.
#[derive(Debug, Clone, Default)]
pub struct Decisions {
    pub quantum_variant: usize,
    pub realtime_variant: usize,
    pub jumps: Vec<Jump>,
    pub jumps_used: usize,
    pub non_natural_jumps: usize,
    pub random_bytes: usize,
}

impl Decisions {
    pub fn draw<C: CoverageCapture>(rng: &mut CaseRng<C>, max_jumps: usize) -> Self {
        let quantum_variant = rng.variant(QUANTUM_TABLE_NS.len());
        let realtime_variant = rng.variant(3);
        let mut jumps = Vec::new();
        for mut item in rng.range(0..=max_jumps) {
            let kind = item.variant(4) as u8;
            let magnitude = item.variant(MAGNITUDE_TABLE_NS.len()) as u8;
            jumps.push(Jump { kind, magnitude });
        }
        Self {
            quantum_variant,
            realtime_variant,
            jumps,
            ..Self::default()
        }
    }

    /// Domain cost for `cautious()`: fewer jumps, fewer non-natural jumps, less virtual time.
    pub fn cost(&self, virtual_elapsed: Duration) -> usize {
        self.jumps_used * 1000
            + self.non_natural_jumps * 10_000
            + virtual_elapsed.as_secs() as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Exited(i32),
    Signaled(i32),
    /// Wall-clock watchdog fired (a thread was blocked in an unsupervised syscall or spinning).
    Hang,
    /// Every thread was parked without a deadline and nothing was ready.
    Deadlock,
    /// Virtual time went past the configured limit.
    VirtualLimit,
    Error(String),
}

impl Outcome {
    pub fn is_failure(&self) -> bool {
        !matches!(self, Outcome::Exited(0))
    }
}

#[derive(Debug, Clone, Default)]
pub struct StopStats {
    pub stops: usize,
    pub clock_reads: usize,
    pub sleeps: usize,
    pub futex_probes: usize,
    pub futex_parked: usize,
    pub poll_probes: usize,
    pub poll_parked: usize,
    pub wakes: usize,
    pub restarts: usize,
    pub jumps: usize,
    pub natural_jumps: usize,
    pub getrandom: usize,
    pub threads: usize,
}

#[derive(Debug, Clone)]
pub struct RunReport {
    pub outcome: Outcome,
    pub virtual_elapsed: Duration,
    pub wall: Duration,
    pub stats: StopStats,
    pub decisions: Decisions,
    /// Hash of the ordered event log; identical hashes mean an identical schedule.
    pub event_hash: u64,
    pub events: Vec<String>,
    pub coverage_bytes: usize,
}

impl RunReport {
    pub fn cost(&self) -> usize {
        self.decisions.cost(self.virtual_elapsed)
    }
}

/// Builder for one supervised program.
#[derive(Debug, Clone)]
pub struct Sandbox {
    program: PathBuf,
    args: Vec<OsString>,
    envs: Vec<(OsString, OsString)>,
    quiet: bool,
    wall_limit: Duration,
    virtual_limit: Option<Duration>,
    max_jumps: usize,
    keep_events: bool,
    hide_vdso: bool,
    coverage_slot: Option<SharedSlot>,
}

impl Sandbox {
    pub fn new(program: impl AsRef<Path>) -> Self {
        Self {
            program: program.as_ref().to_path_buf(),
            args: Vec::new(),
            envs: Vec::new(),
            quiet: false,
            wall_limit: Duration::from_secs(10),
            virtual_limit: None,
            max_jumps: 16,
            keep_events: false,
            hide_vdso: true,
            coverage_slot: None,
        }
    }

    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.envs.push((key.into(), value.into()));
        self
    }

    /// Discard the target's stdout/stderr.
    pub fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    pub fn wall_limit(mut self, limit: Duration) -> Self {
        self.wall_limit = limit;
        self
    }

    pub fn virtual_limit(mut self, limit: Duration) -> Self {
        self.virtual_limit = Some(limit);
        self
    }

    pub fn max_jumps(mut self, max_jumps: usize) -> Self {
        self.max_jumps = max_jumps;
        self
    }

    pub fn keep_events(mut self, keep: bool) -> Self {
        self.keep_events = keep;
        self
    }

    /// Leave `AT_SYSINFO_EHDR` alone (measures the vDSO leak; clock reads bypass the sandbox).
    pub fn hide_vdso(mut self, hide: bool) -> Self {
        self.hide_vdso = hide;
        self
    }

    pub fn with_coverage_slot(mut self, slot: SharedSlot) -> Self {
        self.coverage_slot = Some(slot);
        self
    }

    /// Run the target once, drawing every decision from `rng`.
    pub fn run<C: CoverageCapture>(&self, rng: &mut CaseRng<C>) -> RunReport {
        let decisions = Decisions::draw(rng, self.max_jumps);
        let mut run = Run::new(self, decisions, rng);
        let start = Instant::now();
        let outcome = match run.spawn_and_supervise() {
            Ok(outcome) => outcome,
            Err(err) => {
                run.kill();
                Outcome::Error(err.to_string())
            }
        };
        run.stop_watchdog();
        let coverage_bytes = run.counters.as_ref().map_or(0, Vec::len);
        if let Some(slot) = &self.coverage_slot
            && let Ok(mut slot) = slot.lock()
        {
            slot.counters = run.counters.take();
        }
        RunReport {
            outcome,
            virtual_elapsed: Duration::from_nanos(run.clock.now()),
            wall: start.elapsed(),
            stats: run.stats,
            decisions: run.decisions,
            event_hash: run.hasher.finish(),
            events: run.events,
            coverage_bytes,
        }
    }
}

struct Probe {
    kind: WaitKind,
    deadline: Option<u64>,
    futex: Option<(pid_t, u64)>,
    readiness: Vec<(i32, i16)>,
    nr: i64,
    entry_regs: user_regs_struct,
    /// Seen the syscall-entry stop already; the next stop is the exit stop.
    seen_entry: bool,
}

struct Thread {
    index: usize,
    tgid: pid_t,
    fresh: bool,
    wait: Option<Wait>,
    restart: Option<Restart>,
    probe: Option<Probe>,
}

struct Run<'a, C: CoverageCapture> {
    sandbox: &'a Sandbox,
    rng: &'a mut CaseRng<C>,
    decisions: Decisions,
    clock: VirtualClock,
    threads: BTreeMap<pid_t, Thread>,
    next_index: usize,
    main_pid: pid_t,
    main_status: Option<Outcome>,
    announced: BTreeMap<pid_t, (u64, u64)>,
    counters: Option<Vec<u8>>,
    stats: StopStats,
    hasher: DefaultHasher,
    events: Vec<String>,
    watchdog: Option<mpsc::Sender<()>>,
    hung: Arc<AtomicBool>,
    realtime_applied: bool,
    forced: Option<Outcome>,
}

fn ready_kill(pid: pid_t) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

impl<'a, C: CoverageCapture> Run<'a, C> {
    fn new(sandbox: &'a Sandbox, decisions: Decisions, rng: &'a mut CaseRng<C>) -> Self {
        let clock = VirtualClock::new(QUANTUM_TABLE_NS[decisions.quantum_variant]);
        Self {
            sandbox,
            rng,
            decisions,
            clock,
            threads: BTreeMap::new(),
            next_index: 0,
            main_pid: 0,
            main_status: None,
            announced: BTreeMap::new(),
            counters: None,
            stats: StopStats::default(),
            hasher: DefaultHasher::new(),
            events: Vec::new(),
            watchdog: None,
            hung: Arc::new(AtomicBool::new(false)),
            realtime_applied: false,
            forced: None,
        }
    }

    fn log(&mut self, tid: pid_t, what: &str, detail: impl std::fmt::Display) {
        let index = self.threads.get(&tid).map_or(usize::MAX, |t| t.index);
        let line = format!("t{index} @{} {what} {detail}", self.clock.now());
        self.hasher.write(line.as_bytes());
        if self.sandbox.keep_events {
            self.events.push(line);
        }
    }

    fn kill(&mut self) {
        if self.main_pid > 0 {
            ready_kill(self.main_pid);
        }
    }

    fn stop_watchdog(&mut self) {
        self.watchdog.take();
    }

    fn register(&mut self, tid: pid_t, fresh: bool) -> io::Result<()> {
        if self.threads.contains_key(&tid) {
            return Ok(());
        }
        let tgid = ptrace::tgid_of(tid).unwrap_or(tid);
        let index = self.next_index;
        self.next_index += 1;
        self.stats.threads += 1;
        self.threads.insert(
            tid,
            Thread {
                index,
                tgid,
                fresh,
                wait: None,
                restart: None,
                probe: None,
            },
        );
        Ok(())
    }

    fn spawn_and_supervise(&mut self) -> io::Result<Outcome> {
        let mut cmd = Command::new(&self.sandbox.program);
        cmd.args(&self.sandbox.args);
        for (k, v) in &self.sandbox.envs {
            cmd.env(k, v);
        }
        if self.sandbox.quiet {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
        let filter = seccomp::build_filter(seccomp::TRACED_SYSCALLS);
        unsafe {
            cmd.pre_exec(move || {
                ptrace::traceme()?;
                seccomp::install(&filter)?;
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let pid = child.id() as pid_t;
        self.main_pid = pid;

        // Wall-clock watchdog: kills the tracee if it stops making supervised progress.
        let (tx, rx) = mpsc::channel::<()>();
        let hung = Arc::clone(&self.hung);
        let limit = self.sandbox.wall_limit;
        std::thread::spawn(move || {
            if let Err(mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(limit) {
                hung.store(true, Ordering::SeqCst);
                ready_kill(pid);
            }
        });
        self.watchdog = Some(tx);

        // First stop: SIGTRAP after the exec (PTRACE_TRACEME semantics).
        let (tid, status) = self.wait_any()?;
        if tid != pid || !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGTRAP {
            return Err(io::Error::other(format!(
                "unexpected first stop: tid {tid} status {status:#x}"
            )));
        }
        ptrace::setoptions(pid, ptrace::OPTIONS)?;
        self.register(pid, false)?;
        self.on_exec(pid)?;
        ptrace::cont(pid, 0)?;

        loop {
            if let Some(outcome) = self.forced.take() {
                self.kill();
                self.drain();
                return Ok(outcome);
            }
            if self.threads.is_empty() {
                break;
            }
            if self.threads.values().all(|t| t.wait.is_some()) {
                self.quiesce()?;
                continue;
            }
            let (tid, status) = match self.wait_any() {
                Ok(pair) => pair,
                Err(err) if err.raw_os_error() == Some(libc::ECHILD) => break,
                Err(err) => return Err(err),
            };
            self.handle_stop(tid, status)?;
        }

        if self.hung.load(Ordering::SeqCst) {
            return Ok(Outcome::Hang);
        }
        Ok(self
            .main_status
            .take()
            .unwrap_or_else(|| Outcome::Error("main thread never reported exit".into())))
    }

    fn wait_any(&mut self) -> io::Result<(pid_t, i32)> {
        loop {
            let mut status = 0;
            let tid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
            if tid < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            return Ok((tid, status));
        }
    }

    /// After a forced kill, reap everything so no zombie threads linger.
    fn drain(&mut self) {
        while !self.threads.is_empty() {
            match self.wait_any() {
                Ok((tid, status)) => {
                    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        self.threads.remove(&tid);
                    } else {
                        let _ = ptrace::cont(tid, 0);
                    }
                }
                Err(_) => break,
            }
        }
    }

    fn handle_stop(&mut self, tid: pid_t, status: i32) -> io::Result<()> {
        self.stats.stops += 1;
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            let outcome = if libc::WIFEXITED(status) {
                Outcome::Exited(libc::WEXITSTATUS(status))
            } else {
                Outcome::Signaled(libc::WTERMSIG(status))
            };
            self.log(tid, "exit", format!("{outcome:?}"));
            if tid == self.main_pid {
                self.main_status = Some(outcome);
            }
            let exited = self.threads.remove(&tid);
            // The kernel clears the exiting thread's `tid` word and wakes joiners itself
            // (CLONE_CHILD_CLEARTID), without a FUTEX_WAKE syscall we could observe: re-probe
            // every futex waiter in that process.
            if let Some(exited) = exited {
                let waiters: Vec<pid_t> = self
                    .threads
                    .iter()
                    .filter(|(_, t)| {
                        t.tgid == exited.tgid
                            && t.wait.as_ref().is_some_and(|w| w.kind == WaitKind::Futex)
                    })
                    .map(|(tid, _)| *tid)
                    .collect();
                for waiter in waiters {
                    self.restart_wait(waiter)?;
                }
            }
            return Ok(());
        }
        if !libc::WIFSTOPPED(status) {
            return Ok(());
        }
        self.register(tid, true)?;
        let sig = libc::WSTOPSIG(status);
        let event = status >> 16;
        match (sig, event) {
            (libc::SIGTRAP, ptrace::PTRACE_EVENT_SECCOMP) => self.on_seccomp(tid),
            (libc::SIGTRAP, ptrace::PTRACE_EVENT_EXEC) => {
                self.on_exec(tid)?;
                ptrace::cont(tid, 0)
            }
            (
                libc::SIGTRAP,
                ptrace::PTRACE_EVENT_CLONE | ptrace::PTRACE_EVENT_FORK | ptrace::PTRACE_EVENT_VFORK,
            ) => {
                let new = ptrace::geteventmsg(tid)? as pid_t;
                self.register(new, true)?;
                let index = self.threads[&new].index;
                self.log(tid, "clone", index);
                ptrace::cont(tid, 0)
            }
            (libc::SIGTRAP, ptrace::PTRACE_EVENT_EXIT) => {
                self.read_counters(tid);
                ptrace::cont(tid, 0)
            }
            (libc::SIGTRAP, ptrace::PTRACE_EVENT_STOP) => ptrace::cont(tid, 0),
            (s, 0) if s == libc::SIGTRAP | 0x80 => self.on_syscall_stop(tid),
            (libc::SIGSTOP, 0) => {
                let thread = self.threads.get_mut(&tid).expect("registered");
                let suppress = thread.fresh;
                thread.fresh = false;
                ptrace::cont(tid, if suppress { 0 } else { libc::SIGSTOP })
            }
            (s, 0) => {
                self.log(tid, "signal", s);
                ptrace::cont(tid, s)
            }
            _ => ptrace::cont(tid, 0),
        }
    }

    fn on_exec(&mut self, tid: pid_t) -> io::Result<()> {
        let regs = ptrace::getregs(tid)?;
        let hidden = if self.sandbox.hide_vdso {
            ptrace::hide_vdso_in_auxv(tid, regs.rsp)?
        } else {
            false
        };
        self.log(tid, "exec", format!("vdso_hidden={hidden}"));
        Ok(())
    }

    fn read_counters(&mut self, tid: pid_t) {
        let Some(tgid) = self.threads.get(&tid).map(|t| t.tgid) else {
            return;
        };
        let Some(&(start, end)) = self.announced.get(&tgid) else {
            return;
        };
        let len = end.saturating_sub(start).min(16 << 20) as usize;
        let mut buf = vec![0_u8; len];
        if ptrace::read_mem(tid, start, &mut buf).is_ok() {
            self.counters = Some(buf);
        }
    }

    fn skip(&mut self, tid: pid_t, mut regs: user_regs_struct, ret: i64) -> io::Result<()> {
        regs.orig_rax = u64::MAX;
        regs.rax = ret as u64;
        ptrace::setregs(tid, &regs)?;
        ptrace::cont(tid, 0)
    }

    fn scratch_timespec(&self, tid: pid_t, regs: &user_regs_struct) -> io::Result<u64> {
        let scratch = (regs.rsp - SCRATCH_BELOW_RSP) & !0xf;
        ptrace::write_timespec(tid, scratch, 0, 0)?;
        Ok(scratch)
    }

    fn on_seccomp(&mut self, tid: pid_t) -> io::Result<()> {
        let regs = ptrace::getregs(tid)?;
        let nr = regs.orig_rax as i64;
        let (a1, a2, a3, a4, a5) = (regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8);
        match nr {
            libc::SYS_clock_gettime => {
                if let Some((s, n)) = self.clock.read(a1 as i64) {
                    self.stats.clock_reads += 1;
                    if a2 != 0 {
                        ptrace::write_timespec(tid, a2, s, n)?;
                    }
                    self.skip(tid, regs, 0)
                } else {
                    ptrace::cont(tid, 0)
                }
            }
            libc::SYS_gettimeofday => {
                let (s, n) = self
                    .clock
                    .read(libc::CLOCK_REALTIME as i64)
                    .expect("realtime is virtualised");
                self.stats.clock_reads += 1;
                if a1 != 0 {
                    ptrace::write_timespec(tid, a1, s, n / 1000)?;
                }
                if a2 != 0 {
                    ptrace::write_mem(tid, a2, &[0_u8; 8])?;
                }
                self.skip(tid, regs, 0)
            }
            libc::SYS_time => {
                let (s, _) = self
                    .clock
                    .read(libc::CLOCK_REALTIME as i64)
                    .expect("realtime is virtualised");
                self.stats.clock_reads += 1;
                if a1 != 0 {
                    ptrace::write_u64(tid, a1, s as u64)?;
                }
                self.skip(tid, regs, s)
            }
            libc::SYS_nanosleep => {
                let (s, n) = ptrace::read_timespec(tid, a1)?;
                let deadline = self.clock.deadline_from_relative(s, n);
                self.park_sleep(tid, regs, deadline)
            }
            libc::SYS_clock_nanosleep => {
                let (s, n) = ptrace::read_timespec(tid, a3)?;
                let deadline = if a2 & libc::TIMER_ABSTIME as u64 != 0 {
                    match self.clock.deadline_from_absolute(a1 as i64, s, n) {
                        Some(d) => d,
                        None => return ptrace::cont(tid, 0),
                    }
                } else {
                    self.clock.deadline_from_relative(s, n)
                };
                self.park_sleep(tid, regs, deadline)
            }
            libc::SYS_futex => {
                let cmd = a2 & FUTEX_CMD_MASK;
                match cmd as i32 {
                    libc::FUTEX_WAIT | libc::FUTEX_WAIT_BITSET => {
                        let restart = self.threads.get_mut(&tid).and_then(|t| t.restart.take());
                        let deadline = match restart {
                            Some(r) => r.deadline,
                            None if a4 != 0 => {
                                let (s, n) = ptrace::read_timespec(tid, a4)?;
                                if cmd as i32 == libc::FUTEX_WAIT {
                                    Some(self.clock.deadline_from_relative(s, n))
                                } else {
                                    let clk = if a2 & libc::FUTEX_CLOCK_REALTIME as u64 != 0 {
                                        libc::CLOCK_REALTIME
                                    } else {
                                        libc::CLOCK_MONOTONIC
                                    };
                                    self.clock.deadline_from_absolute(clk as i64, s, n)
                                }
                            }
                            None => None,
                        };
                        let tgid = self.threads[&tid].tgid;
                        let scratch = self.scratch_timespec(tid, &regs)?;
                        let mut probe_regs = regs;
                        probe_regs.r10 = scratch;
                        self.stats.futex_probes += 1;
                        self.start_probe(
                            tid,
                            probe_regs,
                            Probe {
                                kind: WaitKind::Futex,
                                deadline,
                                futex: Some((tgid, a1)),
                                readiness: Vec::new(),
                                nr,
                                entry_regs: regs,
                                seen_entry: false,
                            },
                        )
                    }
                    libc::FUTEX_WAKE
                    | libc::FUTEX_WAKE_BITSET
                    | libc::FUTEX_REQUEUE
                    | libc::FUTEX_CMP_REQUEUE
                    | libc::FUTEX_WAKE_OP => {
                        let tgid = self.threads[&tid].tgid;
                        self.stats.wakes += 1;
                        self.log(tid, "futex_wake", cmd);
                        ptrace::cont(tid, 0)?;
                        let mut addrs = vec![(tgid, a1)];
                        if matches!(
                            cmd as i32,
                            libc::FUTEX_REQUEUE | libc::FUTEX_CMP_REQUEUE | libc::FUTEX_WAKE_OP
                        ) {
                            addrs.push((tgid, a5));
                        }
                        self.wake_futex_waiters(&addrs)
                    }
                    _ => ptrace::cont(tid, 0),
                }
            }
            libc::SYS_epoll_wait | libc::SYS_epoll_pwait => {
                let timeout_ms = a4 as i32;
                if timeout_ms == 0 {
                    return ptrace::cont(tid, 0);
                }
                let deadline = self.restart_or_relative_ms(tid, timeout_ms);
                let mut probe_regs = regs;
                probe_regs.r10 = 0;
                self.start_poll_probe(tid, regs, probe_regs, nr, deadline, vec![(a1 as i32, libc::POLLIN)])
            }
            libc::SYS_epoll_pwait2 => {
                let deadline = self.restart_or_relative_ts(tid, a4)?;
                if deadline == Some(self.clock.now()) && a4 != 0 {
                    return ptrace::cont(tid, 0);
                }
                let scratch = self.scratch_timespec(tid, &regs)?;
                let mut probe_regs = regs;
                probe_regs.r10 = scratch;
                self.start_poll_probe(tid, regs, probe_regs, nr, deadline, vec![(a1 as i32, libc::POLLIN)])
            }
            libc::SYS_poll => {
                let timeout_ms = a3 as i32;
                if timeout_ms == 0 {
                    return ptrace::cont(tid, 0);
                }
                let deadline = self.restart_or_relative_ms(tid, timeout_ms);
                let readiness = waits::read_pollfds(tid, a1, a2)?;
                let mut probe_regs = regs;
                probe_regs.rdx = 0;
                self.start_poll_probe(tid, regs, probe_regs, nr, deadline, readiness)
            }
            libc::SYS_ppoll => {
                let deadline = self.restart_or_relative_ts(tid, a3)?;
                if deadline == Some(self.clock.now()) && a3 != 0 {
                    return ptrace::cont(tid, 0);
                }
                let readiness = waits::read_pollfds(tid, a1, a2)?;
                let scratch = self.scratch_timespec(tid, &regs)?;
                let mut probe_regs = regs;
                probe_regs.rdx = scratch;
                self.start_poll_probe(tid, regs, probe_regs, nr, deadline, readiness)
            }
            libc::SYS_select | libc::SYS_pselect6 => {
                let deadline = if nr == libc::SYS_select {
                    self.restart_or_relative_timeval(tid, a5)?
                } else {
                    self.restart_or_relative_ts(tid, a5)?
                };
                if deadline == Some(self.clock.now()) && a5 != 0 {
                    return ptrace::cont(tid, 0);
                }
                let readiness = waits::read_fdsets(tid, a1, a2, a3, a4)?;
                let scratch = self.scratch_timespec(tid, &regs)?;
                let mut probe_regs = regs;
                probe_regs.r8 = scratch;
                self.start_poll_probe(tid, regs, probe_regs, nr, deadline, readiness)
            }
            libc::SYS_getrandom => {
                let len = (a2 as usize).min(4096);
                let mut buf = vec![0_u8; len];
                self.rng.fill_bytes(&mut buf);
                self.decisions.random_bytes += len;
                self.stats.getrandom += 1;
                ptrace::write_mem(tid, a1, &buf)?;
                self.log(tid, "getrandom", len);
                self.skip(tid, regs, len as i64)
            }
            libc::SYS_timerfd_settime => {
                // Not virtualised in this spike: runs against the real clock.
                self.log(tid, "timerfd_settime_native", a1);
                ptrace::cont(tid, 0)
            }
            ANNOUNCE_NR => {
                let tgid = self.threads[&tid].tgid;
                self.announced.insert(tgid, (a1, a2));
                self.log(tid, "announce", a2.saturating_sub(a1));
                self.skip(tid, regs, 0)
            }
            _ => ptrace::cont(tid, 0),
        }
    }

    fn restart_or_relative_ms(&mut self, tid: pid_t, timeout_ms: i32) -> Option<u64> {
        if let Some(r) = self.threads.get_mut(&tid).and_then(|t| t.restart.take()) {
            return r.deadline;
        }
        if timeout_ms < 0 {
            None
        } else {
            Some(
                self.clock
                    .deadline_from_relative(0, i64::from(timeout_ms) * 1_000_000),
            )
        }
    }

    fn restart_or_relative_ts(&mut self, tid: pid_t, addr: u64) -> io::Result<Option<u64>> {
        if let Some(r) = self.threads.get_mut(&tid).and_then(|t| t.restart.take()) {
            return Ok(r.deadline);
        }
        if addr == 0 {
            return Ok(None);
        }
        let (s, n) = ptrace::read_timespec(tid, addr)?;
        Ok(Some(self.clock.deadline_from_relative(s, n)))
    }

    fn restart_or_relative_timeval(&mut self, tid: pid_t, addr: u64) -> io::Result<Option<u64>> {
        if let Some(r) = self.threads.get_mut(&tid).and_then(|t| t.restart.take()) {
            return Ok(r.deadline);
        }
        if addr == 0 {
            return Ok(None);
        }
        let (s, us) = ptrace::read_timespec(tid, addr)?;
        Ok(Some(self.clock.deadline_from_relative(s, us * 1000)))
    }

    fn park_sleep(&mut self, tid: pid_t, regs: user_regs_struct, deadline: u64) -> io::Result<()> {
        self.stats.sleeps += 1;
        self.log(tid, "sleep", deadline);
        if deadline <= self.clock.now() {
            return self.skip(tid, regs, 0);
        }
        let thread = self.threads.get_mut(&tid).expect("registered");
        thread.wait = Some(Wait {
            kind: WaitKind::Sleep,
            deadline: Some(deadline),
            futex: None,
            readiness: Vec::new(),
        });
        Ok(())
    }

    fn start_poll_probe(
        &mut self,
        tid: pid_t,
        regs: user_regs_struct,
        probe_regs: user_regs_struct,
        nr: i64,
        deadline: Option<u64>,
        readiness: Vec<(i32, i16)>,
    ) -> io::Result<()> {
        self.stats.poll_probes += 1;
        self.start_probe(
            tid,
            probe_regs,
            Probe {
                kind: WaitKind::Poll,
                deadline,
                futex: None,
                readiness,
                nr,
                entry_regs: regs,
                seen_entry: false,
            },
        )
    }

    fn start_probe(
        &mut self,
        tid: pid_t,
        probe_regs: user_regs_struct,
        probe: Probe,
    ) -> io::Result<()> {
        ptrace::setregs(tid, &probe_regs)?;
        let thread = self.threads.get_mut(&tid).expect("registered");
        thread.probe = Some(probe);
        ptrace::syscall(tid, 0)
    }

    /// SIGTRAP|0x80 stop: syscall-entry or syscall-exit of a probe.
    fn on_syscall_stop(&mut self, tid: pid_t) -> io::Result<()> {
        let regs = ptrace::getregs(tid)?;
        let Some(probe) = self.threads.get_mut(&tid).and_then(|t| t.probe.as_mut()) else {
            return ptrace::cont(tid, 0);
        };
        if !probe.seen_entry && regs.rax as i64 == -(libc::ENOSYS as i64) {
            probe.seen_entry = true;
            return ptrace::syscall(tid, 0);
        }
        let probe = self
            .threads
            .get_mut(&tid)
            .and_then(|t| t.probe.take())
            .expect("probe present");
        let result = regs.rax as i64;
        let would_block = match probe.kind {
            WaitKind::Futex => result == -(libc::ETIMEDOUT as i64),
            WaitKind::Poll => result == 0,
            WaitKind::Sleep => false,
        };
        self.log(tid, "probe", format!("nr={} result={result} block={would_block}", probe.nr));
        if !would_block {
            return ptrace::cont(tid, 0);
        }
        if let Some(deadline) = probe.deadline
            && deadline <= self.clock.now()
        {
            // Already timed out in virtual time; the probe result is the right answer.
            return ptrace::cont(tid, 0);
        }
        match probe.kind {
            WaitKind::Futex => self.stats.futex_parked += 1,
            WaitKind::Poll => self.stats.poll_parked += 1,
            WaitKind::Sleep => {}
        }
        let thread = self.threads.get_mut(&tid).expect("registered");
        thread.wait = Some(Wait {
            kind: probe.kind,
            deadline: probe.deadline,
            futex: probe.futex,
            readiness: probe.readiness.clone(),
        });
        thread.probe = Some(probe);
        Ok(())
    }

    fn wake_futex_waiters(&mut self, addrs: &[(pid_t, u64)]) -> io::Result<()> {
        let targets: Vec<pid_t> = self
            .threads
            .iter()
            .filter(|(_, t)| {
                t.wait
                    .as_ref()
                    .and_then(|w| w.futex)
                    .is_some_and(|f| addrs.contains(&f))
            })
            .map(|(tid, _)| *tid)
            .collect();
        for tid in targets {
            self.restart_wait(tid)?;
        }
        Ok(())
    }

    /// Re-issue a parked probe from scratch (rip -= 2, rax = nr) with the original registers.
    fn restart_wait(&mut self, tid: pid_t) -> io::Result<()> {
        let thread = self.threads.get_mut(&tid).expect("registered");
        let Some(wait) = thread.wait.take() else {
            return Ok(());
        };
        let probe = thread.probe.take().expect("parked probe keeps its registers");
        thread.restart = Some(Restart {
            deadline: wait.deadline,
        });
        let mut regs = probe.entry_regs;
        regs.rip -= SYSCALL_INSN_LEN;
        regs.rax = probe.nr as u64;
        regs.orig_rax = probe.nr as u64;
        self.stats.restarts += 1;
        self.log(tid, "restart", probe.nr);
        ptrace::setregs(tid, &regs)?;
        ptrace::cont(tid, 0)
    }

    /// Finish a parked wait because its deadline passed.
    fn complete_timeout(&mut self, tid: pid_t) -> io::Result<()> {
        let thread = self.threads.get_mut(&tid).expect("registered");
        let Some(wait) = thread.wait.take() else {
            return Ok(());
        };
        thread.probe = None;
        self.log(tid, "timeout", format!("{:?}", wait.kind));
        match wait.kind {
            WaitKind::Sleep => {
                let regs = ptrace::getregs(tid)?;
                self.skip(tid, regs, 0)
            }
            // Probe results (-ETIMEDOUT / 0) are already in rax at the exit stop.
            WaitKind::Futex | WaitKind::Poll => ptrace::cont(tid, 0),
        }
    }

    fn parked_poll_threads(&self) -> Vec<(pid_t, pid_t, Vec<(i32, i16)>)> {
        self.threads
            .iter()
            .filter_map(|(tid, t)| {
                let w = t.wait.as_ref()?;
                (w.kind == WaitKind::Poll && !w.readiness.is_empty())
                    .then(|| (*tid, t.tgid, w.readiness.clone()))
            })
            .collect()
    }

    fn restart_ready(&mut self, timeout_ms: i32) -> io::Result<bool> {
        let mut restarted = false;
        for (tid, tgid, readiness) in self.parked_poll_threads() {
            if waits::any_ready(tgid, &readiness, timeout_ms)? {
                self.log(tid, "ready", readiness.len());
                self.restart_wait(tid)?;
                restarted = true;
            }
        }
        Ok(restarted)
    }

    /// Every supervised thread is parked: advance virtual time (or find readiness / deadlock).
    fn quiesce(&mut self) -> io::Result<()> {
        if self.restart_ready(0)? {
            return Ok(());
        }
        let deadlines: BTreeSet<u64> = self
            .threads
            .values()
            .filter_map(|t| t.wait.as_ref().and_then(|w| w.deadline))
            .collect();
        let Some(&earliest) = deadlines.first() else {
            // Nothing timed: give external readiness a bounded real chance, then call it.
            if self.restart_ready(20)? {
                return Ok(());
            }
            self.log(self.main_pid, "deadlock", self.threads.len());
            self.forced = Some(Outcome::Deadlock);
            return Ok(());
        };
        let latest = *deadlines.last().expect("non-empty");

        if !self.realtime_applied {
            self.realtime_applied = true;
            match self.decisions.realtime_variant {
                1 => self.clock.realtime_step_ns += REALTIME_STEP_NS,
                2 => self.clock.realtime_step_ns -= REALTIME_STEP_NS,
                _ => {}
            }
        }

        let jump = self
            .decisions
            .jumps
            .get(self.decisions.jumps_used)
            .copied()
            .unwrap_or(Jump {
                kind: 0,
                magnitude: 0,
            });
        if self.decisions.jumps_used < self.decisions.jumps.len() {
            self.decisions.jumps_used += 1;
            if jump.kind != 0 {
                self.decisions.non_natural_jumps += 1;
            }
        }
        let magnitude = MAGNITUDE_TABLE_NS[usize::from(jump.magnitude)];
        let target = match jump.kind {
            1 => latest,
            2 => earliest.saturating_add(magnitude),
            3 => {
                self.clock.realtime_step_ns += magnitude as i64;
                earliest
            }
            _ => earliest,
        };
        self.stats.jumps += 1;
        if jump.kind == 0 {
            self.stats.natural_jumps += 1;
        }
        self.clock.advance_to(target);
        self.log(
            self.main_pid,
            "jump",
            format!("kind={} mag={} -> {}", jump.kind, jump.magnitude, target),
        );
        if let Some(limit) = self.sandbox.virtual_limit
            && self.clock.now() > limit.as_nanos() as u64
        {
            self.forced = Some(Outcome::VirtualLimit);
            return Ok(());
        }

        let due: Vec<pid_t> = self
            .threads
            .iter()
            .filter(|(_, t)| {
                t.wait
                    .as_ref()
                    .and_then(|w| w.deadline)
                    .is_some_and(|d| d <= self.clock.now())
            })
            .map(|(tid, _)| *tid)
            .collect();
        for tid in due {
            self.complete_timeout(tid)?;
        }
        Ok(())
    }
}
