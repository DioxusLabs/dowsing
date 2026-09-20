//! Supervisor side: spawns targets, runs one case per request, and plugs into dowsing as a
//! `CoverageCapture`.
//!
//! [`ChildCoverage`] is a cheap handle over a pool of targets. `curious().with_coverage(...)`
//! hands out `CaseRng`s exactly as for an in-process backend; the harness passes each RNG to
//! [`ChildCoverage::run`], which mirrors its byte budget into the child, absorbs the child's
//! trace back into the same `CaseRng`, and stashes the decoded coverage for `finish_capture`.

use crate::{
    CTL_FD, MODE_ENV, MODE_EXEC, MODE_FORK, REQUEST_EXIT, SHM_FD, STATUS_FD,
    shm::{
        CASE_FLAG_CMP_FEEDBACK, Capacities, HELLO_INSTRUMENTED, Header, MAGIC, OVERFLOW_INPUT,
        Region, STATE_CRASHED, STATE_DONE, STATE_STARTED, VERDICT_FAILED, VERDICT_OK,
        VERDICT_PANICKED,
    },
};
use iterator_fuzz::{
    Case, CaseCoverage, CaseRng,
    coverage::{
        CoverageCapture, CoverageId, CoverageSet, ExecutionFeedback, ParallelCoverageCapture,
    },
    raw::{RawCase, RawSequence, RawSpan, decode_sancov_counters},
};
use std::{
    cell::RefCell,
    ffi::OsString,
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::process::CommandExt,
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// How each case gets its own process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// One long-lived target per pool slot; each case is a `fork()` of it.
    Fork,
    /// Spawn the target binary afresh for every case (baseline).
    Exec,
}

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub mode: Mode,
    /// Initial byte budget mirrored into the child; doubled on exhaustion up to `max_budget`.
    pub budget: usize,
    pub max_budget: usize,
    pub timeout: Duration,
    pub cmp_feedback: bool,
    /// Send the target's stderr to `/dev/null`.
    pub quiet: bool,
    pub caps: Capacities,
}

impl BridgeConfig {
    pub fn new(program: impl Into<PathBuf>, mode: Mode) -> Self {
        let caps = Capacities::default();
        Self {
            program: program.into(),
            args: Vec::new(),
            mode,
            budget: 4096,
            max_budget: caps.input,
            timeout: Duration::from_secs(2),
            cmp_feedback: true,
            quiet: false,
            caps,
        }
    }

    pub fn forkserver(program: impl Into<PathBuf>) -> Self {
        Self::new(program, Mode::Fork)
    }

    pub fn exec_per_case(program: impl Into<PathBuf>) -> Self {
        Self::new(program, Mode::Exec)
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_cmp_feedback(mut self, enabled: bool) -> Self {
        self.cmp_feedback = enabled;
        self
    }

    pub fn with_budget(mut self, budget: usize) -> Self {
        self.budget = budget.min(self.caps.input);
        self
    }

    pub fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }
}

/// How the process that ran the case terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Exited(i32),
    Signaled(i32),
    TimedOut,
}

impl Exit {
    fn from_wait_status(status: i32) -> Self {
        if libc::WIFEXITED(status) {
            Self::Exited(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            Self::Signaled(libc::WTERMSIG(status))
        } else {
            Self::Exited(-1)
        }
    }
}

/// Wall-clock breakdown of one `run`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timings {
    /// Filling the byte budget from the supervisor's `CaseRng`.
    pub fill: Duration,
    /// Spawning (exec mode) or the request round trip (fork mode), until the pid is known.
    pub launch: Duration,
    /// From pid known until the case process exited.
    pub execute: Duration,
    /// Decoding spans/features from shared memory and absorbing them into the `CaseRng`.
    pub decode: Duration,
    /// Number of budget retries after exhaustion.
    pub retries: u32,
}

impl Timings {
    pub fn total(&self) -> Duration {
        self.fill + self.launch + self.execute + self.decode
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Passed,
    Failed,
    Panicked,
    Crashed(i32),
    TimedOut,
    /// The case child exited mid-case without exporting a verdict (`std::process::exit`).
    Exited(i32),
    /// Protocol failure: the target never started the case or produced garbage.
    Broken(String),
}

impl Status {
    pub fn is_failure(&self) -> bool {
        !matches!(self, Self::Passed | Self::Exited(_) | Self::Broken(_))
    }
}

/// One executed case. Drop (or call [`Outcome::coverage`]) to feed its coverage back into the
/// search; call [`Outcome::discard`] to exclude it, exactly as with a plain `CaseRng`.
pub struct Outcome {
    pub status: Status,
    pub exit: Exit,
    pub cost: u64,
    pub consumed: usize,
    pub feature_count: usize,
    pub timings: Timings,
    /// Replayable case (the child's consumed prefix plus its spans).
    pub case: Case,
    feedback: Option<ExecutionFeedback>,
    rng: Option<CaseRng<ChildCoverage>>,
}

impl Outcome {
    pub fn coverage(mut self) -> Result<CaseCoverage, String> {
        let rng = self.rng.take().expect("outcome rng");
        PENDING.with(|pending| *pending.borrow_mut() = self.feedback.take());
        rng.coverage_with_cost(self.cost as usize)
    }

    pub fn discard(mut self) {
        self.feedback = None;
        if let Some(rng) = self.rng.take() {
            rng.discard();
        }
    }
}

impl Drop for Outcome {
    fn drop(&mut self) {
        if let Some(rng) = self.rng.take() {
            PENDING.with(|pending| *pending.borrow_mut() = self.feedback.take());
            drop(rng);
        }
    }
}

/// Aggregate statistics across all `run` calls of a pool.
#[derive(Debug, Clone, Copy, Default)]
pub struct BridgeStats {
    pub runs: u64,
    pub failures: u64,
    pub crashes: u64,
    pub timeouts: u64,
    pub retries: u64,
    pub respawns: u64,
    pub fill: Duration,
    pub launch: Duration,
    pub execute: Duration,
    pub decode: Duration,
}

// ---- process management ---------------------------------------------------------------

struct Forkserver {
    child: Child,
    ctl: File,
    status: File,
}

struct Target {
    config: BridgeConfig,
    region: Region,
    forkserver: Option<Forkserver>,
    instrumented: bool,
    counters: usize,
}

struct RawRun {
    exit: Exit,
    header: Header,
    launch: Duration,
    execute: Duration,
}

fn pipe() -> io::Result<(File, File)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}

fn command(
    config: &BridgeConfig,
    mode: &str,
    shm_fd: RawFd,
    ctl: Option<RawFd>,
    status: Option<RawFd>,
) -> Command {
    let mut command = Command::new(&config.program);
    command.args(&config.args);
    command.env(MODE_ENV, mode);
    command.stdin(Stdio::null());
    if config.quiet {
        command.stderr(Stdio::null());
    }
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(shm_fd, SHM_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some(ctl) = ctl
                && libc::dup2(ctl, CTL_FD) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if let Some(status) = status
                && libc::dup2(status, STATUS_FD) < 0
            {
                return Err(io::Error::last_os_error());
            }
            // Die with the supervisor thread that spawned us.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        });
    }
    command
}

fn poll_readable(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
    loop {
        let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        return Ok(ready > 0);
    }
}

fn read_u32(file: &mut File) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

impl Target {
    fn new(config: BridgeConfig) -> Result<Self, String> {
        let region = Region::create(config.caps).map_err(|e| format!("create shm: {e}"))?;
        let mut target = Self {
            config,
            region,
            forkserver: None,
            instrumented: false,
            counters: 0,
        };
        if target.config.mode == Mode::Fork {
            target.spawn_forkserver()?;
        }
        Ok(target)
    }

    fn spawn_forkserver(&mut self) -> Result<(), String> {
        let (ctl_read, ctl_write) = pipe().map_err(|e| format!("pipe: {e}"))?;
        let (status_read, status_write) = pipe().map_err(|e| format!("pipe: {e}"))?;
        let child = command(
            &self.config,
            MODE_FORK,
            self.region.fd(),
            Some(ctl_read.as_raw_fd()),
            Some(status_write.as_raw_fd()),
        )
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", self.config.program.display()))?;
        drop(ctl_read);
        drop(status_write);
        let mut forkserver = Forkserver {
            child,
            ctl: ctl_write,
            status: status_read,
        };
        if !poll_readable(
            forkserver.status.as_raw_fd(),
            self.config.timeout.max(Duration::from_secs(5)),
        )
        .map_err(|e| e.to_string())?
        {
            let _ = forkserver.child.kill();
            return Err("forkserver did not say hello".into());
        }
        let magic = read_u32(&mut forkserver.status).map_err(|e| format!("hello: {e}"))?;
        if magic != MAGIC {
            let _ = forkserver.child.kill();
            return Err(format!("forkserver hello magic {magic:#x}"));
        }
        let flags = read_u32(&mut forkserver.status).map_err(|e| format!("hello: {e}"))?;
        self.instrumented = flags & HELLO_INSTRUMENTED != 0;
        self.forkserver = Some(forkserver);
        Ok(())
    }

    fn stop_forkserver(&mut self) {
        if let Some(mut forkserver) = self.forkserver.take() {
            let _ = forkserver.ctl.write_all(&REQUEST_EXIT.to_le_bytes());
            drop(forkserver.ctl);
            if !poll_readable(forkserver.status.as_raw_fd(), Duration::from_millis(200))
                .unwrap_or(false)
            {
                let _ = forkserver.child.kill();
            }
            let _ = forkserver.child.wait();
        }
    }

    fn prepare(&mut self, budget: &[u8], seed: u64) {
        self.region.reset_response();
        self.region.input_mut()[..budget.len()].copy_from_slice(budget);
        let mut header = self.region.header();
        header.seed = seed;
        header.input_len = budget.len() as u32;
        header.case_flags = if self.config.cmp_feedback {
            CASE_FLAG_CMP_FEEDBACK
        } else {
            0
        };
        self.region.write_header(&header);
    }

    fn execute(
        &mut self,
        budget: &[u8],
        seed: u64,
        stats: &mut BridgeStats,
    ) -> Result<RawRun, String> {
        self.prepare(budget, seed);
        match self.config.mode {
            Mode::Fork => self.execute_fork(stats),
            Mode::Exec => self.execute_exec(),
        }
    }

    fn execute_fork(&mut self, stats: &mut BridgeStats) -> Result<RawRun, String> {
        if self.forkserver.is_none() {
            stats.respawns += 1;
            self.spawn_forkserver()?;
        }
        let timeout = self.config.timeout;
        let result = (|| {
            let forkserver = self.forkserver.as_mut().expect("forkserver present");
            let start = Instant::now();
            forkserver
                .ctl
                .write_all(&1u32.to_le_bytes())
                .map_err(|e| format!("forkserver request: {e}"))?;
            let pid = read_u32(&mut forkserver.status)
                .map_err(|e| format!("forkserver pid: {e}"))? as i32;
            let launched = Instant::now();
            let mut exit = None;
            if !poll_readable(forkserver.status.as_raw_fd(), timeout).map_err(|e| e.to_string())? {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                exit = Some(Exit::TimedOut);
            }
            let wait_status = read_u32(&mut forkserver.status)
                .map_err(|e| format!("forkserver status: {e}"))?
                as i32;
            let finished = Instant::now();
            Ok(RawRun {
                exit: exit.unwrap_or_else(|| Exit::from_wait_status(wait_status)),
                header: self.region.header(),
                launch: launched - start,
                execute: finished - launched,
            })
        })();
        if result.is_err() {
            // The forkserver itself died; drop it so the next case respawns.
            if let Some(mut forkserver) = self.forkserver.take() {
                let _ = forkserver.child.kill();
                let _ = forkserver.child.wait();
            }
        }
        result
    }

    fn execute_exec(&mut self) -> Result<RawRun, String> {
        let start = Instant::now();
        let mut child = command(&self.config, MODE_EXEC, self.region.fd(), None, None)
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", self.config.program.display()))?;
        let launched = Instant::now();
        let pidfd =
            unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) } as RawFd;
        if pidfd < 0 {
            return Err(format!("pidfd_open: {}", io::Error::last_os_error()));
        }
        let pidfd = unsafe { File::from_raw_fd(pidfd) };
        let mut exit = None;
        if !poll_readable(pidfd.as_raw_fd(), self.config.timeout).map_err(|e| e.to_string())? {
            let _ = child.kill();
            exit = Some(Exit::TimedOut);
        }
        let status = child.wait().map_err(|e| format!("wait: {e}"))?;
        let finished = Instant::now();
        let exit = exit.unwrap_or_else(|| {
            use std::os::unix::process::ExitStatusExt;
            match (status.code(), status.signal()) {
                (Some(code), _) => Exit::Exited(code),
                (None, Some(signal)) => Exit::Signaled(signal),
                _ => Exit::Exited(-1),
            }
        });
        // Exec mode learns instrumentation from the first result rather than a hello.
        let header = self.region.header();
        self.instrumented |= header.counters_len > 0 || header.n_features > 0;
        self.counters = self.counters.max(header.counters_len as usize);
        Ok(RawRun {
            exit,
            header,
            launch: launched - start,
            execute: finished - launched,
        })
    }

    fn decode_trace(&self, header: &Header, input_len: usize) -> RawCase {
        let consumed = (header.consumed as usize).min(input_len);
        let spans = |records: &[crate::shm::SpanRec], n: u32| {
            records[..n as usize]
                .iter()
                .map(|rec| RawSpan {
                    start: rec.start as usize,
                    len: rec.len as usize,
                    kind: rec.kind as u8,
                })
                .collect::<Vec<_>>()
        };
        let items = self.region.items();
        let sequences = self.region.sequences()[..header.n_sequences as usize]
            .iter()
            .map(|rec| RawSequence {
                length_start: rec.length_start as usize,
                length_len: rec.length_len as usize,
                items: items[rec.items_start as usize..(rec.items_start + rec.items_len) as usize]
                    .iter()
                    .map(|item| (item.start as usize, item.len as usize))
                    .collect(),
            })
            .collect();
        RawCase {
            seed: header.seed,
            prefix: self.region.input()[..consumed].to_vec(),
            zero_tail: false,
            draws: spans(self.region.draws(), header.n_draws),
            semantics: spans(self.region.semantics(), header.n_semantics),
            sequences,
        }
    }

    fn decode_feedback(&self, header: &Header) -> ExecutionFeedback {
        let ids = self.region.features()[..header.n_features as usize]
            .iter()
            .map(|raw| CoverageId::new(*raw))
            .collect::<CoverageSet>();
        let mut dictionary = Vec::with_capacity(header.n_dict as usize);
        let mut offset = 0;
        let bytes = self.region.dict_bytes();
        for len in &self.region.dict_lens()[..header.n_dict as usize] {
            let len = *len as usize;
            dictionary.push(bytes[offset..offset + len].to_vec());
            offset += len;
        }
        ExecutionFeedback::new(ids, header.hit_count_weight, dictionary)
    }

    fn decode_crash_feedback(&self, header: &Header) -> ExecutionFeedback {
        decode_sancov_counters(&self.region.counters()[..header.counters_len as usize])
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        self.stop_forkserver();
    }
}

// ---- dowsing integration ---------------------------------------------------------------

struct Pool {
    config: BridgeConfig,
    idle: Mutex<Vec<Target>>,
    stats: Mutex<BridgeStats>,
    next_token: AtomicU64,
}

thread_local! {
    static PENDING: RefCell<Option<ExecutionFeedback>> = const { RefCell::new(None) };
}

/// Coverage backend whose cases execute in supervised child processes.
///
/// Clones share one pool of targets; each concurrently running case leases its own target, so
/// parallel use gets one forkserver per worker thread.
#[derive(Clone)]
pub struct ChildCoverage {
    pool: Arc<Pool>,
}

impl ChildCoverage {
    /// Create the pool and, in fork mode, start the first forkserver eagerly so configuration
    /// errors surface here.
    pub fn spawn(config: BridgeConfig) -> Result<Self, String> {
        let first = Target::new(config.clone())?;
        Ok(Self {
            pool: Arc::new(Pool {
                config,
                idle: Mutex::new(vec![first]),
                stats: Mutex::new(BridgeStats::default()),
                next_token: AtomicU64::new(1),
            }),
        })
    }

    pub fn config(&self) -> &BridgeConfig {
        &self.pool.config
    }

    pub fn stats(&self) -> BridgeStats {
        *self.pool.stats.lock().expect("stats poisoned")
    }

    /// Whether the target reported SanitizerCoverage counters (known after the hello in fork
    /// mode, after the first case in exec mode).
    pub fn instrumented(&self) -> bool {
        self.pool
            .idle
            .lock()
            .expect("pool poisoned")
            .iter()
            .any(|target| target.instrumented)
    }

    /// Number of SanitizerCoverage 8-bit counters the target exports per case (0 until known).
    pub fn counters(&self) -> usize {
        self.pool
            .idle
            .lock()
            .expect("pool poisoned")
            .iter()
            .map(|target| target.counters)
            .max()
            .unwrap_or(0)
    }

    fn lease(&self) -> Result<Target, String> {
        let idle = self.pool.idle.lock().expect("pool poisoned").pop();
        match idle {
            Some(target) => Ok(target),
            None => Target::new(self.pool.config.clone()),
        }
    }

    fn release(&self, target: Target) {
        self.pool.idle.lock().expect("pool poisoned").push(target);
    }

    /// Execute one dowsing case in a child process.
    ///
    /// The RNG must not have been drawn from yet: its whole remaining budget is mirrored into the
    /// child and whatever the child consumed is absorbed back, so afterwards `fork_case()` and
    /// the corpus see exactly what an in-process run would have recorded.
    pub fn run(&self, mut rng: CaseRng<ChildCoverage>) -> Result<Outcome, String> {
        let mut target = self.lease()?;
        let result = self.run_on(&mut target, &mut rng);
        self.release(target);
        match result {
            Ok((status, exit, cost, consumed, feature_count, timings, feedback)) => {
                let case = rng.fork_case();
                {
                    let mut stats = self.pool.stats.lock().expect("stats poisoned");
                    stats.runs += 1;
                    stats.retries += u64::from(timings.retries);
                    stats.fill += timings.fill;
                    stats.launch += timings.launch;
                    stats.execute += timings.execute;
                    stats.decode += timings.decode;
                    match status {
                        Status::Failed | Status::Panicked => stats.failures += 1,
                        Status::Crashed(_) => stats.crashes += 1,
                        Status::TimedOut => stats.timeouts += 1,
                        _ => {}
                    }
                }
                Ok(Outcome {
                    status,
                    exit,
                    cost,
                    consumed,
                    feature_count,
                    timings,
                    case,
                    feedback: Some(feedback),
                    rng: Some(rng),
                })
            }
            Err(err) => {
                rng.discard();
                Err(err)
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn run_on(
        &self,
        target: &mut Target,
        rng: &mut CaseRng<ChildCoverage>,
    ) -> Result<(Status, Exit, u64, usize, usize, Timings, ExecutionFeedback), String> {
        let config = &self.pool.config;
        let mut budget_len = config.budget.min(config.caps.input).max(1);
        let mut budget = vec![0u8; budget_len];
        let mut timings = Timings::default();
        let mut stats = BridgeStats::default();
        let run = loop {
            let t0 = Instant::now();
            rng.fill_budget(&mut budget[..budget_len]);
            timings.fill += t0.elapsed();
            let run = target.execute(&budget[..budget_len], rng.seed(), &mut stats)?;
            timings.launch += run.launch;
            timings.execute += run.execute;
            let exhausted =
                run.header.state == STATE_DONE && run.header.overflow & OVERFLOW_INPUT != 0;
            if exhausted && budget_len < config.max_budget.min(config.caps.input) {
                budget_len = (budget_len * 2)
                    .min(config.max_budget)
                    .min(config.caps.input);
                budget.resize(budget_len, 0);
                timings.retries += 1;
                continue;
            }
            break run;
        };
        self.pool.stats.lock().expect("stats poisoned").respawns += stats.respawns;

        let t0 = Instant::now();
        let header = run.header;
        let (status, raw, feedback, cost) = match (header.state, run.exit) {
            (STATE_DONE, _) => {
                let status = match header.verdict {
                    VERDICT_OK => Status::Passed,
                    VERDICT_FAILED => Status::Failed,
                    VERDICT_PANICKED => Status::Panicked,
                    other => Status::Broken(format!("unknown verdict {other}")),
                };
                let status = if header.overflow & OVERFLOW_INPUT != 0 {
                    Status::Broken(format!("child exhausted the {budget_len}-byte budget"))
                } else {
                    status
                };
                (
                    status,
                    target.decode_trace(&header, budget_len),
                    target.decode_feedback(&header),
                    header.cost,
                )
            }
            (STATE_CRASHED, exit) => {
                let signal = match exit {
                    Exit::Signaled(signal) => signal,
                    _ => header.crash_signal as i32,
                };
                (
                    Status::Crashed(signal),
                    whole_budget(&header, &budget[..budget_len]),
                    target.decode_crash_feedback(&header),
                    0,
                )
            }
            (_, Exit::TimedOut) => (
                Status::TimedOut,
                whole_budget(&header, &budget[..budget_len]),
                ExecutionFeedback::default(),
                0,
            ),
            (STATE_STARTED, Exit::Exited(code)) => (
                Status::Exited(code),
                whole_budget(&header, &budget[..budget_len]),
                ExecutionFeedback::default(),
                0,
            ),
            (STATE_STARTED, Exit::Signaled(signal)) => (
                Status::Crashed(signal),
                whole_budget(&header, &budget[..budget_len]),
                ExecutionFeedback::default(),
                0,
            ),
            (state, exit) => (
                Status::Broken(format!(
                    "child never started the case (state {state}, {exit:?})"
                )),
                whole_budget(&header, &budget[..budget_len]),
                ExecutionFeedback::default(),
                0,
            ),
        };
        let consumed = raw.prefix.len();
        rng.absorb_trace(raw);
        let feature_count = feedback.features().len();
        timings.decode += t0.elapsed();
        Ok((
            status,
            run.exit,
            cost,
            consumed,
            feature_count,
            timings,
            feedback,
        ))
    }
}

fn whole_budget(header: &Header, budget: &[u8]) -> RawCase {
    RawCase {
        seed: header.seed,
        prefix: budget.to_vec(),
        zero_tail: false,
        draws: Vec::new(),
        semantics: Vec::new(),
        sequences: Vec::new(),
    }
}

impl CoverageCapture for ChildCoverage {
    type Token = u64;

    fn start_capture(&mut self) -> Result<Self::Token, String> {
        Ok(self.pool.next_token.fetch_add(1, Ordering::Relaxed))
    }

    fn finish_capture(&mut self, _token: Self::Token) -> Result<ExecutionFeedback, String> {
        PENDING
            .with(|pending| pending.borrow_mut().take())
            .ok_or_else(|| "case was not executed through ChildCoverage::run".to_string())
    }

    fn discard_capture(&mut self, _token: Self::Token) -> Result<(), String> {
        PENDING.with(|pending| pending.borrow_mut().take());
        Ok(())
    }
}

impl ParallelCoverageCapture for ChildCoverage {}
