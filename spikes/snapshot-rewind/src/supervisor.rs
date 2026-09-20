//! Parent-side orchestration: run each candidate in a forked runner (or a
//! continuation forked from a matching holder), collect holders the runner
//! creates, record the result into the base crate's search state.

use crate::{
    fds,
    policy::SnapshotPolicy,
    proto::{Channel, Kind, Message, Verdict},
    runner::{RunnerConfig, fork_runner},
    tree::{Holder, HolderSet},
};
use iterator_fuzz::{Case, CaseCoverage, CaseRng, coverage::CoverageCapture};
use std::{
    collections::BTreeMap,
    io,
    time::{Duration, Instant},
};

/// Result of one candidate execution as seen by the supervisor.
#[derive(Debug)]
pub struct Outcome {
    /// `None` when the runner died without reporting (crash, `_exit`, signal).
    pub verdict: Option<Verdict>,
    /// Raw `waitpid` status.
    pub status: i32,
    /// Replayable case for this execution (only when the runner reported).
    pub case: Option<Case>,
    pub coverage: Option<CaseCoverage>,
    /// Holder id and cursor this execution resumed from, if any.
    pub resumed_from: Option<(usize, usize)>,
    /// Supervisor-side wall time for the whole candidate.
    pub wall: Duration,
    /// Runner-side wall time from (re)start to end of body.
    pub body: Duration,
    pub bytes_consumed: usize,
    /// Holders this run created.
    pub holders_created: usize,
    /// Raw coverage feature ids reported by the runner (empty under `NoCoverage`).
    pub features: Vec<u64>,
}

impl Outcome {
    pub fn crashed(&self) -> bool {
        self.verdict.is_none()
    }

    pub fn signal(&self) -> Option<i32> {
        if libc::WIFSIGNALED(self.status) {
            Some(libc::WTERMSIG(self.status))
        } else {
            None
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct SnapshotStats {
    pub candidates: u64,
    pub fresh_runs: u64,
    pub continuations: u64,
    pub holders_created: u64,
    pub holders_evicted: u64,
    pub crashes: u64,
    pub refusals: u64,
    pub refusal_reasons: BTreeMap<String, u64>,
    pub logs: Vec<String>,
    /// Runner-reported wall time skipped by resuming from a holder (sum of chain costs).
    pub skipped_us: u64,
    /// Spawn round trip: `Spawn` sent -> `Spawned` received.
    pub spawn_us: Vec<u64>,
    /// Fork latency reported by runners when creating holders.
    pub holder_fork_us: Vec<u64>,
    pub holder_rss_kb: Vec<u64>,
    /// Supervisor wall time per candidate, split by fresh/continuation.
    pub fresh_wall_us: Vec<u64>,
    pub continuation_wall_us: Vec<u64>,
    pub peak_live_holders: usize,
    pub peak_holder_pss_kb: u64,
}

impl SnapshotStats {
    pub fn summary(&self) -> String {
        format!(
            "candidates={} fresh={} continuations={} holders_created={} evicted={} refusals={} crashes={} skipped={:.1}ms peak_holders={} peak_holder_pss={}MB spawn_rt={} fresh_wall={} cont_wall={}",
            self.candidates,
            self.fresh_runs,
            self.continuations,
            self.holders_created,
            self.holders_evicted,
            self.refusals,
            self.crashes,
            self.skipped_us as f64 / 1e3,
            self.peak_live_holders,
            self.peak_holder_pss_kb / 1024,
            describe_us(&self.spawn_us),
            describe_us(&self.fresh_wall_us),
            describe_us(&self.continuation_wall_us),
        )
    }
}

pub fn describe_us(samples: &[u64]) -> String {
    if samples.is_empty() {
        return "n/a".to_string();
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let pick = |q: f64| sorted[((sorted.len() - 1) as f64 * q).round() as usize];
    format!(
        "n={} p50={:.3}ms p90={:.3}ms max={:.3}ms",
        sorted.len(),
        pick(0.5) as f64 / 1e3,
        pick(0.9) as f64 / 1e3,
        sorted[sorted.len() - 1] as f64 / 1e3
    )
}

pub struct Supervisor {
    policy: SnapshotPolicy,
    holders: HolderSet,
    stats: SnapshotStats,
    mem_total_kb: u64,
    /// Continuations served so far (for the reuse estimate).
    served: u64,
}

impl Supervisor {
    pub fn new(policy: SnapshotPolicy) -> Self {
        unsafe {
            // Holders are grandchildren; when their runner exits they reparent
            // to us so we can reap them.
            libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1);
        }
        let mem_total_kb = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("MemTotal:"))
                    .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
            })
            .unwrap_or(0);
        Self {
            policy,
            holders: HolderSet::default(),
            stats: SnapshotStats::default(),
            mem_total_kb,
            served: 0,
        }
    }

    pub fn policy(&self) -> &SnapshotPolicy {
        &self.policy
    }

    pub fn stats(&self) -> &SnapshotStats {
        &self.stats
    }

    pub fn holders(&self) -> &HolderSet {
        &self.holders
    }

    fn expected_reuse(&self) -> f64 {
        let prior = self.policy.expected_reuse_prior;
        (prior * 2.0 + self.served as f64) / (2.0 + self.stats.holders_created as f64)
    }

    fn free_slots(&self) -> u32 {
        self.policy
            .max_holders
            .saturating_sub(self.holders.len())
            .min(u32::MAX as usize) as u32
    }

    fn runner_config(&self) -> RunnerConfig {
        RunnerConfig {
            policy: self.policy.clone(),
            expected_reuse: self.expected_reuse(),
            free_slots: self.free_slots(),
            close_fds: self.holders.iter().map(|holder| holder.control.raw()).collect(),
        }
    }

    /// Execute one candidate to completion and record it.
    pub fn run_candidate<C: CoverageCapture + 'static>(
        &mut self,
        mut rng: CaseRng<C>,
        body: &mut dyn FnMut(&mut CaseRng<C>) -> Verdict,
    ) -> Outcome {
        let started = Instant::now();
        self.stats.candidates += 1;
        self.sweep_orphans();

        let stream = rng.snapshot_stream();
        let mut resumed_from = None;
        let mut child: Option<(i32, Channel, Option<usize>)> = None;

        if self.policy.enabled {
            if let Some(holder_id) = self
                .holders
                .best_match(&stream.prefix)
                .map(|holder| holder.id)
            {
                match self.spawn_from_holder(holder_id, &stream) {
                    Ok((pid, channel)) => {
                        let (cursor, skipped) = {
                            let holder = self.holders.get(holder_id).expect("holder present");
                            (holder.cursor(), holder.chain_cost_us(&self.holders))
                        };
                        let holder = self.holders.get_mut(holder_id).expect("holder present");
                        holder.uses += 1;
                        holder.last_used = Instant::now();
                        self.stats.skipped_us += skipped;
                        self.stats.continuations += 1;
                        self.served += 1;
                        resumed_from = Some((holder_id, cursor));
                        child = Some((pid, channel, Some(holder_id)));
                    }
                    Err(error) => {
                        self.log(format!("holder {holder_id} unusable ({error}); evicting"));
                        self.evict(holder_id);
                    }
                }
            }
        }

        let (pid, channel, via_holder) = match child {
            Some(child) => child,
            None => {
                let config = self.runner_config();
                let (pid, channel) = fork_runner(&mut rng, body, &config).expect("fork runner");
                self.stats.fresh_runs += 1;
                (pid, channel, None)
            }
        };

        // Event loop until the runner reports or dies.
        let mut finished = None;
        let mut holders_created = 0;
        loop {
            match channel.recv() {
                Ok(Some((message, fd))) => match message {
                    Message::Holder {
                        pid: holder_pid,
                        trace,
                        kind,
                        prefix_cost_us,
                        fork_us,
                        rss_kb,
                    } => {
                        let Some(fd) = fd else {
                            self.log("Holder message without fd".to_string());
                            continue;
                        };
                        holders_created += 1;
                        self.register_holder(
                            holder_pid,
                            trace,
                            kind,
                            Channel::from_owned(fd),
                            prefix_cost_us,
                            fork_us,
                            rss_kb,
                            via_holder,
                        );
                    }
                    Message::Refused { cursor, reason } => {
                        self.stats.refusals += 1;
                        let key = reason
                            .split(':')
                            .next()
                            .unwrap_or("unknown")
                            .trim()
                            .to_string();
                        *self.stats.refusal_reasons.entry(key).or_insert(0) += 1;
                        self.log(format!("snapshot refused at cursor {cursor}: {reason}"));
                    }
                    Message::Finished {
                        verdict,
                        execution,
                        body_us,
                    } => {
                        finished = Some((verdict, execution, body_us));
                    }
                    Message::Log(text) => self.log(text),
                    other => self.log(format!("unexpected runner message {other:?}")),
                },
                Ok(None) => break,
                Err(error) => {
                    self.log(format!("runner channel error: {error}"));
                    break;
                }
            }
        }
        drop(channel);

        let status = match via_holder {
            None => wait_child(pid),
            Some(holder_id) => self.reap_via_holder(holder_id, pid),
        };

        let wall = started.elapsed();
        let outcome = match finished {
            Some((verdict, execution, body_us)) => {
                let case = rng.snapshot_case(&execution);
                let bytes_consumed = execution.bytes_consumed();
                let features = execution
                    .feedback()
                    .map(|feedback| feedback.features().iter().map(|id| id.raw()).collect())
                    .unwrap_or_default();
                let coverage = rng.snapshot_record(*execution).ok();
                Outcome {
                    verdict: Some(verdict),
                    status,
                    case: Some(case),
                    coverage,
                    resumed_from,
                    wall,
                    body: Duration::from_micros(body_us),
                    bytes_consumed,
                    holders_created,
                    features,
                }
            }
            None => {
                self.stats.crashes += 1;
                rng.snapshot_abandon();
                Outcome {
                    verdict: None,
                    status,
                    case: None,
                    coverage: None,
                    resumed_from,
                    wall,
                    body: Duration::ZERO,
                    bytes_consumed: 0,
                    holders_created,
                    features: Vec::new(),
                }
            }
        };
        let wall_us = wall.as_micros() as u64;
        if resumed_from.is_some() {
            self.stats.continuation_wall_us.push(wall_us);
        } else {
            self.stats.fresh_wall_us.push(wall_us);
        }
        self.enforce_budget();
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    fn register_holder(
        &mut self,
        pid: i32,
        trace: Vec<u8>,
        kind: Kind,
        control: Channel,
        prefix_cost_us: u64,
        fork_us: u64,
        rss_kb: u64,
        parent: Option<usize>,
    ) {
        if self.holders.has_exact(&trace) {
            // Duplicate position (e.g. two runs sharing a prefix both crossed the cliff).
            let _ = control.send(&Message::Exit, None);
            let _ = wait_pidfd_exit(pid, 1000);
            reap_if_child(pid);
            return;
        }
        let id = self.holders.allocate_id();
        let now = Instant::now();
        self.stats.holders_created += 1;
        self.stats.holder_fork_us.push(fork_us);
        self.stats.holder_rss_kb.push(rss_kb);
        self.holders.insert(Holder {
            id,
            pid,
            trace,
            kind,
            control,
            created: now,
            last_used: now,
            uses: 0,
            prefix_cost_us,
            fork_us,
            rss_kb,
            parent,
        });
        self.stats.peak_live_holders = self.stats.peak_live_holders.max(self.holders.len());
    }

    fn spawn_from_holder(
        &mut self,
        holder_id: usize,
        stream: &iterator_fuzz::snapshot_hooks::StreamSpec,
    ) -> io::Result<(i32, Channel)> {
        let expected_reuse = self.expected_reuse() as f32;
        let free_slots = self.free_slots();
        let holder = self
            .holders
            .get(holder_id)
            .ok_or_else(|| io::Error::other("holder vanished"))?;
        let (parent_end, child_end) = Channel::pair()?;
        let sent_at = Instant::now();
        holder.control.send(
            &Message::Spawn {
                stream: stream.clone(),
                expected_reuse,
                free_slots,
            },
            Some(child_end.raw()),
        )?;
        drop(child_end);
        match holder.control.recv()? {
            Some((Message::Spawned { pid }, _)) => {
                self.stats
                    .spawn_us
                    .push(sent_at.elapsed().as_micros() as u64);
                Ok((pid, parent_end))
            }
            Some((Message::Log(text), _)) => Err(io::Error::other(text)),
            Some((other, _)) => Err(io::Error::other(format!("unexpected {other:?}"))),
            None => Err(io::Error::other("holder closed its control channel")),
        }
    }

    fn reap_via_holder(&mut self, holder_id: usize, pid: i32) -> i32 {
        let Some(holder) = self.holders.get(holder_id) else {
            return -1;
        };
        if holder.control.send(&Message::Reap { pid }, None).is_err() {
            return -1;
        }
        match holder.control.recv() {
            Ok(Some((Message::Reaped { status, .. }, _))) => status,
            _ => -1,
        }
    }

    fn evict(&mut self, id: usize) {
        if let Some(holder) = self.holders.remove(id) {
            let _ = holder.control.send(&Message::Exit, None);
            drop(holder.control);
            let _ = wait_pidfd_exit(holder.pid, 2000);
            reap_if_child(holder.pid);
            self.stats.holders_evicted += 1;
        }
    }

    fn enforce_budget(&mut self) {
        while self.holders.len() > self.policy.max_holders {
            match self.holders.eviction_candidate(None) {
                Some(id) => self.evict(id),
                None => break,
            }
        }
        if self.mem_total_kb > 0 {
            let floor = (self.mem_total_kb as f64 * self.policy.mem_available_floor) as u64;
            while !self.holders.is_empty() && fds::mem_available_kb() < floor {
                match self.holders.eviction_candidate(None) {
                    Some(id) => {
                        self.log(format!(
                            "MemAvailable below floor ({floor} kB); evicting holder {id}"
                        ));
                        self.evict(id);
                    }
                    None => break,
                }
            }
        }
    }

    /// Sample PSS of every live holder (slow: reads smaps_rollup); for reports.
    pub fn sample_holder_pss(&mut self) -> u64 {
        let total: u64 = self
            .holders
            .iter()
            .filter_map(|holder| fds::pss_kb(holder.pid))
            .sum();
        self.stats.peak_holder_pss_kb = self.stats.peak_holder_pss_kb.max(total);
        total
    }

    fn sweep_orphans(&mut self) {
        loop {
            let mut status = 0;
            let rc = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if rc <= 0 {
                break;
            }
        }
    }

    fn log(&mut self, text: String) {
        if self.stats.logs.len() < 256 {
            self.stats.logs.push(text);
        }
    }

    /// Tear down every holder.
    pub fn shutdown(&mut self) {
        let holders = self.holders.drain();
        for holder in &holders {
            let _ = holder.control.send(&Message::Exit, None);
        }
        for holder in holders {
            drop(holder.control);
            let _ = wait_pidfd_exit(holder.pid, 2000);
            reap_if_child(holder.pid);
        }
        self.sweep_orphans();
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn wait_child(pid: i32) -> i32 {
    let mut status = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return status;
        }
        if rc < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return -1;
    }
}

fn reap_if_child(pid: i32) {
    let mut status = 0;
    unsafe {
        libc::waitpid(pid, &mut status, libc::WNOHANG);
    }
}

/// Wait for `pid` to exit using a pidfd (works for non-children too).
fn wait_pidfd_exit(pid: i32, timeout_ms: i32) -> bool {
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if pidfd < 0 {
        return false;
    }
    let mut pfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    unsafe {
        libc::close(pidfd);
    }
    rc > 0
}
