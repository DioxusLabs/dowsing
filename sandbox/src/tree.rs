//! The decision tree and the search over it.
//!
//! Every decision point the session reports becomes a [`Node`]; edges are choices. Expanding a
//! node means restoring the nearest snapshotted ancestor, replaying the decisions down to the
//! node, taking an untried choice and rolling out with the default policy until the run ends.
//!
//! The rollout policy is PCT (probabilistic concurrency testing): every thread gets a random
//! priority, the highest-priority runnable candidate runs, and at `d` random change points
//! (edge counts) the running thread drops to the lowest priority. A `Budget` choice is the
//! exact edge distance to the next change point, so a preemption lands on any instruction
//! boundary the instrumentation can see, not on a coarse table entry.
//!
//! Energy is coverage novelty, of two kinds: new edges, and new *interleaving features* (a
//! thread stopping at a point right after edge `g` and a different thread running next). Edge
//! coverage saturates after a few runs on schedule bugs; interleaving features are what keep
//! the frontier pointed at unexplored preemption points.

use crate::{
    session::{Event, Session},
    shm::Bitmap,
    snapshot::SnapshotId,
    world::{BUDGET_MAX, Candidate, Decision, Kind, Outcome, Pending, Point, TraceEvent},
};
use rand::{Rng, SeedableRng, rngs::SmallRng, seq::SliceRandom};
use std::{
    collections::HashSet,
    fmt,
    hash::{Hash, Hasher},
    io,
    time::{Duration, Instant},
};

/// Search knobs; the defaults are the ones that won `sandbox/sweep.sh`.
#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    /// Distinct budgets tried per `Budget` node before it leaves the frontier.
    pub budget_fanout: usize,
    /// Maximum PCT change points per rollout (`d` is drawn from `1..=pct_depth`).
    pub pct_depth: usize,
    /// UCB exploration constant for frontier selection.
    pub ucb_c: f64,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            budget_fanout: 8,
            pct_depth: 3,
            ucb_c: 2.0,
        }
    }
}

pub type NodeId = usize;

#[derive(Debug, Clone)]
pub struct Node {
    pub parent: Option<NodeId>,
    pub choice_from_parent: u32,
    pub depth: usize,
    /// The decision pending at this node; `None` for terminal nodes.
    pub kind: Option<Kind>,
    pub n: u32,
    /// Total instrumented edges executed when this node was reached.
    pub edges: u64,
    pub children: Vec<(u32, NodeId)>,
    /// `Budget` nodes, once the thread has been run to its natural stop from here: the guard
    /// ids of the edges it executed. Budgets past the segment are the same run as 0, and
    /// preempting at a second execution of the same edge is not a new program point, so the
    /// budgets worth trying are one per distinct guard (see [`Node::budgets`]).
    pub segment: Option<Vec<u32>>,
    /// A `Budget` node with no known segment whose sampled offsets were all already tried.
    pub exhausted: bool,
    /// No untried choice remains anywhere in this subtree.
    pub closed: bool,
    pub snapshot: Option<SnapshotId>,
    pub visits: u32,
    /// New features first found on runs through this node (the first run's baseline excluded).
    pub novelty: u32,
    pub outcome: Option<Outcome>,
}

impl Node {
    fn child(&self, choice: u32) -> Option<NodeId> {
        self.children
            .iter()
            .find(|(c, _)| *c == choice)
            .map(|(_, id)| *id)
    }

    fn tried(&self, choice: u32) -> bool {
        self.child(choice).is_some()
    }

    /// Candidate budgets besides 0: the first occurrence of each distinct guard in the segment.
    fn budgets(&self) -> Option<Vec<u32>> {
        let seg = self.segment.as_ref()?;
        let mut seen = HashSet::new();
        Some(
            seg.iter()
                .enumerate()
                .filter(|(_, g)| seen.insert(**g))
                .map(|(i, _)| i as u32 + 1)
                .collect(),
        )
    }

    /// Candidate budgets not yet tried (`None` while the segment is unknown).
    fn untried_budgets(&self) -> Option<Vec<u32>> {
        self.budgets()
            .map(|b| b.into_iter().filter(|c| !self.tried(*c)).collect())
    }

    /// Whether the node has an untried choice the search may take now. `Budget` nodes widen
    /// progressively: `fanout` children up front, then one more per `visits²` growth, so a
    /// long segment does not get enumerated before anything below it is explored.
    fn expandable(&self, fanout: usize) -> bool {
        match self.kind {
            None => false,
            Some(Kind::Budget) => {
                if self.exhausted {
                    return false;
                }
                if !self.tried(0) {
                    return true;
                }
                let allowed = fanout + (self.visits as f64).sqrt() as usize;
                match self.untried_budgets() {
                    Some(u) => !u.is_empty() && self.children.len() < allowed,
                    None => self.children.len() < fanout,
                }
            }
            Some(_) => (self.children.len() as u32) < self.n,
        }
    }
}

/// PCT state for one rollout.
struct Policy {
    /// Per thread; unknown (not yet created) threads get one on first sight.
    prio: Vec<u32>,
    /// Priority of a thread's pending timeout when it is offered as a `Fire` candidate.
    timer_prio: Vec<u32>,
    /// Global edge counts at which the running thread is demoted, ascending.
    change_points: Vec<u64>,
    lowest: u32,
}

impl Policy {
    /// `spent` preemptions already lie on the prefix this rollout continues (the frontier
    /// node's own forced preemption included); they count towards the run's `d`, so the
    /// rollout adds only the remainder. With `d` = 1 a preemption forced by the search is
    /// followed by a preemption-free rollout, which is the schedule a depth-1 bug needs.
    fn new(rng: &mut SmallRng, threads: usize, k_est: u64, depth: usize, spent: usize) -> Self {
        let mut prio: Vec<u32> = (0..threads as u32).map(|i| 1000 + i).collect();
        prio.shuffle(rng);
        let mut timer_prio: Vec<u32> = (0..threads as u32).map(|i| 1000 + i).collect();
        timer_prio.shuffle(rng);
        let d = rng.random_range(1..=depth).saturating_sub(spent);
        let mut change_points: Vec<u64> =
            (0..d).map(|_| rng.random_range(0..k_est.max(1))).collect();
        change_points.sort_unstable();
        Self {
            prio,
            timer_prio,
            change_points,
            lowest: 1000,
        }
    }

    fn ensure(&mut self, rng: &mut SmallRng, thread: usize) {
        while self.prio.len() <= thread {
            self.prio.push(rng.random_range(1000..2000));
            self.timer_prio.push(rng.random_range(1000..2000));
        }
    }

    fn schedule(&mut self, rng: &mut SmallRng, candidates: &[Candidate]) -> u32 {
        let mut best = 0;
        let mut best_p = 0;
        for (i, c) in candidates.iter().enumerate() {
            let p = match *c {
                Candidate::Run(t) => {
                    self.ensure(rng, t);
                    self.prio[t]
                }
                Candidate::Fire(t) => {
                    self.ensure(rng, t);
                    self.timer_prio[t]
                }
            };
            if i == 0 || p > best_p {
                best = i;
                best_p = p;
            }
        }
        best as u32
    }

    /// Edges until the next change point after `edges`, or 0 to run to the natural stop.
    fn budget(&mut self, edges: u64) -> u32 {
        while let Some(cp) = self.change_points.first() {
            if *cp > edges {
                return (*cp - edges).min(BUDGET_MAX as u64 - 1) as u32;
            }
            self.change_points.remove(0);
        }
        0
    }

    fn demote(&mut self, rng: &mut SmallRng, thread: usize) {
        self.ensure(rng, thread);
        self.lowest -= 1;
        self.prio[thread] = self.lowest;
    }
}

#[derive(Debug, Clone)]
pub struct Budget {
    pub runs: usize,
    pub wall: Duration,
    pub stop_on_failure: bool,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            runs: 1000,
            wall: Duration::from_secs(60),
            stop_on_failure: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Failure {
    pub outcome: Outcome,
    pub decisions: Vec<Decision>,
    pub stderr: String,
    pub run: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub runs: usize,
    pub restores: usize,
    pub restore_pages: usize,
    pub restore_wall: Duration,
    pub snapshots: usize,
    pub snapshot_pages: usize,
    pub snapshot_wall: Duration,
    pub replayed_decisions: usize,
    pub executed_decisions: usize,
    /// Distinct coverage edges seen.
    pub features: usize,
    /// Distinct interleaving features seen (see module docs).
    pub sched_features: usize,
    pub divergences: usize,
    pub failures: Vec<Failure>,
    pub wall: Duration,
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "runs {} in {:.2?} ({:.0}/s), features {} edges + {} interleavings, failures {}, divergences {}",
            self.runs,
            self.wall,
            self.runs as f64 / self.wall.as_secs_f64().max(1e-9),
            self.features,
            self.sched_features,
            self.failures.len(),
            self.divergences
        )?;
        writeln!(
            f,
            "decisions: {} replayed, {} executed fresh",
            self.replayed_decisions, self.executed_decisions
        )?;
        writeln!(
            f,
            "snapshots: {} taken, {} pages copied, {:.2?} total",
            self.snapshots, self.snapshot_pages, self.snapshot_wall
        )?;
        write!(
            f,
            "restores: {} done, {} pages written ({:.1} avg), {:.2?} total ({:.1?} avg)",
            self.restores,
            self.restore_pages,
            self.restore_pages as f64 / self.restores.max(1) as f64,
            self.restore_wall,
            self.restore_wall / self.restores.max(1) as u32
        )
    }
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub outcome: Outcome,
    pub decisions: Vec<Decision>,
    pub trace_hash: u64,
    pub stderr: String,
    pub new_features: usize,
}

pub struct Search {
    pub session: Session,
    pub nodes: Vec<Node>,
    seen: Bitmap,
    sched_seen: HashSet<u64>,
    /// Largest edge total of any completed run: the PCT horizon `k`.
    k_est: u64,
    /// Per thread, the most edges it has executed in one run.
    thread_est: Vec<u64>,
    rng: SmallRng,
    started: Instant,
    /// Take a snapshot every this many decisions along a rollout.
    pub snapshot_every: usize,
    pub tuning: Tuning,
    pub stats: Stats,
    pub verbose: bool,
}

impl Search {
    /// Start the target, run to its first decision, and snapshot it as the root.
    pub fn new(mut session: Session, seed: u64) -> io::Result<Self> {
        let first = session.step()?;
        let root = match first {
            Event::Decision { kind, n } => Node {
                parent: None,
                choice_from_parent: 0,
                depth: 0,
                kind: Some(kind),
                n,
                edges: session.world.edges,
                children: Vec::new(),
                segment: None,
                exhausted: false,
                closed: false,
                snapshot: None,
                visits: 0,
                novelty: 0,
                outcome: None,
            },
            Event::Done(outcome) => Node {
                parent: None,
                choice_from_parent: 0,
                depth: 0,
                kind: None,
                n: 0,
                edges: session.world.edges,
                children: Vec::new(),
                segment: None,
                exhausted: false,
                closed: true,
                snapshot: None,
                visits: 0,
                novelty: 0,
                outcome: Some(outcome),
            },
        };
        let mut search = Self {
            session,
            nodes: vec![root],
            seen: Bitmap::default(),
            sched_seen: HashSet::new(),
            k_est: 64,
            thread_est: Vec::new(),
            rng: SmallRng::seed_from_u64(seed),
            started: Instant::now(),
            snapshot_every: 8,
            tuning: Tuning::default(),
            stats: Stats::default(),
            verbose: false,
        };
        search.absorb_coverage();
        if search.nodes[0].outcome.is_some() {
            search.stats.runs = 1;
        }
        search.take_snapshot(0)?;
        Ok(search)
    }

    fn absorb_coverage(&mut self) -> u32 {
        let mut fresh = 0;
        for bit in self.session.take_new_coverage() {
            let (w, b) = ((bit / 64) as usize, bit % 64);
            if self.seen.0[w] & (1 << b) == 0 {
                self.seen.0[w] |= 1 << b;
                fresh += 1;
            }
        }
        self.stats.features += fresh as usize;
        fresh
    }

    /// Interleaving features of the finished run: every context switch, identified by where
    /// the outgoing thread stopped (point and last edge) and what ran next. Also refreshes
    /// the PCT horizon estimates.
    fn absorb_schedule(&mut self) -> u32 {
        let trace: &[TraceEvent] = &self.session.world.trace;
        let mut fresh = 0;
        let mut per_thread: Vec<u64> = Vec::new();
        for w in trace.windows(2) {
            let (a, b) = (w[0], w[1]);
            if per_thread.len() <= a.thread {
                per_thread.resize(a.thread + 1, 0);
            }
            per_thread[a.thread] += a.edges;
            if a.thread == b.thread {
                continue;
            }
            let mut h = std::hash::DefaultHasher::new();
            (a.thread, a.point, a.guard, b.thread).hash(&mut h);
            if self.sched_seen.insert(h.finish()) {
                fresh += 1;
            }
        }
        if let Some(last) = trace.last() {
            if per_thread.len() <= last.thread {
                per_thread.resize(last.thread + 1, 0);
            }
            per_thread[last.thread] += last.edges;
        }
        self.k_est = self.k_est.max(self.session.world.edges);
        if self.thread_est.len() < per_thread.len() {
            self.thread_est.resize(per_thread.len(), 0);
        }
        for (est, seen) in self.thread_est.iter_mut().zip(per_thread) {
            *est = (*est).max(seen);
        }
        self.stats.sched_features += fresh as usize;
        fresh
    }

    fn take_snapshot(&mut self, node: NodeId) -> io::Result<()> {
        let (id, st) = self.session.snapshot()?;
        self.nodes[node].snapshot = Some(id);
        self.stats.snapshots += 1;
        self.stats.snapshot_pages += st.pages_copied;
        self.stats.snapshot_wall += st.wall;
        Ok(())
    }

    fn path(&self, mut node: NodeId) -> Vec<NodeId> {
        let mut path = vec![node];
        while let Some(p) = self.nodes[node].parent {
            path.push(p);
            node = p;
        }
        path.reverse();
        path
    }

    /// Bring the session to `node`'s state: restore the nearest snapshotted ancestor, replay.
    pub fn goto(&mut self, node: NodeId) -> io::Result<()> {
        let path = self.path(node);
        let anchor = path
            .iter()
            .rposition(|n| self.nodes[*n].snapshot.is_some())
            .expect("root is always snapshotted");
        let snap = self.nodes[path[anchor]].snapshot.unwrap();
        if self.session.head() != Some(snap)
            || self.session.world.outcome.is_some()
            || self.session.world.pending.is_none()
        {
            let st = self.session.restore(snap)?;
            self.stats.restores += 1;
            self.stats.restore_pages += st.pages_written;
            self.stats.restore_wall += st.wall;
        }
        for pair in path[anchor..].windows(2) {
            let to = pair[1];
            let choice = self.nodes[to].choice_from_parent;
            self.session.choose(choice)?;
            let ev = self.session.step()?;
            self.stats.replayed_decisions += 1;
            if !self.matches(to, &ev) {
                self.stats.divergences += 1;
                return Err(io::Error::other(format!(
                    "divergence replaying to node {to} (depth {}): expected {:?}/{} got {ev:?}",
                    self.nodes[to].depth, self.nodes[to].kind, self.nodes[to].n
                )));
            }
        }
        Ok(())
    }

    fn matches(&self, node: NodeId, ev: &Event) -> bool {
        match (ev, &self.nodes[node]) {
            (Event::Decision { kind, n }, nd) => nd.kind == Some(*kind) && nd.n == *n,
            (Event::Done(o), nd) => nd.outcome.as_ref() == Some(o),
        }
    }

    fn add_child(&mut self, parent: NodeId, choice: u32, ev: &Event) -> NodeId {
        if let Some(existing) = self.nodes[parent].child(choice) {
            return existing;
        }
        let depth = self.nodes[parent].depth + 1;
        let edges = self.session.world.edges;
        let node = match ev {
            Event::Decision { kind, n } => Node {
                parent: Some(parent),
                choice_from_parent: choice,
                depth,
                kind: Some(*kind),
                n: *n,
                edges,
                children: Vec::new(),
                segment: None,
                exhausted: false,
                closed: false,
                snapshot: None,
                visits: 0,
                novelty: 0,
                outcome: None,
            },
            Event::Done(outcome) => Node {
                parent: Some(parent),
                choice_from_parent: choice,
                depth,
                kind: None,
                n: 0,
                edges,
                children: Vec::new(),
                segment: None,
                exhausted: false,
                closed: true,
                snapshot: None,
                visits: 0,
                novelty: 0,
                outcome: Some(outcome.clone()),
            },
        };
        self.nodes.push(node);
        let id = self.nodes.len() - 1;
        self.nodes[parent].children.push((choice, id));
        id
    }

    /// The PCT policy's choice for the pending decision.
    fn policy_choice(&mut self, policy: &mut Policy) -> u32 {
        match self.session.world.pending.as_ref() {
            Some(Pending::Schedule { candidates }) => {
                let candidates = candidates.clone();
                policy.schedule(&mut self.rng, &candidates)
            }
            Some(Pending::Budget { .. }) => policy.budget(self.session.world.edges),
            Some(Pending::Variant { n, .. }) => self.rng.random_range(0..*n),
            None => 0,
        }
    }

    /// An untried choice at a frontier node: uniform over the unexplored siblings, except a
    /// `Budget` node samples an exact edge offset within the thread's estimated run length.
    fn untried_choice(&mut self, node: NodeId) -> Option<u32> {
        let nd = &self.nodes[node];
        let tried: Vec<u32> = nd.children.iter().map(|(c, _)| *c).collect();
        if nd.kind == Some(Kind::Budget) {
            if !tried.contains(&0) {
                return Some(0);
            }
            if let Some(untried) = nd.untried_budgets() {
                return (!untried.is_empty())
                    .then(|| untried[self.rng.random_range(0..untried.len())]);
            }
            let thread = match self.session.world.pending {
                Some(Pending::Budget { thread }) => thread,
                _ => 0,
            };
            let horizon = self.thread_est.get(thread).copied().unwrap_or(0).max(8);
            for _ in 0..64 {
                let c = self.rng.random_range(1..=horizon) as u32;
                if !tried.contains(&c) {
                    return Some(c);
                }
            }
            return None;
        }
        let untried: Vec<u32> = (0..nd.n).filter(|c| !tried.contains(c)).collect();
        if untried.is_empty() {
            None
        } else {
            Some(untried[self.rng.random_range(0..untried.len())])
        }
    }

    /// One search iteration: pick a frontier node, expand an untried choice, roll out.
    pub fn expand_once(&mut self) -> io::Result<Option<RunResult>> {
        let Some(node) = self.pick_frontier() else {
            return Ok(None);
        };
        self.goto(node)?;
        let Some(first) = self.untried_choice(node) else {
            self.nodes[node].exhausted = true;
            self.close_upwards(node);
            return self.expand_once();
        };
        let result = self.rollout(node, first)?;
        Ok(Some(result))
    }

    /// After stepping past a `Budget` node, whose trace had `mark` events before the step: the
    /// budgeted thread's segment is the first event appended. If it ended at a natural stop
    /// the segment is now known and fixes the node's candidate budgets.
    fn learn_budgets(&mut self, node: NodeId, mark: usize) {
        if self.nodes[node].kind != Some(Kind::Budget) || self.nodes[node].segment.is_some() {
            return;
        }
        let Some(seg) = self.session.world.trace.get(mark).copied() else {
            return;
        };
        if seg.point == Point::Preempt {
            return;
        }
        let start = self.nodes[node].edges;
        self.nodes[node].segment = Some(self.session.guards(start, start + seg.edges));
    }

    /// Take `first` at `at`, then follow the PCT policy to the end of the run.
    fn rollout(&mut self, at: NodeId, first: u32) -> io::Result<RunResult> {
        let mut node = at;
        let mut choice = first;
        let mut fresh_total = 0;
        let mut path = self.path(at);
        let threads = self.session.world.threads.len();
        let spent = self
            .session
            .world
            .trace
            .iter()
            .filter(|e| e.point == Point::Preempt)
            .count()
            + usize::from(self.nodes[at].kind == Some(Kind::Budget) && first != 0);
        let mut policy = Policy::new(
            &mut self.rng,
            threads,
            self.k_est,
            self.tuning.pct_depth,
            spent,
        );
        loop {
            let mark = self.session.world.trace.len();
            self.session.choose(choice)?;
            let ev = self.session.step()?;
            self.stats.executed_decisions += 1;
            fresh_total += self.absorb_coverage();
            self.learn_budgets(node, mark);
            if let Some(TraceEvent {
                thread,
                point: Point::Preempt,
                ..
            }) = self.session.world.trace.last().copied()
            {
                policy.demote(&mut self.rng, thread);
            }
            let child = self.add_child(node, choice, &ev);
            path.push(child);
            node = child;
            match ev {
                Event::Decision { .. } => {
                    if self.nodes[node].depth.is_multiple_of(self.snapshot_every)
                        && self.nodes[node].snapshot.is_none()
                    {
                        self.take_snapshot(node)?;
                    }
                    choice = self.policy_choice(&mut policy);
                }
                Event::Done(outcome) => {
                    self.stats.runs += 1;
                    fresh_total += self.absorb_schedule();
                    self.close_upwards(node);
                    // The first run's features are the program's baseline, not a merit of
                    // the path it happened to take.
                    let credit = if self.stats.runs == 1 { 0 } else { fresh_total };
                    for n in &path {
                        self.nodes[*n].visits += 1;
                        self.nodes[*n].novelty += credit;
                    }
                    let decisions = self.session.decisions().to_vec();
                    let stderr = self.session.take_stderr();
                    if !outcome.is_ok() {
                        self.stats.failures.push(Failure {
                            outcome: outcome.clone(),
                            decisions: decisions.clone(),
                            stderr: stderr.clone(),
                            run: self.stats.runs,
                        });
                    }
                    return Ok(RunResult {
                        outcome,
                        decisions,
                        trace_hash: self.session.world.trace_hash(),
                        stderr,
                        new_features: fresh_total as usize,
                    });
                }
            }
        }
    }

    /// Recompute `closed` from `node` up to the root.
    fn close_upwards(&mut self, mut node: NodeId) {
        loop {
            let n = &self.nodes[node];
            let closed = !n.expandable(self.tuning.budget_fanout)
                && n.children.iter().all(|(_, c)| self.nodes[*c].closed);
            self.nodes[node].closed = closed;
            match self.nodes[node].parent {
                Some(p) if closed => node = p,
                _ => return,
            }
        }
    }

    /// MCTS selection: descend from the root by UCB over children (mean new features per run
    /// through the child, plus an exploration bonus) until a node with an untried choice. The
    /// tree structure keeps the search from drowning in the exponentially many deep leaves.
    fn pick_frontier(&mut self) -> Option<NodeId> {
        let mut node = 0;
        loop {
            if self.nodes[node].closed {
                return None;
            }
            if self.nodes[node].expandable(self.tuning.budget_fanout) {
                return Some(node);
            }
            let parent_visits = self.nodes[node].visits as f64 + 2.0;
            let mut best: Option<(NodeId, f64)> = None;
            for &(_, c) in &self.nodes[node].children {
                if self.nodes[c].closed {
                    continue;
                }
                let n = &self.nodes[c];
                let visits = n.visits as f64 + 1.0;
                let mean = (n.novelty as f64 + 1.0) / visits;
                let explore = self.tuning.ucb_c * (parent_visits.ln() / visits).sqrt();
                let score = mean + explore + self.rng.random_range(0.0..1e-6);
                if best.is_none_or(|(_, b)| score > b) {
                    best = Some((c, score));
                }
            }
            match best {
                Some((c, _)) => node = c,
                None => {
                    self.close_upwards(node);
                    return self.pick_frontier();
                }
            }
        }
    }

    /// Stats with `wall` refreshed to the time since `new`.
    pub fn stats(&mut self) -> &Stats {
        self.stats.wall = self.started.elapsed();
        &self.stats
    }

    pub fn run(&mut self, budget: &Budget) -> io::Result<&Stats> {
        let start = Instant::now();
        while self.stats.runs < budget.runs && start.elapsed() < budget.wall {
            match self.expand_once()? {
                None => break,
                Some(r) => {
                    if self.verbose {
                        eprintln!(
                            "run {:>5}: {:<12} {:>3} decisions, +{} features  {}",
                            self.stats.runs,
                            r.outcome.to_string(),
                            r.decisions.len(),
                            r.new_features,
                            r.decisions
                                .iter()
                                .map(|d| format!("{}:{}", d.kind, d.choice))
                                .collect::<Vec<_>>()
                                .join(" ")
                        );
                    }
                    if budget.stop_on_failure && !r.outcome.is_ok() {
                        break;
                    }
                }
            }
        }
        Ok(self.stats())
    }

    /// Replay a choice list from the root (missing choices default to 0). Uses the deepest
    /// snapshot on the matching tree path; creates nodes along the way.
    pub fn replay(&mut self, choices: &[u32]) -> io::Result<RunResult> {
        if self.nodes[0].kind.is_none() {
            let outcome = self.nodes[0].outcome.clone().unwrap();
            return Ok(RunResult {
                outcome,
                decisions: Vec::new(),
                trace_hash: self.session.world.trace_hash(),
                stderr: String::new(),
                new_features: 0,
            });
        }
        // Follow existing nodes as far as the choices match.
        let mut node = 0;
        let mut i = 0;
        while i < choices.len() {
            match self.nodes[node].child(choices[i]) {
                Some(c) if self.nodes[c].kind.is_some() || i + 1 == choices.len() => {
                    node = c;
                    i += 1;
                }
                _ => break,
            }
        }
        if self.nodes[node].kind.is_none() {
            // Landed on a known terminal: replay it anyway to produce the result.
            let p = self.nodes[node].parent.unwrap();
            i -= 1;
            node = p;
        }
        self.goto(node)?;
        let mut path = self.path(node);
        let mut fresh_total = 0;
        loop {
            let n = self.nodes[node].n;
            let choice = if i < choices.len() {
                choices[i].min(n - 1)
            } else {
                0
            };
            i += 1;
            let mark = self.session.world.trace.len();
            self.session.choose(choice)?;
            let ev = self.session.step()?;
            self.stats.executed_decisions += 1;
            fresh_total += self.absorb_coverage();
            self.learn_budgets(node, mark);
            let child = self.add_child(node, choice, &ev);
            path.push(child);
            node = child;
            if let Event::Done(outcome) = ev {
                self.stats.runs += 1;
                fresh_total += self.absorb_schedule();
                self.close_upwards(node);
                let decisions = self.session.decisions().to_vec();
                let stderr = self.session.take_stderr();
                return Ok(RunResult {
                    outcome,
                    decisions,
                    trace_hash: self.session.world.trace_hash(),
                    stderr,
                    new_features: fresh_total as usize,
                });
            }
            if self.nodes[node].depth.is_multiple_of(self.snapshot_every)
                && self.nodes[node].snapshot.is_none()
            {
                self.take_snapshot(node)?;
            }
        }
    }

    /// Tree-aware shrinking: truncate, delete one decision, or lower one choice; keep any
    /// candidate that reproduces `outcome` and is cheaper (fewer non-zero choices, then shorter).
    pub fn shrink(
        &mut self,
        failing: &[Decision],
        outcome: &Outcome,
        max_runs: usize,
    ) -> io::Result<(Vec<Decision>, usize)> {
        let same = |o: &Outcome| {
            std::mem::discriminant(o) == std::mem::discriminant(outcome)
                && match (o, outcome) {
                    (Outcome::Exited(a), Outcome::Exited(b)) => a == b,
                    (Outcome::Signaled(a), Outcome::Signaled(b)) => a == b,
                    _ => true,
                }
        };
        let cost = |c: &[u32]| (c.iter().filter(|x| **x != 0).count(), c.len());
        let mut best: Vec<u32> = failing.iter().map(|d| d.choice).collect();
        while best.last() == Some(&0) {
            best.pop();
        }
        let mut best_decisions = failing.to_vec();
        let mut runs = 0;
        let mut improved = true;
        while improved && runs < max_runs {
            improved = false;
            let mut candidates: Vec<Vec<u32>> = Vec::new();
            let len = best.len();
            // Truncations (largest first).
            for cut in (0..len).rev() {
                candidates.push(best[..cut].to_vec());
            }
            // Delete one decision (later decisions shift left onto earlier positions).
            for i in (0..len).rev() {
                let mut c = best.clone();
                c.remove(i);
                candidates.push(c);
            }
            // Lower one choice to zero, then to choice-1.
            for i in (0..len).rev() {
                if best[i] != 0 {
                    let mut c = best.clone();
                    c[i] = 0;
                    candidates.push(c);
                    if best[i] > 1 {
                        let mut c = best.clone();
                        c[i] -= 1;
                        candidates.push(c);
                    }
                }
            }
            for cand in candidates {
                if runs >= max_runs {
                    break;
                }
                let mut trimmed = cand;
                while trimmed.last() == Some(&0) {
                    trimmed.pop();
                }
                if cost(&trimmed) >= cost(&best) {
                    continue;
                }
                let r = self.replay(&trimmed)?;
                runs += 1;
                if same(&r.outcome) {
                    let mut actual: Vec<u32> = r.decisions.iter().map(|d| d.choice).collect();
                    while actual.last() == Some(&0) {
                        actual.pop();
                    }
                    if cost(&actual) < cost(&best) {
                        best = actual;
                        best_decisions = r.decisions;
                        improved = true;
                        break;
                    }
                }
            }
        }
        Ok((best_decisions, runs))
    }
}

pub fn format_decisions(decisions: &[Decision]) -> String {
    decisions
        .iter()
        .map(|d| d.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget_node(segment: Option<Vec<u32>>, tried: &[u32]) -> Node {
        Node {
            parent: None,
            choice_from_parent: 0,
            depth: 0,
            kind: Some(Kind::Budget),
            n: BUDGET_MAX,
            edges: 0,
            children: tried.iter().map(|c| (*c, 0)).collect(),
            segment,
            exhausted: false,
            closed: false,
            snapshot: None,
            visits: 0,
            novelty: 0,
            outcome: None,
        }
    }

    #[test]
    fn budgets_are_first_occurrences_of_distinct_guards() {
        let n = budget_node(Some(vec![5, 5, 9, 5, 9, 2]), &[]);
        assert_eq!(n.budgets(), Some(vec![1, 3, 6]));
        assert_eq!(budget_node(Some(vec![]), &[]).budgets(), Some(vec![]));
        assert_eq!(budget_node(None, &[]).budgets(), None);
    }

    #[test]
    fn budget_node_widens_then_closes() {
        // Nothing tried: 0 first.
        assert!(budget_node(None, &[]).expandable(2));
        // Unknown segment: sampled offsets up to the fanout.
        assert!(budget_node(None, &[0, 7]).expandable(3));
        assert!(!budget_node(None, &[0, 7, 9]).expandable(3));
        // Known segment: only its distinct guards, and no more once all are tried.
        let seg = Some(vec![1, 2, 3]);
        assert!(budget_node(seg.clone(), &[0]).expandable(8));
        assert!(!budget_node(seg.clone(), &[0, 1, 2, 3]).expandable(8));
        assert!(!budget_node(Some(vec![]), &[0]).expandable(8));
        // Fanout caps the up-front width; visits grow it.
        let mut n = budget_node(Some((1..=20).collect()), &[0, 1, 2]);
        assert!(!n.expandable(2));
        n.visits = 4;
        assert!(n.expandable(2));
    }

    #[test]
    fn pct_policy_prefers_priority_and_counts_spent_preemptions() {
        let mut rng = SmallRng::seed_from_u64(1);
        let p = Policy::new(&mut rng, 2, 100, 3, 3);
        assert!(p.change_points.is_empty());
        let mut p = Policy::new(&mut rng, 2, 100, 1, 0);
        assert_eq!(p.change_points.len(), 1);
        let cands = [Candidate::Run(0), Candidate::Run(1)];
        let top = p.schedule(&mut rng, &cands) as usize;
        p.demote(&mut rng, top);
        assert_eq!(p.schedule(&mut rng, &cands) as usize, 1 - top);
        let cp = p.change_points[0];
        assert_eq!(p.budget(cp + 1), 0);
        assert!(p.change_points.is_empty());
    }
}
