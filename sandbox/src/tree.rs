//! The decision tree and the search over it.
//!
//! Every decision point the session reports becomes a [`Node`]; edges are choices. Expanding a
//! node means restoring the nearest snapshotted ancestor, replaying the decisions down to the
//! node, taking an untried choice and rolling out with the default policy until the run ends.
//! Coverage novelty found beneath a node is its energy; frontier nodes are sampled by it.

use crate::{
    session::{Event, Session},
    shm::Bitmap,
    snapshot::SnapshotId,
    world::{Decision, Kind, Outcome},
};
use rand::{Rng, SeedableRng, rngs::SmallRng};
use std::{
    fmt, io,
    time::{Duration, Instant},
};

pub type NodeId = usize;

#[derive(Debug, Clone)]
pub struct Node {
    pub parent: Option<NodeId>,
    pub choice_from_parent: u32,
    pub depth: usize,
    /// The decision pending at this node; `None` for terminal nodes.
    pub kind: Option<Kind>,
    pub n: u32,
    pub children: Vec<(u32, NodeId)>,
    pub snapshot: Option<SnapshotId>,
    pub visits: u32,
    /// New coverage features first found on runs through this node.
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

    fn expandable(&self) -> bool {
        self.kind.is_some() && (self.children.len() as u32) < self.n
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
    pub features: usize,
    pub divergences: usize,
    pub failures: Vec<Failure>,
    pub wall: Duration,
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "runs {} in {:.2?} ({:.0}/s), features {}, failures {}, divergences {}",
            self.runs,
            self.wall,
            self.runs as f64 / self.wall.as_secs_f64().max(1e-9),
            self.features,
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
    rng: SmallRng,
    started: Instant,
    /// Take a snapshot every this many decisions along a rollout.
    pub snapshot_every: usize,
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
                children: Vec::new(),
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
                children: Vec::new(),
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
            rng: SmallRng::seed_from_u64(seed),
            started: Instant::now(),
            snapshot_every: 8,
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
        let node = match ev {
            Event::Decision { kind, n } => Node {
                parent: Some(parent),
                choice_from_parent: choice,
                depth,
                kind: Some(*kind),
                n: *n,
                children: Vec::new(),
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
                children: Vec::new(),
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

    fn default_choice(&mut self, n: u32) -> u32 {
        if n <= 1 || self.rng.random_bool(0.5) {
            0
        } else {
            self.rng.random_range(0..n)
        }
    }

    /// One search iteration: pick a frontier node, expand an untried choice, roll out.
    pub fn expand_once(&mut self) -> io::Result<Option<RunResult>> {
        let Some(node) = self.pick_frontier() else {
            return Ok(None);
        };
        self.goto(node)?;
        let tried: Vec<u32> = self.nodes[node].children.iter().map(|(c, _)| *c).collect();
        let untried: Vec<u32> = (0..self.nodes[node].n)
            .filter(|c| !tried.contains(c))
            .collect();
        let first = untried[self.rng.random_range(0..untried.len())];
        let result = self.rollout(node, first)?;
        Ok(Some(result))
    }

    /// Take `first` at `at`, then follow the default policy to the end of the run.
    fn rollout(&mut self, at: NodeId, first: u32) -> io::Result<RunResult> {
        let mut node = at;
        let mut choice = first;
        let mut fresh_total = 0;
        let mut path = self.path(at);
        loop {
            self.session.choose(choice)?;
            let ev = self.session.step()?;
            self.stats.executed_decisions += 1;
            fresh_total += self.absorb_coverage();
            let child = self.add_child(node, choice, &ev);
            path.push(child);
            node = child;
            match ev {
                Event::Decision { n, .. } => {
                    if self.nodes[node].depth.is_multiple_of(self.snapshot_every)
                        && self.nodes[node].snapshot.is_none()
                    {
                        self.take_snapshot(node)?;
                    }
                    choice = self.default_choice(n);
                }
                Event::Done(outcome) => {
                    self.stats.runs += 1;
                    for n in &path {
                        self.nodes[*n].visits += 1;
                        self.nodes[*n].novelty += fresh_total;
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

    /// Weighted sample over expandable nodes: energy = (novelty + 1) / sqrt(visits + 1).
    fn pick_frontier(&mut self) -> Option<NodeId> {
        let weights: Vec<(NodeId, f64)> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.expandable())
            .map(|(i, n)| {
                (
                    i,
                    (n.novelty as f64 + 1.0)
                        / ((n.visits as f64) + 1.0).sqrt()
                        / (n.depth as f64 + 1.0),
                )
            })
            .collect();
        if weights.is_empty() {
            return None;
        }
        let total: f64 = weights.iter().map(|(_, w)| w).sum();
        let mut x = self.rng.random_range(0.0..total);
        for (id, w) in &weights {
            if x < *w {
                return Some(*id);
            }
            x -= w;
        }
        weights.last().map(|(id, _)| *id)
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
                            "run {:>5}: {:<12} {:>3} decisions, +{} features",
                            self.stats.runs,
                            r.outcome.to_string(),
                            r.decisions.len(),
                            r.new_features
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
            self.session.choose(choice)?;
            let ev = self.session.step()?;
            self.stats.executed_decisions += 1;
            fresh_total += self.absorb_coverage();
            let child = self.add_child(node, choice, &ev);
            path.push(child);
            node = child;
            if let Event::Done(outcome) = ev {
                self.stats.runs += 1;
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
