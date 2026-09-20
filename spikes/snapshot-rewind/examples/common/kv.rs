//! Demo target: a deterministic log-structured KV store whose setup replays a
//! write-ahead log into an arena sized to the requested RSS, followed by a
//! random op sequence checked against a model. `Restore` after `Compact`
//! reinstates stale slot offsets (the deliberate bug).
//!
//! Shared by the examples and the tests through `#[path]`.

#![allow(dead_code)]

use iterator_fuzz::{CaseRng, ChildRng, coverage::CoverageCapture};
use rand::RngCore;
use snapshot_rewind::Verdict;
use std::collections::BTreeMap;

pub const KEYS: usize = 8;
pub const VALUE: usize = 64;
pub const OPS: usize = 6;

#[derive(Debug, Clone)]
pub struct KvConfig {
    pub arena_mb: usize,
    /// WAL replay passes over the arena (each pass touches every page).
    pub passes: usize,
    pub max_ops: usize,
    /// Extra work per op in arena bytes hashed (0 = ops are microseconds).
    pub op_work_kb: usize,
}

impl Default for KvConfig {
    fn default() -> Self {
        Self {
            arena_mb: 10,
            passes: 1,
            max_ops: 64,
            op_work_kb: 0,
        }
    }
}

pub struct Store {
    arena: Vec<u8>,
    index: [Option<usize>; KEYS],
    head: usize,
    saved: Option<[Option<usize>; KEYS]>,
}

impl Store {
    /// "Expensive setup": allocate the arena and replay a WAL into it.
    pub fn setup(config: &KvConfig, flavor: usize) -> Self {
        let len = config.arena_mb * 1024 * 1024;
        let mut arena = vec![0u8; len.max(VALUE * KEYS * 4)];
        let salt = 0x9E37_79B9_7F4A_7C15u64.wrapping_mul(flavor as u64 + 1);
        for pass in 0..config.passes.max(1) {
            let mut x = salt ^ (pass as u64).wrapping_mul(0xD1B5_4A32_D192_ED03);
            for chunk in arena.chunks_exact_mut(8) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                chunk.copy_from_slice(&x.to_le_bytes());
            }
        }
        let mut store = Self {
            arena,
            index: [None; KEYS],
            head: 0,
            saved: None,
        };
        // Replayed records.
        for record in 0..(KEYS * 4) {
            let key = (record * 5 + flavor) % KEYS;
            let value = [(record as u8).wrapping_mul(31) ^ flavor as u8; VALUE];
            store.put(key, &value);
        }
        store
    }

    pub fn arena_len(&self) -> usize {
        self.arena.len()
    }

    fn put(&mut self, key: usize, value: &[u8; VALUE]) {
        if self.head + VALUE > self.arena.len() {
            self.compact();
        }
        let slot = self.head;
        self.arena[slot..slot + VALUE].copy_from_slice(value);
        self.index[key] = Some(slot);
        self.head += VALUE;
    }

    fn get(&self, key: usize) -> Option<[u8; VALUE]> {
        let slot = self.index[key]?;
        let mut out = [0u8; VALUE];
        out.copy_from_slice(&self.arena[slot..slot + VALUE]);
        Some(out)
    }

    fn delete(&mut self, key: usize) {
        self.index[key] = None;
    }

    fn snapshot(&mut self) {
        self.saved = Some(self.index);
    }

    /// BUG: restores slot offsets that `compact` may have moved.
    fn restore(&mut self) {
        if let Some(saved) = self.saved {
            self.index = saved;
        }
    }

    fn compact(&mut self) {
        let mut live: Vec<(usize, usize)> = (0..KEYS)
            .filter_map(|key| self.index[key].map(|slot| (slot, key)))
            .collect();
        live.sort_unstable();
        let mut head = 0;
        for (slot, key) in live {
            if slot != head {
                debug_assert!(slot > head, "live slots are monotone during compaction");
                let (front, back) = self.arena.split_at_mut(slot);
                front[head..head + VALUE].copy_from_slice(&back[..VALUE]);
            }
            self.index[key] = Some(head);
            head += VALUE;
        }
        self.head = head;
    }

    /// Touch `kb` kilobytes of the arena (simulated per-op work).
    fn work(&self, kb: usize, seed: usize) -> u64 {
        let bytes = kb * 1024;
        if bytes == 0 || self.arena.is_empty() {
            return 0;
        }
        let start = (seed * 4099) % self.arena.len();
        let mut acc = 0u64;
        for i in 0..bytes {
            acc = acc
                .wrapping_mul(31)
                .wrapping_add(self.arena[(start + i) % self.arena.len()] as u64);
        }
        acc
    }
}

#[derive(Default)]
pub struct Model {
    map: BTreeMap<usize, [u8; VALUE]>,
    saved: Option<BTreeMap<usize, [u8; VALUE]>>,
}

impl Model {
    fn from_store(store: &Store) -> Self {
        let mut map = BTreeMap::new();
        for key in 0..KEYS {
            if let Some(value) = store.get(key) {
                map.insert(key, value);
            }
        }
        Self { map, saved: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Put(usize, u8),
    Get(usize),
    Delete(usize),
    Snapshot,
    Compact,
    Restore,
}

/// Both `CaseRng` and the per-item `ChildRng` can draw ops.
pub trait OpRng: RngCore {
    fn variant(&mut self, upper: usize) -> usize;
}

impl<C: CoverageCapture> OpRng for CaseRng<C> {
    fn variant(&mut self, upper: usize) -> usize {
        CaseRng::variant(self, upper)
    }
}

impl<C: CoverageCapture> OpRng for ChildRng<'_, C> {
    fn variant(&mut self, upper: usize) -> usize {
        ChildRng::variant(self, upper)
    }
}

pub fn draw_op<R: OpRng>(rng: &mut R) -> Op {
    match rng.variant(OPS) {
        0 => {
            let key = rng.variant(KEYS);
            let fill = rng.next_u32() as u8;
            Op::Put(key, fill)
        }
        1 => Op::Get(rng.variant(KEYS)),
        2 => Op::Delete(rng.variant(KEYS)),
        3 => Op::Snapshot,
        4 => Op::Compact,
        _ => Op::Restore,
    }
}

/// Apply one op to both; `Err` on divergence.
pub fn apply(store: &mut Store, model: &mut Model, op: Op) -> Result<(), String> {
    match op {
        Op::Put(key, fill) => {
            let value = [fill; VALUE];
            store.put(key, &value);
            model.map.insert(key, value);
        }
        Op::Get(key) => {
            let actual = store.get(key);
            let expected = model.map.get(&key).copied();
            if actual != expected {
                return Err(format!(
                    "get({key}) = {:?}, expected {:?}",
                    actual.map(|value| value[0]),
                    expected.map(|value| value[0])
                ));
            }
        }
        Op::Delete(key) => {
            store.delete(key);
            model.map.remove(&key);
        }
        Op::Snapshot => {
            store.snapshot();
            model.saved = Some(model.map.clone());
        }
        Op::Compact => store.compact(),
        Op::Restore => {
            store.restore();
            if let Some(saved) = &model.saved {
                model.map = saved.clone();
            }
        }
    }
    Ok(())
}

/// The full harness body: setup, checkpoint hint, op sequence.
///
/// Returns `(verdict, ops)`. Ops are returned so callers can print the failing
/// sequence; the byte trace is what dowsing replays.
pub fn run_case<C: CoverageCapture>(rng: &mut CaseRng<C>, config: &KvConfig) -> (Verdict, Vec<Op>) {
    let flavor = rng.variant(3);
    let mut store = Store::setup(config, flavor);
    rng.checkpoint_hint();
    let mut model = Model::from_store(&store);
    let mut ops = Vec::new();
    let mut sink = 0u64;
    for mut item in rng.range(0..=config.max_ops) {
        let op = draw_op(&mut item);
        ops.push(op);
        if config.op_work_kb > 0 {
            sink ^= store.work(config.op_work_kb, ops.len());
        }
        if let Err(_divergence) = apply(&mut store, &mut model, op) {
            std::hint::black_box(sink);
            return (Verdict::Fail, ops);
        }
    }
    std::hint::black_box(sink);
    (Verdict::Keep, ops)
}

/// Same body without dowsing: used by the in-process baseline.
pub fn body<C: CoverageCapture>(rng: &mut CaseRng<C>, config: &KvConfig) -> Verdict {
    run_case(rng, config).0
}

/// Replay a case's ops from its byte trace (for printing).
pub fn describe_ops(ops: &[Op]) -> String {
    ops.iter()
        .map(|op| match op {
            Op::Put(k, v) => format!("put({k},{v})"),
            Op::Get(k) => format!("get({k})"),
            Op::Delete(k) => format!("del({k})"),
            Op::Snapshot => "snap".to_string(),
            Op::Compact => "compact".to_string(),
            Op::Restore => "restore".to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}
