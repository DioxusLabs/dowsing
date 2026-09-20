//! The set of live holders, keyed by the stream bytes they have consumed.
//!
//! Conceptually a trie over byte prefixes; with at most a few dozen holders a
//! linear scan with `memcmp` is faster than any pointer-chasing structure, so
//! that is what this is. `best_match` returns the deepest holder whose consumed
//! bytes are a prefix of the candidate's materialised prefix.

use crate::proto::{Channel, Kind};
use std::time::Instant;

#[derive(Debug)]
pub struct Holder {
    pub id: usize,
    pub pid: i32,
    /// Bytes consumed before the pause (`trace[..cursor]`).
    pub trace: Vec<u8>,
    pub kind: Kind,
    pub control: Channel,
    pub created: Instant,
    pub last_used: Instant,
    pub uses: u64,
    /// Wall time the runner spent from its own origin to this boundary.
    pub prefix_cost_us: u64,
    pub fork_us: u64,
    pub rss_kb: u64,
    /// Holder whose continuation created this one, if any.
    pub parent: Option<usize>,
}

impl Holder {
    pub fn cursor(&self) -> usize {
        self.trace.len()
    }

    /// Prefix cost accumulated along the holder chain (what a continuation skips).
    pub fn chain_cost_us(&self, set: &HolderSet) -> u64 {
        let mut total = self.prefix_cost_us;
        let mut parent = self.parent;
        while let Some(id) = parent {
            match set.get(id) {
                Some(holder) => {
                    total += holder.prefix_cost_us;
                    parent = holder.parent;
                }
                None => break,
            }
        }
        total
    }
}

#[derive(Debug, Default)]
pub struct HolderSet {
    holders: Vec<Holder>,
    next_id: usize,
}

impl HolderSet {
    pub fn len(&self) -> usize {
        self.holders.len()
    }

    pub fn is_empty(&self) -> bool {
        self.holders.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Holder> {
        self.holders.iter()
    }

    pub fn get(&self, id: usize) -> Option<&Holder> {
        self.holders.iter().find(|holder| holder.id == id)
    }

    pub fn get_mut(&mut self, id: usize) -> Option<&mut Holder> {
        self.holders.iter_mut().find(|holder| holder.id == id)
    }

    pub fn allocate_id(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn insert(&mut self, holder: Holder) {
        self.holders.push(holder);
    }

    pub fn remove(&mut self, id: usize) -> Option<Holder> {
        let index = self.holders.iter().position(|holder| holder.id == id)?;
        Some(self.holders.swap_remove(index))
    }

    /// Deepest holder whose consumed bytes are a prefix of `prefix`.
    pub fn best_match(&self, prefix: &[u8]) -> Option<&Holder> {
        self.holders
            .iter()
            .filter(|holder| {
                let cursor = holder.cursor();
                prefix.len() >= cursor && prefix[..cursor] == holder.trace[..]
            })
            .max_by_key(|holder| (holder.cursor(), holder.created))
    }

    /// Is there already a holder paused at exactly this prefix?
    pub fn has_exact(&self, trace: &[u8]) -> bool {
        self.holders.iter().any(|holder| holder.trace == trace)
    }

    /// Least valuable holder: fewest uses, then oldest last use.
    pub fn eviction_candidate(&self, protect: Option<usize>) -> Option<usize> {
        self.holders
            .iter()
            .filter(|holder| Some(holder.id) != protect)
            .min_by_key(|holder| (holder.uses, holder.last_used))
            .map(|holder| holder.id)
    }

    pub fn drain(&mut self) -> Vec<Holder> {
        std::mem::take(&mut self.holders)
    }
}
