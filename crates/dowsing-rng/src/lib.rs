//! Semantic RNG traces that can be forked, stored in memory, and replayed.

use rand::{RngCore, SeedableRng, rngs::SmallRng};
use std::{
    ops::{Bound, Range, RangeBounds},
    sync::{Arc, Mutex, MutexGuard},
};

/// Replayable RNG trace produced by [`SemanticRng::fork_trace`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {
    seed: u64,
    root: TraceNode,
    flat: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TraceNode {
    events: Vec<TraceEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceEvent {
    Draw {
        bytes: Vec<u8>,
    },
    Range {
        length: Vec<u8>,
        children: Vec<TraceNode>,
    },
}

/// Span metadata for one semantic range in a flattened trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceSpan {
    pub length_start: usize,
    pub length_len: usize,
    pub items: Vec<Range<usize>>,
}

/// Snapshot of a semantic RNG execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceSnapshot {
    pub seed: u64,
    pub trace: Trace,
    pub prefix: Vec<u8>,
    pub draws: Vec<Range<usize>>,
    pub sequences: Vec<SequenceSpan>,
    pub bytes_consumed: usize,
}

/// Shared handle for forking or finishing a semantic RNG trace.
#[derive(Debug, Clone)]
pub struct TraceHandle {
    runtime: Arc<Mutex<SemanticRuntime>>,
}

/// RNG that records semantic draw and range structure while replaying a stored trace.
#[derive(Debug)]
pub struct SemanticRng {
    handle: TraceHandle,
    node_id: usize,
}

#[derive(Debug)]
struct SemanticRuntime {
    fallback: SmallRng,
    seed: u64,
    flat_replay: Option<Vec<u8>>,
    cursor: usize,
    bytes_consumed: usize,
    prefix: Vec<u8>,
    draws: Vec<Range<usize>>,
    finished: bool,
    nodes: Vec<RngNode>,
    ranges: Vec<RangeNode>,
}

#[derive(Debug)]
struct RngNode {
    parent: Option<usize>,
    end: Option<usize>,
    active_child: Option<usize>,
    replay: ReplayCursor,
    events: Vec<RuntimeEvent>,
}

#[derive(Debug)]
struct RangeNode {
    item_nodes: Vec<usize>,
    replay_children: Vec<TraceNode>,
}

#[derive(Debug, Clone, Default)]
struct ReplayCursor {
    node: Option<TraceNode>,
    event_index: usize,
    draw_offset: usize,
}

#[derive(Debug)]
enum RuntimeEvent {
    Draw(Vec<u8>),
    Range { length: Vec<u8>, range_id: usize },
}

enum ReplaySource<'a> {
    NodeDraw,
    RangeLength(&'a [u8]),
    FlatOnly,
}

/// Range iterator returned by [`SemanticRng::range`].
#[derive(Debug)]
pub struct RangeIter<'a> {
    handle: TraceHandle,
    parent_node: usize,
    range_id: usize,
    len: usize,
    index: usize,
    _borrow: std::marker::PhantomData<&'a mut SemanticRng>,
}

impl Trace {
    /// Build an empty trace backed by `seed`.
    pub fn empty(seed: u64) -> Self {
        Self {
            seed,
            root: TraceNode::default(),
            flat: None,
        }
    }

    /// Build a legacy flat-prefix trace backed by `seed`.
    pub fn from_flat_prefix(seed: u64, prefix: Vec<u8>) -> Self {
        Self {
            seed,
            root: TraceNode {
                events: if prefix.is_empty() {
                    Vec::new()
                } else {
                    vec![TraceEvent::Draw {
                        bytes: prefix.clone(),
                    }]
                },
            },
            flat: Some(prefix),
        }
    }

    /// Seed backing this trace.
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Return the flattened byte prefix represented by this trace.
    pub fn flatten_prefix(&self) -> Vec<u8> {
        if let Some(prefix) = &self.flat {
            return prefix.clone();
        }
        let mut prefix = Vec::new();
        flatten_node(&self.root, &mut prefix);
        prefix
    }

    /// Return semantic range spans in flattened-prefix coordinates.
    pub fn sequence_spans(&self) -> Vec<SequenceSpan> {
        let mut cursor = 0;
        let mut sequences = Vec::new();
        collect_sequence_spans(&self.root, &mut cursor, &mut sequences);
        sequences
    }

    fn from_root(seed: u64, root: TraceNode) -> Self {
        Self {
            seed,
            root,
            flat: None,
        }
    }

    #[cfg(test)]
    fn from_range(seed: u64, length: impl Into<Vec<u8>>, children: Vec<Vec<u8>>) -> Self {
        Self {
            seed,
            root: TraceNode {
                events: vec![TraceEvent::Range {
                    length: length.into(),
                    children: children
                        .into_iter()
                        .map(|bytes| TraceNode {
                            events: if bytes.is_empty() {
                                Vec::new()
                            } else {
                                vec![TraceEvent::Draw { bytes }]
                            },
                        })
                        .collect(),
                }],
            },
            flat: None,
        }
    }

    #[cfg(test)]
    fn from_range_then_draw(
        seed: u64,
        length: impl Into<Vec<u8>>,
        children: Vec<Vec<u8>>,
        tail: Vec<u8>,
    ) -> Self {
        let mut events = vec![TraceEvent::Range {
            length: length.into(),
            children: children
                .into_iter()
                .map(|bytes| TraceNode {
                    events: if bytes.is_empty() {
                        Vec::new()
                    } else {
                        vec![TraceEvent::Draw { bytes }]
                    },
                })
                .collect(),
        }];
        if !tail.is_empty() {
            events.push(TraceEvent::Draw { bytes: tail });
        }
        Self {
            seed,
            root: TraceNode { events },
            flat: None,
        }
    }
}

impl SemanticRng {
    /// Create an RNG that records and replays `trace`.
    pub fn new(trace: Trace) -> Self {
        let seed = trace.seed;
        let flat_replay = trace.flat;
        let replay = if flat_replay.is_some() {
            ReplayCursor::default()
        } else {
            ReplayCursor::new(trace.root)
        };
        Self {
            handle: TraceHandle {
                runtime: Arc::new(Mutex::new(SemanticRuntime {
                    fallback: SmallRng::seed_from_u64(seed),
                    seed,
                    flat_replay,
                    cursor: 0,
                    bytes_consumed: 0,
                    prefix: Vec::new(),
                    draws: Vec::new(),
                    finished: false,
                    nodes: vec![RngNode {
                        parent: None,
                        end: None,
                        active_child: None,
                        replay,
                        events: Vec::new(),
                    }],
                    ranges: Vec::new(),
                })),
            },
            node_id: 0,
        }
    }

    /// Seed backing this execution.
    pub fn seed(&self) -> u64 {
        self.handle.seed()
    }

    /// Shared handle for this execution.
    pub fn handle(&self) -> TraceHandle {
        self.handle.clone()
    }

    /// Fork the consumed RNG path into a replayable trace.
    pub fn fork_trace(&self) -> Trace {
        self.handle.fork_trace()
    }

    /// Finish the shared execution and return its trace snapshot.
    pub fn finish(&mut self) -> Result<TraceSnapshot, String> {
        self.handle.finish()
    }

    /// Generate a length in `range` and return a structured range iterator.
    pub fn range<R>(&mut self, range: R) -> RangeIter<'_>
    where
        R: RangeBounds<usize>,
    {
        let handle = self.handle.clone();
        let (len, range_id) = lock_runtime(&handle.runtime).open_range(self.node_id, range);
        RangeIter {
            handle,
            parent_node: self.node_id,
            range_id,
            len,
            index: 0,
            _borrow: std::marker::PhantomData,
        }
    }
}

impl TraceHandle {
    /// Seed backing this execution.
    pub fn seed(&self) -> u64 {
        lock_runtime(&self.runtime).seed
    }

    /// Fork the consumed RNG path into a replayable trace.
    pub fn fork_trace(&self) -> Trace {
        lock_runtime(&self.runtime).fork_trace()
    }

    /// Finish the shared execution and return its trace snapshot.
    pub fn finish(&self) -> Result<TraceSnapshot, String> {
        lock_runtime(&self.runtime).finish()
    }
}

impl<'a> Iterator for RangeIter<'a> {
    type Item = SemanticRng;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.len {
            return None;
        }

        let position = self.index;
        self.index += 1;
        let node_id = lock_runtime(&self.handle.runtime).open_range_item(
            self.parent_node,
            self.range_id,
            position,
        );
        Some(SemanticRng {
            handle: self.handle.clone(),
            node_id,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for RangeIter<'_> {}

impl RngCore for SemanticRng {
    fn next_u32(&mut self) -> u32 {
        lock_runtime(&self.handle.runtime).next_u32(self.node_id)
    }

    fn next_u64(&mut self) -> u64 {
        lock_runtime(&self.handle.runtime).next_u64(self.node_id)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        lock_runtime(&self.handle.runtime).fill_bytes(self.node_id, dst);
    }
}

impl Drop for SemanticRng {
    fn drop(&mut self) {
        lock_runtime(&self.handle.runtime).close_node(self.node_id);
    }
}

impl ReplayCursor {
    fn new(node: TraceNode) -> Self {
        Self {
            node: Some(node),
            event_index: 0,
            draw_offset: 0,
        }
    }
}

impl SemanticRuntime {
    fn fork_trace(&self) -> Trace {
        Trace::from_root(self.seed, self.build_trace_node(0))
    }

    fn finish(&mut self) -> Result<TraceSnapshot, String> {
        if self.finished {
            return Err("semantic rng already finished".to_string());
        }
        self.finished = true;
        let trace = self.fork_trace();
        Ok(TraceSnapshot {
            seed: self.seed,
            trace: trace.clone(),
            prefix: self.prefix.clone(),
            draws: self.draws.clone(),
            sequences: trace.sequence_spans(),
            bytes_consumed: self.bytes_consumed,
        })
    }

    fn open_range<R>(&mut self, node_id: usize, range: R) -> (usize, usize)
    where
        R: RangeBounds<usize>,
    {
        self.assert_node_available(node_id);
        let (start, width) = normalize_range(range);
        let replay_range = self.take_replay_range(node_id);
        let (len, length) = if width == 1 {
            (start, Vec::new())
        } else {
            let length = if let Some((replay_length, _)) = &replay_range {
                self.draw_vec_from(node_id, 4, false, ReplaySource::RangeLength(replay_length))
            } else {
                self.draw_vec_from(node_id, 4, false, ReplaySource::FlatOnly)
            };
            let value = u32::from_le_bytes(to_word_bytes(&length));
            (
                start + (value as u16 % width.min(u16::MAX as usize) as u16) as usize,
                length,
            )
        };
        let range_id = self.ranges.len();
        self.nodes[node_id]
            .events
            .push(RuntimeEvent::Range { length, range_id });
        self.ranges.push(RangeNode {
            item_nodes: Vec::with_capacity(len),
            replay_children: replay_range
                .map(|(_, children)| children)
                .unwrap_or_default(),
        });
        (len, range_id)
    }

    fn open_range_item(&mut self, parent_node: usize, range_id: usize, position: usize) -> usize {
        self.assert_node_available(parent_node);
        let replay = self
            .ranges
            .get(range_id)
            .and_then(|range| range.replay_children.get(position))
            .cloned()
            .map(ReplayCursor::new)
            .unwrap_or_default();
        let node_id = self.nodes.len();
        self.nodes[parent_node].active_child = Some(node_id);
        self.nodes.push(RngNode {
            parent: Some(parent_node),
            end: None,
            active_child: None,
            replay,
            events: Vec::new(),
        });
        self.ranges
            .get_mut(range_id)
            .expect("range item references missing range")
            .item_nodes
            .push(node_id);
        node_id
    }

    fn next_u32(&mut self, node_id: usize) -> u32 {
        let bytes = self.draw_array::<4>(node_id, true);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self, node_id: usize) -> u64 {
        let bytes = self.draw_array::<8>(node_id, true);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, node_id: usize, dst: &mut [u8]) {
        let bytes = self.draw_vec(node_id, dst.len(), true);
        dst.copy_from_slice(&bytes);
    }

    fn record_draw(&mut self, start: usize, len: usize) {
        if len == 0 {
            return;
        }
        self.draws.push(start..start + len);
    }

    fn draw_array<const N: usize>(&mut self, node_id: usize, record_event: bool) -> [u8; N] {
        let bytes = self.draw_vec(node_id, N, record_event);
        bytes.try_into().expect("fixed draw length mismatch")
    }

    fn draw_vec(&mut self, node_id: usize, len: usize, record_event: bool) -> Vec<u8> {
        self.draw_vec_from(node_id, len, record_event, ReplaySource::NodeDraw)
    }

    fn draw_vec_from(
        &mut self,
        node_id: usize,
        len: usize,
        record_event: bool,
        replay_source: ReplaySource<'_>,
    ) -> Vec<u8> {
        self.assert_node_available(node_id);
        let start = self.cursor;
        let mut bytes = Vec::with_capacity(len);
        for offset in 0..len {
            let byte = self
                .replay_byte(node_id, offset, &replay_source)
                .unwrap_or_else(|| self.fallback_byte());
            self.cursor = self.cursor.saturating_add(1);
            self.bytes_consumed = self.bytes_consumed.saturating_add(1);
            self.prefix.push(byte);
            bytes.push(byte);
        }
        self.record_draw(start, len);
        if record_event && !bytes.is_empty() {
            self.nodes[node_id]
                .events
                .push(RuntimeEvent::Draw(bytes.clone()));
        }
        bytes
    }

    fn replay_byte(
        &mut self,
        node_id: usize,
        offset: usize,
        replay_source: &ReplaySource<'_>,
    ) -> Option<u8> {
        match replay_source {
            ReplaySource::NodeDraw => self.next_flat_replay_byte().or_else(|| {
                if self.flat_replay.is_some() {
                    None
                } else {
                    self.next_tree_draw_byte(node_id)
                }
            }),
            ReplaySource::RangeLength(bytes) => bytes.get(offset).copied(),
            ReplaySource::FlatOnly => self.next_flat_replay_byte(),
        }
    }

    fn next_flat_replay_byte(&self) -> Option<u8> {
        self.flat_replay
            .as_ref()
            .and_then(|prefix| prefix.get(self.cursor))
            .copied()
    }

    fn fallback_byte(&mut self) -> u8 {
        let mut byte = [0];
        self.fallback.fill_bytes(&mut byte);
        byte[0]
    }

    fn next_tree_draw_byte(&mut self, node_id: usize) -> Option<u8> {
        loop {
            let event = {
                let replay = &self.nodes.get(node_id)?.replay;
                let node = replay.node.as_ref()?;
                node.events.get(replay.event_index).cloned()?
            };
            match event {
                TraceEvent::Draw { bytes } => {
                    let replay = &mut self.nodes[node_id].replay;
                    if replay.draw_offset < bytes.len() {
                        let byte = bytes[replay.draw_offset];
                        replay.draw_offset += 1;
                        if replay.draw_offset >= bytes.len() {
                            replay.event_index += 1;
                            replay.draw_offset = 0;
                        }
                        return Some(byte);
                    }
                    replay.event_index += 1;
                    replay.draw_offset = 0;
                }
                TraceEvent::Range { .. } => return None,
            }
        }
    }

    fn take_replay_range(&mut self, node_id: usize) -> Option<(Vec<u8>, Vec<TraceNode>)> {
        if self.flat_replay.is_some() {
            return None;
        }
        loop {
            let event = {
                let replay = &self.nodes.get(node_id)?.replay;
                if replay.draw_offset != 0 {
                    return None;
                }
                let node = replay.node.as_ref()?;
                node.events.get(replay.event_index).cloned()?
            };
            match event {
                TraceEvent::Draw { bytes } if bytes.is_empty() => {
                    self.nodes[node_id].replay.event_index += 1;
                }
                TraceEvent::Draw { .. } => return None,
                TraceEvent::Range { length, children } => {
                    let replay = &mut self.nodes[node_id].replay;
                    replay.event_index += 1;
                    replay.draw_offset = 0;
                    return Some((length, children));
                }
            }
        }
    }

    fn assert_node_available(&self, node_id: usize) {
        if self.finished {
            panic!("semantic rng already finished");
        }
        let node = self.nodes.get(node_id).expect("semantic rng node missing");
        if node.end.is_some() {
            panic!("semantic rng node is no longer active");
        }
        if node.active_child.is_some() {
            panic!("cannot use a SemanticRng while one of its range children is active");
        }
        if let Some(parent) = node.parent
            && self.nodes[parent].active_child != Some(node_id)
        {
            panic!("range child is no longer the active child");
        }
    }

    fn close_node(&mut self, node_id: usize) {
        if self
            .nodes
            .get(node_id)
            .is_none_or(|node| node.end.is_some())
        {
            return;
        }
        self.nodes[node_id].end = Some(self.cursor);
        self.release_closed_ancestors(node_id);
    }

    fn release_closed_ancestors(&mut self, mut node_id: usize) {
        loop {
            let complete =
                self.nodes[node_id].end.is_some() && self.nodes[node_id].active_child.is_none();
            if !complete {
                return;
            }
            let Some(parent) = self.nodes[node_id].parent else {
                return;
            };
            if self.nodes[parent].active_child != Some(node_id) {
                return;
            }
            self.nodes[parent].active_child = None;
            node_id = parent;
        }
    }

    fn build_trace_node(&self, node_id: usize) -> TraceNode {
        let node = self.nodes.get(node_id).expect("semantic rng node missing");
        let mut events = Vec::with_capacity(node.events.len());
        for event in &node.events {
            match event {
                RuntimeEvent::Draw(bytes) => {
                    events.push(TraceEvent::Draw {
                        bytes: bytes.clone(),
                    });
                }
                RuntimeEvent::Range { length, range_id } => {
                    let range = self
                        .ranges
                        .get(*range_id)
                        .expect("semantic rng range missing");
                    events.push(TraceEvent::Range {
                        length: length.clone(),
                        children: range
                            .item_nodes
                            .iter()
                            .map(|node_id| self.build_trace_node(*node_id))
                            .collect(),
                    });
                }
            }
        }
        TraceNode { events }
    }
}

fn normalize_range(range: impl RangeBounds<usize>) -> (usize, usize) {
    let start = match range.start_bound() {
        Bound::Included(value) => *value,
        Bound::Excluded(value) => value.saturating_add(1),
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(value) => value.saturating_add(1),
        Bound::Excluded(value) => *value,
        Bound::Unbounded => panic!("range requires a bounded upper limit"),
    };
    assert!(start < end, "range requires a non-empty range");
    (start, end - start)
}

fn to_word_bytes(bytes: &[u8]) -> [u8; 4] {
    let mut word = [0; 4];
    let len = bytes.len().min(word.len());
    word[..len].copy_from_slice(&bytes[..len]);
    word
}

fn lock_runtime(runtime: &Mutex<SemanticRuntime>) -> MutexGuard<'_, SemanticRuntime> {
    runtime
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn flatten_node(node: &TraceNode, prefix: &mut Vec<u8>) {
    for event in &node.events {
        match event {
            TraceEvent::Draw { bytes } => prefix.extend_from_slice(bytes),
            TraceEvent::Range { length, children } => {
                prefix.extend_from_slice(length);
                for child in children {
                    flatten_node(child, prefix);
                }
            }
        }
    }
}

fn collect_sequence_spans(node: &TraceNode, cursor: &mut usize, sequences: &mut Vec<SequenceSpan>) {
    for event in &node.events {
        match event {
            TraceEvent::Draw { bytes } => {
                *cursor = (*cursor).saturating_add(bytes.len());
            }
            TraceEvent::Range { length, children } => {
                let length_start = *cursor;
                *cursor = (*cursor).saturating_add(length.len());
                let mut items = Vec::new();
                for child in children {
                    let start = *cursor;
                    collect_sequence_spans(child, cursor, sequences);
                    if start < *cursor {
                        items.push(start..*cursor);
                    }
                }
                if !length.is_empty() && !items.is_empty() {
                    sequences.push(SequenceSpan {
                        length_start,
                        length_len: length.len(),
                        items,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SemanticRng, Trace};
    use rand::{Rng, RngCore, SeedableRng, rngs::SmallRng};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[test]
    fn fork_trace_replays_consumed_rng_path() {
        let (trace, original) = {
            let mut rng = SemanticRng::new(Trace::empty(99));
            let bytes = [rng.random::<u8>(), rng.random::<u8>(), rng.random::<u8>()];
            (rng.fork_trace(), bytes)
        };

        let mut replay = SemanticRng::new(trace);
        let replayed = [
            replay.random::<u8>(),
            replay.random::<u8>(),
            replay.random::<u8>(),
        ];

        assert_eq!(replayed, original);
    }

    #[test]
    fn fork_trace_replays_consumed_rng_paths_longer_than_prefix_limit() {
        let len = 5000;
        let (trace, original) = {
            let mut rng = SemanticRng::new(Trace::empty(99));
            let mut bytes = vec![0; len];
            rng.fill_bytes(&mut bytes);
            (rng.fork_trace(), bytes)
        };

        let replayed = {
            let mut rng = SemanticRng::new(trace);
            let mut bytes = vec![0; len];
            rng.fill_bytes(&mut bytes);
            bytes
        };

        assert_eq!(replayed, original);
    }

    #[test]
    fn flat_replay_past_trace_falls_back_to_rng_not_zero() {
        let seed = 7;
        let trace = Trace::from_flat_prefix(seed, vec![42]);
        let mut rng = SemanticRng::new(trace);
        let mut bytes = [0; 2];
        rng.fill_bytes(&mut bytes);

        let mut fallback = SmallRng::seed_from_u64(seed);
        let mut expected_tail = [0];
        fallback.fill_bytes(&mut expected_tail);

        assert_eq!(bytes, [42, expected_tail[0]]);
    }

    #[test]
    fn tree_trace_replays_range_children() {
        let trace = Trace::from_range(11, 2_u32.to_le_bytes(), vec![vec![10], vec![20]]);
        let mut rng = SemanticRng::new(trace);

        assert_eq!(sample_byte_sequence(&mut rng), [10, 20]);
    }

    #[test]
    fn missing_tree_range_children_fall_back_to_rng() {
        let seed = 12;
        let trace = Trace::from_range(seed, 3_u32.to_le_bytes(), vec![vec![10]]);
        let mut rng = SemanticRng::new(trace);
        let items = sample_byte_sequence(&mut rng);

        let mut fallback = SmallRng::seed_from_u64(seed);
        let mut expected_tail = [0; 2];
        fallback.fill_bytes(&mut expected_tail[0..1]);
        fallback.fill_bytes(&mut expected_tail[1..2]);

        assert_eq!(items, [10, expected_tail[0], expected_tail[1]]);
    }

    #[test]
    fn missing_tree_range_children_do_not_consume_parent_tail() {
        let seed = 13;
        let trace =
            Trace::from_range_then_draw(seed, 3_u32.to_le_bytes(), vec![vec![10]], vec![99]);
        let mut rng = SemanticRng::new(trace);
        let items = sample_byte_sequence(&mut rng);
        let tail: u8 = rng.random();

        let mut fallback = SmallRng::seed_from_u64(seed);
        let mut expected_tail = [0; 2];
        fallback.fill_bytes(&mut expected_tail[0..1]);
        fallback.fill_bytes(&mut expected_tail[1..2]);

        assert_eq!(items, [10, expected_tail[0], expected_tail[1]]);
        assert_eq!(tail, 99);
    }

    #[test]
    fn range_yields_rng_like_children() {
        let mut rng = SemanticRng::new(Trace::empty(0));
        let values = {
            let mut items = rng.range(1..=3);
            let mut values = Vec::new();
            while let Some(mut item) = items.next() {
                values.push((item.random_range(0..4), item.random::<u8>()));
            }
            values
        };

        assert!((1..=3).contains(&values.len()));
    }

    #[test]
    fn range_items_are_independent_rng_nodes() {
        let mut rng = SemanticRng::new(Trace::empty(0));

        let root_value: u8 = rng.random();
        let child_value = {
            let mut items = rng.range(1..=1);
            let mut item = items.next().expect("range item");
            item.random::<u8>()
        };

        assert_ne!(root_value, child_value);
    }

    #[test]
    fn parent_draw_while_range_child_is_active_panics() {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut rng = SemanticRng::new(Trace::empty(0));
            let _item = {
                let mut items = rng.range(1..=1);
                items.next().expect("range item")
            };

            let _: u8 = rng.random();
        }));

        assert!(result.is_err());
    }

    #[test]
    fn next_range_sibling_while_previous_child_is_active_panics() {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut rng = SemanticRng::new(Trace::empty(0));
            let mut items = rng.range(2..=2);
            let _first = items.next().expect("first range item");
            let _second = items.next().expect("second range item");
        }));

        assert!(result.is_err());
    }

    #[test]
    fn finish_returns_flat_prefix_draws_and_sequence_spans() {
        let mut prefix = 2_u32.to_le_bytes().to_vec();
        prefix.extend([10, 20]);
        let mut rng = SemanticRng::new(Trace::from_flat_prefix(0, prefix));
        assert_eq!(sample_byte_sequence(&mut rng), [10, 20]);

        let snapshot = rng.finish().expect("finish semantic rng");

        assert_eq!(snapshot.prefix.len(), 6);
        assert_eq!(snapshot.draws, [0..4, 4..5, 5..6]);
        assert_eq!(snapshot.sequences.len(), 1);
        assert_eq!(snapshot.sequences[0].length_start, 0);
        assert_eq!(snapshot.sequences[0].length_len, 4);
        assert_eq!(snapshot.sequences[0].items, [4..5, 5..6]);
    }

    fn sample_byte_sequence(rng: &mut SemanticRng) -> Vec<u8> {
        rng.range(0..8)
            .map(|mut item| {
                let mut byte = [0];
                item.fill_bytes(&mut byte);
                byte[0]
            })
            .collect()
    }
}
