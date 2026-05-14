//! Fuzz the Dioxus VirtualDom's **keyed list** diff path by streaming
//! incremental mutations into a tracking tree and asserting it stays
//! structurally equal to a fresh rebuild over the same model state.
//!
//! The component is intentionally narrow: a single keyed list of `Row`
//! components, each of which contains a nested keyed list. Every fuzz op
//! goes through `diff_keyed_children` somewhere.
//!
//! Run with `cargo run --release --example dioxus_vdom --features "dioxus rayon"`.
//!
//! Coverage-guided:
//!
//! ```sh
//! RUSTFLAGS="-Cinstrument-coverage" \
//!   FUZZ_COVERAGE=1 FUZZ_SEEDS=128 FUZZ_STEPS=128 FUZZ_COVERAGE_CASES=64 \
//!   cargo run --example dioxus_vdom --features "dioxus rayon llvm-coverage"
//! ```
#![allow(non_snake_case)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;

use dioxus::prelude::*;
use dioxus_core::{
    AttributeValue, ElementId, Mutations, ScopeId, Template, TemplateAttribute, TemplateNode,
    VirtualDom, WriteMutations,
};
use iterator_fuzz::{
    CaseIteratorExt, Fuzzer, Step, llvm_coverage::LlvmCoverage, parallel::ParCaseIteratorExt,
    replay_ops,
};
use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};
use rayon::iter::ParallelIterator;

// ---------- Model ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
struct Item {
    key: u32,
    label: u8,
    /// Toggles whether the leading and trailing `Indicator` sub-components
    /// render, which switches the Row from a single-root `<li>` to a
    /// multi-root structure with conditional empty-fragment siblings.
    leading: bool,
    trailing: bool,
    tags: Vec<Tag>,
}

#[derive(Clone, Debug, PartialEq)]
struct Tag {
    key: u32,
    val: u8,
}

#[derive(Clone, Debug)]
struct Model {
    items: Vec<Item>,
    next_item_key: u32,
    next_tag_key: u32,
}

impl Model {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            next_item_key: 0,
            next_tag_key: 0,
        }
    }

    fn fresh_item_key(&mut self) -> u32 {
        let k = self.next_item_key;
        self.next_item_key += 1;
        k
    }

    fn fresh_tag_key(&mut self) -> u32 {
        let k = self.next_tag_key;
        self.next_tag_key += 1;
        k
    }
}

thread_local! {
    static MODEL: RefCell<Model> = RefCell::new(Model::new());
}

fn read_model() -> Model {
    MODEL.with(|m| m.borrow().clone())
}

fn with_model<R>(f: impl FnOnce(&mut Model) -> R) -> R {
    MODEL.with(|m| f(&mut m.borrow_mut()))
}

// ---------- Component -----------------------------------------------------------------------
//
// Single keyed list at the app root, each Row containing a nested keyed list.

fn App() -> Element {
    let m = read_model();
    rsx! {
        ul {
            for item in m.items.iter() {
                Row { key: "{item.key}", item: item.clone() }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct RowProps {
    item: Item,
}

fn Row(props: RowProps) -> Element {
    let item = &props.item;
    // The whole template flips between two shapes based on label parity. This
    // forces dioxus to take the `template != template` branch in `diff_node`
    // and call `replace()` on a row that's also being keyed-reordered.
    if item.label % 2 == 0 {
        rsx! {
            if item.leading {
                Indicator {}
            }
            li {
                "even-{item.label}"
                ul {
                    for tag in item.tags.iter() {
                        li { key: "{tag.key}", "t{tag.val}" }
                    }
                }
            }
            if item.trailing {
                Indicator {}
            }
        }
    } else {
        rsx! {
            if item.leading {
                Indicator {}
            }
            div {
                "odd-{item.label}"
                section {
                    for tag in item.tags.iter() {
                        span { key: "{tag.key}", "s{tag.val}" }
                    }
                }
            }
            if item.trailing {
                Indicator {}
            }
        }
    }
}

#[component]
fn Indicator() -> Element {
    rsx! { div {} }
}

// ---------- Op ------------------------------------------------------------------------------

/// A single primitive model mutation. The fuzzer's "step" applies a small
/// random *batch* of these per render (see `Op`), so the framework naturally
/// explores multi-mutation-per-render transitions without me hand-picking
/// which combinations matter.
#[derive(Clone, Copy, Debug)]
enum PrimOp {
    PushItem(u8),
    PopItem,
    InsertItem(u8, u8),
    RemoveItem(u8),
    SetItemLabel(u8, u8),
    ToggleLeading(u8),
    ToggleTrailing(u8),
    SwapItems(u8, u8),
    MoveItem(u8, u8),
    ReverseItems,
    RotateLeft(u8),
    ClearItems,
    PushItemTag(u8, u8),
    PopItemTag(u8),
    InsertItemTag(u8, u8, u8),
    RemoveItemTag(u8, u8),
    SetItemTagVal(u8, u8, u8),
    SwapItemTags(u8, u8, u8),
    MoveItemTag(u8, u8, u8),
    ReverseItemTags(u8),
    RotateItemTagsLeft(u8, u8),
    ClearItemTags(u8),
}

const MAX_ITEMS: u8 = 24;
const MAX_TAGS: u8 = 12;
const LABEL_RANGE: u8 = 32;

impl Distribution<PrimOp> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> PrimOp {
        let item = |rng: &mut R| rng.random_range(0..MAX_ITEMS);
        let tag = |rng: &mut R| rng.random_range(0..MAX_TAGS);
        let label = |rng: &mut R| rng.random_range(0..LABEL_RANGE);
        match rng.random_range(0..40) {
            // outer keyed list — heavy on reorders
            0..=3 => PrimOp::PushItem(label(rng)),
            4..=5 => PrimOp::PopItem,
            6..=8 => PrimOp::InsertItem(item(rng), label(rng)),
            9..=10 => PrimOp::RemoveItem(item(rng)),
            11 => PrimOp::SetItemLabel(item(rng), label(rng)),
            12 => PrimOp::ToggleLeading(item(rng)),
            13 => PrimOp::ToggleTrailing(item(rng)),
            14..=17 => PrimOp::SwapItems(item(rng), item(rng)),
            18..=21 => PrimOp::MoveItem(item(rng), item(rng)),
            22..=23 => PrimOp::ReverseItems,
            24..=25 => PrimOp::RotateLeft(item(rng)),
            26 => PrimOp::ClearItems,
            // nested keyed list inside each Row
            27..=29 => PrimOp::PushItemTag(item(rng), label(rng)),
            30 => PrimOp::PopItemTag(item(rng)),
            31 => PrimOp::InsertItemTag(item(rng), tag(rng), label(rng)),
            32 => PrimOp::RemoveItemTag(item(rng), tag(rng)),
            33 => PrimOp::SetItemTagVal(item(rng), tag(rng), label(rng)),
            34..=36 => PrimOp::SwapItemTags(item(rng), tag(rng), tag(rng)),
            37 => PrimOp::MoveItemTag(item(rng), tag(rng), tag(rng)),
            38 => PrimOp::ReverseItemTags(item(rng)),
            _ => match rng.random_range(0..2) {
                0 => PrimOp::RotateItemTagsLeft(item(rng), tag(rng)),
                _ => PrimOp::ClearItemTags(item(rng)),
            },
        }
    }
}

/// A batch of up to four primitive mutations applied together before a single
/// render. Random batching lets the fuzzer hit diffs that have to reconcile
/// multiple state changes in the same pass (e.g. reorder + delete, reverse +
/// insert) without me handpicking those combinations.
#[derive(Clone, Copy, Debug)]
struct Op {
    slots: [Option<PrimOp>; 4],
}

impl Distribution<Op> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Op {
        let slot = |rng: &mut R| -> Option<PrimOp> {
            if rng.random_range(0..10) < 7 {
                Some(rng.sample(StandardUniform))
            } else {
                None
            }
        };
        Op {
            slots: [
                Some(rng.sample(StandardUniform)),
                slot(rng),
                slot(rng),
                slot(rng),
            ],
        }
    }
}

fn apply_prim(m: &mut Model, op: PrimOp) {
    match op {
        PrimOp::PushItem(label) => {
            let key = m.fresh_item_key();
            m.items.push(Item {
                key,
                label,
                leading: false,
                trailing: false,
                tags: Vec::new(),
            });
        }
        PrimOp::PopItem => {
            m.items.pop();
        }
        PrimOp::InsertItem(idx, label) => {
            let len = m.items.len();
            let i = (idx as usize).min(len);
            let key = m.fresh_item_key();
            m.items.insert(
                i,
                Item {
                    key,
                    label,
                    leading: false,
                    trailing: false,
                    tags: Vec::new(),
                },
            );
        }
        PrimOp::RemoveItem(idx) => {
            let i = idx as usize;
            if i < m.items.len() {
                m.items.remove(i);
            }
        }
        PrimOp::SetItemLabel(idx, label) => {
            let i = idx as usize;
            if i < m.items.len() {
                m.items[i].label = label;
            }
        }
        PrimOp::ToggleLeading(idx) => {
            let i = idx as usize;
            if i < m.items.len() {
                m.items[i].leading = !m.items[i].leading;
            }
        }
        PrimOp::ToggleTrailing(idx) => {
            let i = idx as usize;
            if i < m.items.len() {
                m.items[i].trailing = !m.items[i].trailing;
            }
        }
        PrimOp::SwapItems(a, b) => {
            let (a, b) = (a as usize, b as usize);
            let len = m.items.len();
            if a < len && b < len && a != b {
                m.items.swap(a, b);
            }
        }
        PrimOp::MoveItem(from, to) => {
            let len = m.items.len();
            let (from, to) = (from as usize, to as usize);
            if from < len && to < len && from != to {
                let item = m.items.remove(from);
                m.items.insert(to, item);
            }
        }
        PrimOp::ReverseItems => m.items.reverse(),
        PrimOp::RotateLeft(k) => {
            let len = m.items.len();
            if len > 1 {
                let k = (k as usize) % len;
                m.items.rotate_left(k);
            }
        }
        PrimOp::ClearItems => m.items.clear(),
        PrimOp::PushItemTag(item_idx, val) => {
            let i = item_idx as usize;
            if i < m.items.len() {
                let key = m.fresh_tag_key();
                m.items[i].tags.push(Tag { key, val });
            }
        }
        PrimOp::PopItemTag(item_idx) => {
            let i = item_idx as usize;
            if i < m.items.len() {
                m.items[i].tags.pop();
            }
        }
        PrimOp::InsertItemTag(item_idx, idx, val) => {
            let i = item_idx as usize;
            if i < m.items.len() {
                let pos = (idx as usize).min(m.items[i].tags.len());
                let key = m.fresh_tag_key();
                m.items[i].tags.insert(pos, Tag { key, val });
            }
        }
        PrimOp::RemoveItemTag(item_idx, idx) => {
            let i = item_idx as usize;
            if i < m.items.len() {
                let tags = &mut m.items[i].tags;
                let pos = idx as usize;
                if pos < tags.len() {
                    tags.remove(pos);
                }
            }
        }
        PrimOp::SetItemTagVal(item_idx, idx, val) => {
            let i = item_idx as usize;
            if i < m.items.len() {
                let tags = &mut m.items[i].tags;
                let pos = idx as usize;
                if pos < tags.len() {
                    tags[pos].val = val;
                }
            }
        }
        PrimOp::SwapItemTags(item_idx, a, b) => {
            let i = item_idx as usize;
            let (a, b) = (a as usize, b as usize);
            if i < m.items.len() {
                let tags = &mut m.items[i].tags;
                let len = tags.len();
                if a < len && b < len && a != b {
                    tags.swap(a, b);
                }
            }
        }
        PrimOp::MoveItemTag(item_idx, from, to) => {
            let i = item_idx as usize;
            let (from, to) = (from as usize, to as usize);
            if i < m.items.len() {
                let tags = &mut m.items[i].tags;
                let len = tags.len();
                if from < len && to < len && from != to {
                    let tag = tags.remove(from);
                    tags.insert(to, tag);
                }
            }
        }
        PrimOp::ReverseItemTags(item_idx) => {
            let i = item_idx as usize;
            if i < m.items.len() {
                m.items[i].tags.reverse();
            }
        }
        PrimOp::RotateItemTagsLeft(item_idx, k) => {
            let i = item_idx as usize;
            if i < m.items.len() {
                let tags = &mut m.items[i].tags;
                let len = tags.len();
                if len > 1 {
                    let k = (k as usize) % len;
                    tags.rotate_left(k);
                }
            }
        }
        PrimOp::ClearItemTags(item_idx) => {
            let i = item_idx as usize;
            if i < m.items.len() {
                m.items[i].tags.clear();
            }
        }
    }
}

fn apply_to_model(op: Op) {
    with_model(|m| {
        for slot in op.slots.iter().flatten() {
            apply_prim(m, *slot);
        }
    });
}

// ---------- TrackingTree --------------------------------------------------------------------
//
// Implements `WriteMutations` by maintaining a node arena, an element id -> arena index map,
// the mutation stack, and a list of root children (the kids of the implicit `ElementId(0)`).

#[derive(Clone, Debug)]
enum NodeKind {
    Element {
        tag: String,
        namespace: Option<String>,
    },
    Text(String),
    Placeholder,
}

#[derive(Clone, Debug)]
struct TrackNode {
    kind: NodeKind,
    attrs: BTreeMap<(String, Option<String>), String>,
    children: Vec<usize>,
    parent: Option<usize>,
}

struct TrackingTree {
    arena: Vec<Option<TrackNode>>,
    id_map: BTreeMap<usize, usize>,
    stack: Vec<usize>,
    root_children: Vec<usize>,
}

impl TrackingTree {
    fn new() -> Self {
        Self {
            arena: Vec::new(),
            id_map: BTreeMap::new(),
            stack: Vec::new(),
            root_children: Vec::new(),
        }
    }

    fn alloc(&mut self, kind: NodeKind) -> usize {
        let idx = self.arena.len();
        self.arena.push(Some(TrackNode {
            kind,
            attrs: BTreeMap::new(),
            children: Vec::new(),
            parent: None,
        }));
        idx
    }

    fn node(&self, idx: usize) -> &TrackNode {
        self.arena[idx].as_ref().expect("node still live")
    }

    fn node_mut(&mut self, idx: usize) -> &mut TrackNode {
        self.arena[idx].as_mut().expect("node still live")
    }

    fn lookup(&self, id: ElementId) -> usize {
        *self
            .id_map
            .get(&id.0)
            .unwrap_or_else(|| panic!("renderer asked for unknown ElementId({})", id.0))
    }

    fn clone_template(&mut self, tn: &TemplateNode) -> usize {
        match tn {
            TemplateNode::Element {
                tag,
                namespace,
                attrs,
                children,
            } => {
                let me = self.alloc(NodeKind::Element {
                    tag: (*tag).to_string(),
                    namespace: namespace.map(|n| n.to_string()),
                });
                {
                    let n = self.node_mut(me);
                    for attr in *attrs {
                        if let TemplateAttribute::Static {
                            name,
                            value,
                            namespace,
                        } = attr
                        {
                            n.attrs.insert(
                                ((*name).to_string(), namespace.map(|s| s.to_string())),
                                (*value).to_string(),
                            );
                        }
                    }
                }
                let mut kids = Vec::with_capacity(children.len());
                for child in *children {
                    let c = self.clone_template(child);
                    self.node_mut(c).parent = Some(me);
                    kids.push(c);
                }
                self.node_mut(me).children = kids;
                me
            }
            TemplateNode::Text { text } => self.alloc(NodeKind::Text((*text).to_string())),
            TemplateNode::Dynamic { .. } => self.alloc(NodeKind::Placeholder),
        }
    }

    fn walk_path(&self, start: usize, path: &[u8]) -> usize {
        let mut cur = start;
        for &p in path {
            cur = self.node(cur).children[p as usize];
        }
        cur
    }

    fn pop_m(&mut self, m: usize) -> Vec<usize> {
        let split = self.stack.len() - m;
        self.stack.split_off(split)
    }

    fn position_in_parent(&self, idx: usize) -> (Option<usize>, usize) {
        let parent = self.node(idx).parent;
        let pos = match parent {
            None => self
                .root_children
                .iter()
                .position(|&i| i == idx)
                .expect("detached node had no slot in root children"),
            Some(p) => self
                .node(p)
                .children
                .iter()
                .position(|&i| i == idx)
                .expect("node missing from its parent's child list"),
        };
        (parent, pos)
    }

    fn detach_from_parent(&mut self, idx: usize) -> (Option<usize>, usize) {
        let (parent, pos) = self.position_in_parent(idx);
        match parent {
            None => {
                self.root_children.remove(pos);
            }
            Some(p) => {
                self.node_mut(p).children.remove(pos);
            }
        }
        (parent, pos)
    }

    /// DOM `insertBefore` and `appendChild` auto-detach nodes that are already
    /// attached. Dioxus relies on that: a keyed reorder emits PushRoot+InsertBefore
    /// to *move* an existing node, with no explicit Remove.
    fn unhook(&mut self, idx: usize) {
        if self.node(idx).parent.is_some() {
            self.detach_from_parent(idx);
        } else if let Some(pos) = self.root_children.iter().position(|&i| i == idx) {
            self.root_children.remove(pos);
        }
    }

    fn unhook_all(&mut self, children: &[usize]) {
        for &c in children {
            self.unhook(c);
        }
    }

    fn insert_detached(&mut self, parent: Option<usize>, pos: usize, children: Vec<usize>) {
        for &c in &children {
            self.node_mut(c).parent = parent;
        }
        match parent {
            None => {
                for (i, c) in children.into_iter().enumerate() {
                    self.root_children.insert(pos + i, c);
                }
            }
            Some(p) => {
                let parent_node = self.node_mut(p);
                for (i, c) in children.into_iter().enumerate() {
                    parent_node.children.insert(pos + i, c);
                }
            }
        }
    }

    fn append_detached(&mut self, parent: Option<usize>, children: Vec<usize>) {
        for &c in &children {
            self.node_mut(c).parent = parent;
        }
        match parent {
            None => self.root_children.extend(children),
            Some(p) => self.node_mut(p).children.extend(children),
        }
    }

    fn drop_subtree(&mut self, idx: usize) {
        let n = self.arena[idx]
            .take()
            .expect("drop_subtree on already-dropped node");
        let dead_ids: Vec<usize> = self
            .id_map
            .iter()
            .filter_map(|(&eid, &aidx)| (aidx == idx).then_some(eid))
            .collect();
        for eid in dead_ids {
            self.id_map.remove(&eid);
        }
        for c in n.children {
            self.drop_subtree(c);
        }
    }
}

// ---------- Canonical structural snapshot --------------------------------------------------

#[derive(Clone, PartialEq, Eq, Debug)]
enum Canonical {
    Element {
        tag: String,
        namespace: Option<String>,
        attrs: Vec<(String, Option<String>, String)>,
        children: Vec<Canonical>,
    },
    Text(String),
    Placeholder,
}

impl TrackingTree {
    fn canonical(&self) -> Vec<Canonical> {
        self.root_children
            .iter()
            .map(|&i| self.canonical_node(i))
            .collect()
    }

    fn canonical_node(&self, idx: usize) -> Canonical {
        let n = self.node(idx);
        match &n.kind {
            NodeKind::Element { tag, namespace } => Canonical::Element {
                tag: tag.clone(),
                namespace: namespace.clone(),
                attrs: n
                    .attrs
                    .iter()
                    .map(|((k, ns), v)| (k.clone(), ns.clone(), v.clone()))
                    .collect(),
                children: n.children.iter().map(|&c| self.canonical_node(c)).collect(),
            },
            NodeKind::Text(t) => Canonical::Text(t.clone()),
            NodeKind::Placeholder => Canonical::Placeholder,
        }
    }
}

// ---------- WriteMutations -----------------------------------------------------------------

fn attr_to_string(value: &AttributeValue) -> Option<String> {
    match value {
        AttributeValue::Text(s) => Some(s.clone()),
        AttributeValue::Bool(b) => Some(b.to_string()),
        AttributeValue::Float(f) => Some(f.to_string()),
        AttributeValue::Int(i) => Some(i.to_string()),
        AttributeValue::None => None,
        _ => Some("<opaque>".into()),
    }
}

impl WriteMutations for TrackingTree {
    fn append_children(&mut self, id: ElementId, m: usize) {
        let kids = self.pop_m(m);
        self.unhook_all(&kids);
        let parent = (id.0 != 0).then(|| self.lookup(id));
        self.append_detached(parent, kids);
    }

    fn assign_node_id(&mut self, path: &'static [u8], id: ElementId) {
        let top = *self.stack.last().expect("assign_node_id with empty stack");
        let target = self.walk_path(top, path);
        self.id_map.insert(id.0, target);
    }

    fn create_text_node(&mut self, value: &str, id: ElementId) {
        let idx = self.alloc(NodeKind::Text(value.to_string()));
        self.id_map.insert(id.0, idx);
        self.stack.push(idx);
    }

    fn load_template(&mut self, template: Template, index: usize, id: ElementId) {
        let root = &template.roots()[index];
        let idx = self.clone_template(root);
        self.id_map.insert(id.0, idx);
        self.stack.push(idx);
    }

    fn replace_node_with(&mut self, id: ElementId, m: usize) {
        let new_kids = self.pop_m(m);
        self.unhook_all(&new_kids);
        let target = self.lookup(id);
        let (parent, pos) = self.detach_from_parent(target);
        self.drop_subtree(target);
        self.insert_detached(parent, pos, new_kids);
    }

    fn insert_children_at_path(&mut self, path: &'static [u8], m: usize) {
        let new_kids = self.pop_m(m);
        let top = *self
            .stack
            .last()
            .expect("insert_children_at_path with empty stack");
        let target = self.walk_path(top, path);
        self.unhook_all(&new_kids);
        let (parent, pos) = self.detach_from_parent(target);
        self.drop_subtree(target);
        self.insert_detached(parent, pos, new_kids);
    }

    fn insert_nodes_after(&mut self, id: ElementId, m: usize) {
        let new_kids = self.pop_m(m);
        self.unhook_all(&new_kids);
        let anchor = self.lookup(id);
        let (parent, pos) = self.position_in_parent(anchor);
        self.insert_detached(parent, pos + 1, new_kids);
    }

    fn insert_nodes_before(&mut self, id: ElementId, m: usize) {
        let new_kids = self.pop_m(m);
        self.unhook_all(&new_kids);
        let anchor = self.lookup(id);
        let (parent, pos) = self.position_in_parent(anchor);
        self.insert_detached(parent, pos, new_kids);
    }

    fn set_attribute(
        &mut self,
        name: &'static str,
        ns: Option<&'static str>,
        value: &AttributeValue,
        id: ElementId,
    ) {
        let idx = self.lookup(id);
        let key = (name.to_string(), ns.map(|s| s.to_string()));
        match attr_to_string(value) {
            Some(v) => {
                self.node_mut(idx).attrs.insert(key, v);
            }
            None => {
                self.node_mut(idx).attrs.remove(&key);
            }
        }
    }

    fn set_node_text(&mut self, value: &str, id: ElementId) {
        let idx = self.lookup(id);
        self.node_mut(idx).kind = NodeKind::Text(value.to_string());
    }

    fn create_event_listener(&mut self, _name: &'static str, _id: ElementId) {}

    fn remove_event_listener(&mut self, _name: &'static str, _id: ElementId) {}

    fn remove_node(&mut self, id: ElementId) {
        let idx = self.lookup(id);
        let _ = self.detach_from_parent(idx);
        self.drop_subtree(idx);
    }

    fn push_root(&mut self, id: ElementId) {
        if id.0 == 0 {
            panic!("dioxus emitted PushRoot {{ id: ElementId(0) }} (document root sentinel)");
        }
        if id.0 == usize::MAX {
            panic!("dioxus emitted PushRoot {{ id: ElementId(usize::MAX) }} (unmounted sentinel)");
        }
        let idx = self.lookup(id);
        self.stack.push(idx);
    }

    fn pop_root(&mut self) {
        self.stack.pop().expect("pop_root with empty stack");
    }
}

// ---------- Harness -------------------------------------------------------------------------

struct Harness {
    vdom: VirtualDom,
    incremental: TrackingTree,
}

impl Harness {
    fn fresh() -> Self {
        with_model(|m| *m = Model::new());
        let mut vdom = VirtualDom::new(App);
        let mut incremental = TrackingTree::new();
        vdom.rebuild(&mut incremental);
        Self { vdom, incremental }
    }
}

fn fresh_render() -> Vec<Canonical> {
    let mut vdom = VirtualDom::new(App);
    let mut tree = TrackingTree::new();
    vdom.rebuild(&mut tree);
    tree.canonical()
}

fn apply_step(state: &mut Harness, step: Step<'_, Op>) -> Result<(), String> {
    let op = *step.op;
    apply_to_model(op);
    state.vdom.mark_dirty(ScopeId::APP);

    let render_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.vdom.render_immediate(&mut state.incremental);
        if !state.incremental.stack.is_empty() {
            panic!(
                "render_immediate left mutation stack non-empty (len={})",
                state.incremental.stack.len()
            );
        }
        state.incremental.canonical()
    }));

    let incremental = match render_result {
        Ok(t) => t,
        Err(payload) => {
            return Err(format!(
                "step {} ({op:?}): panic in incremental render: {}",
                step.index,
                panic_message(&payload),
            ));
        }
    };

    // A re-render with no model change must emit zero mutations.
    state.vdom.mark_dirty(ScopeId::APP);
    let mut idempotent = Mutations::default();
    let idempotent_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.vdom.render_immediate(&mut idempotent);
    }));
    if let Err(payload) = idempotent_result {
        return Err(format!(
            "step {} ({op:?}): panic in no-change re-render: {}",
            step.index,
            panic_message(&payload),
        ));
    }
    if !idempotent.edits.is_empty() {
        return Err(format!(
            "step {} ({op:?}): re-render with no state change emitted {} mutation(s):\n  {:#?}",
            step.index,
            idempotent.edits.len(),
            idempotent.edits,
        ));
    }

    let fresh_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(fresh_render));
    let fresh = match fresh_result {
        Ok(t) => t,
        Err(payload) => {
            return Err(format!(
                "step {} ({op:?}): panic in FRESH rebuild: {}",
                step.index,
                panic_message(&payload),
            ));
        }
    };

    if incremental != fresh {
        return Err(format!(
            "step {} ({op:?}): incremental tree diverged from a fresh rebuild\n\
             incremental: {incremental:#?}\n\
             fresh:       {fresh:#?}",
            step.index
        ));
    }
    Ok(())
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

fn cost(op: &Op) -> u64 {
    op.slots.iter().filter(|s| s.is_some()).count() as u64
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn coverage_sources() -> Vec<PathBuf> {
    std::env::var_os("FUZZ_COVERAGE_SOURCES")
        .map(|paths| std::env::split_paths(&paths).collect())
        .unwrap_or_else(|| vec![PathBuf::from("../dioxus/packages/core/src")])
}

fn coverage_collector() -> LlvmCoverage {
    let object = std::env::var_os("FUZZ_COVERAGE_OBJECT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_exe().expect("failed to locate current executable"));
    let workdir = std::env::var_os("FUZZ_COVERAGE_WORKDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/iterator-fuzz-cov/dioxus-vdom-example"));
    let mut coverage = LlvmCoverage::new(object, coverage_sources(), workdir)
        .expect("failed to initialize LLVM coverage");
    if let Some(path) = std::env::var_os("LLVM_PROFDATA") {
        coverage = coverage.llvm_profdata(path);
    }
    if let Some(path) = std::env::var_os("LLVM_COV") {
        coverage = coverage.llvm_cov(path);
    }
    coverage
}

fn run_coverage_guided() {
    let seeds = env_u64("FUZZ_SEEDS", 128);
    let steps = env_usize("FUZZ_STEPS", 128);
    let max_cases = env_usize("FUZZ_COVERAGE_CASES", 64);
    let mut coverage = coverage_collector();
    let mut explorer = Fuzzer::sequences(StandardUniform)
        .base_seed(0)
        .seeds(seeds)
        .steps(steps)
        .coverage_guided(move |ops: &[Op]| {
            coverage
                .evaluate(|| replay_ops(ops, Harness::fresh, apply_step))
                .expect("failed to collect LLVM coverage")
        })
        .cost(cost);

    println!("coverage-guided fuzzing {seeds} seeds x {steps} ops, accepting up to {max_cases}");
    let mut accepted = 0usize;
    for case in (&mut explorer).take(max_cases) {
        accepted += 1;
        println!(
            "accepted #{accepted}: seed {:?}, len {}, +{} coverage ids",
            case.seed,
            case.len,
            case.unique_coverage.len()
        );
        if let Err(error) = &case.outcome {
            println!("failure after {} ops: {error}", case.ops.len());
            break;
        }
    }
    let stats = explorer.stats();
    println!(
        "coverage summary: generated {}, executed {}, accepted {}, failures {}, coverage ids {}",
        stats.generated, stats.executed, stats.accepted, stats.failures, stats.coverage_ids
    );
}

fn main() {
    if std::env::var_os("FUZZ_COVERAGE").is_some() {
        run_coverage_guided();
        return;
    }

    let seeds = env_u64("FUZZ_SEEDS", 32_768);
    let steps = env_usize("FUZZ_STEPS", 512);

    let workers = rayon::current_num_threads();
    println!(
        "fuzzing {seeds} seeds × {steps} ops across {workers} rayon workers (keyed-list focus)"
    );

    // VirtualDom is `!Send`, but each parallel case constructs its own Harness
    // inside the worker via `Harness::fresh` and never sends it elsewhere.
    let bug = Fuzzer::sequences(StandardUniform)
        .base_seed(0)
        .seeds(seeds)
        .steps(steps)
        .par()
        .minimized_failures(Harness::fresh, apply_step, cost)
        .find_any(|_| true);

    match bug {
        None => {
            println!(
                "no divergence: {seeds} seeds × {steps} ops (parallel) found no incremental/fresh mismatch"
            );
        }
        Some(bug) => {
            println!(
                "seed {} diverged: original {} ops -> minimized to {} ops",
                bug.seed,
                bug.ops.len(),
                bug.minimized_ops.len()
            );
            for (i, op) in bug.minimized_ops.iter().enumerate() {
                let prims: Vec<_> = op.slots.iter().flatten().collect();
                println!("  {i}: {prims:?}");
            }
            println!("minimized error: {}", bug.minimized_error);
        }
    }
}
