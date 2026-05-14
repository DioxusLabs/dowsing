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
