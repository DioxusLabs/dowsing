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
