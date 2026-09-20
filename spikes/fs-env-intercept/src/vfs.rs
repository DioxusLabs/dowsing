//! Lazy materialization of the virtual tree into a per-case tmpfs directory.
//!
//! A node is materialized the first time the target touches it; the draws that shaped it are
//! attached to the node so a re-issued syscall (after `SEND -> ENOENT`) or a second open sees the
//! same bytes. The materialized tree is made of real files, directories and symlinks so the
//! injected fd supports `read`/`mmap`/`fstat`/`lseek`/`getdents64` natively.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::draw::Draw;
use crate::spec::{Content, NodeSpec, Spec};

#[derive(Debug, Clone)]
pub enum Node {
    File { bytes: usize },
    Dir,
    Symlink { target: PathBuf },
    Missing { errno: i32 },
}

pub struct Vfs {
    root: PathBuf,
    nodes: HashMap<PathBuf, Node>,
    pub materialized_bytes: usize,
    pub non_default_variants: usize,
    pub touched: usize,
}

const EXTRA_NAMES: &[&str] = &["cache", "state.db", "lock", "a", ".hidden", "x y", "z"];

pub fn case_root(case_id: u64) -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| PathBuf::from("/dev/shm"));
    base.join("dowsing")
        .join(std::process::id().to_string())
        .join(case_id.to_string())
}

impl Vfs {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            nodes: HashMap::new(),
            materialized_bytes: 0,
            non_default_variants: 0,
            touched: 0,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path of the materialized copy of `virtual_path`.
    pub fn real_path(&self, virtual_path: &Path) -> PathBuf {
        self.root
            .join(virtual_path.strip_prefix("/").unwrap_or(virtual_path))
    }

    /// Map a materialized path back to its virtual path (for relative `openat` on injected dir fds).
    pub fn virtual_path(&self, real: &Path) -> Option<PathBuf> {
        real.strip_prefix(&self.root)
            .ok()
            .map(|rest| Path::new("/").join(rest))
    }

    /// Fixed content for implicit files (e.g. `/proc/self/environ`).
    pub fn insert_fixed_file(&mut self, virtual_path: &Path, bytes: &[u8]) -> io::Result<()> {
        let real = self.real_path(virtual_path);
        if let Some(parent) = real.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&real, bytes)?;
        self.nodes
            .insert(virtual_path.to_path_buf(), Node::File { bytes: bytes.len() });
        Ok(())
    }

    /// Materialize `virtual_path` (and, for directories, its children) if not done yet.
    pub fn materialize(
        &mut self,
        spec: &Spec,
        draw: &mut dyn Draw,
        virtual_path: &Path,
    ) -> io::Result<Node> {
        if let Some(node) = self.nodes.get(virtual_path) {
            return Ok(node.clone());
        }
        self.touched += 1;
        let real = self.real_path(virtual_path);
        if let Some(parent) = real.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let node = match spec.node(virtual_path) {
            Some(NodeSpec::File { content, may_fail }) => {
                let presence = if *may_fail { draw.variant(3) } else { 0 };
                match presence {
                    0 => {
                        let bytes = generate(content, draw);
                        std::fs::write(&real, &bytes)?;
                        self.materialized_bytes += bytes.len();
                        Node::File { bytes: bytes.len() }
                    }
                    1 => {
                        self.non_default_variants += 1;
                        Node::Missing { errno: libc::ENOENT }
                    }
                    _ => {
                        self.non_default_variants += 1;
                        Node::Missing { errno: libc::EACCES }
                    }
                }
            }
            Some(NodeSpec::Dir { extra_entries }) => {
                std::fs::create_dir_all(&real)?;
                self.nodes.insert(virtual_path.to_path_buf(), Node::Dir);
                for child in spec.children(virtual_path) {
                    self.materialize(spec, draw, &child)?;
                }
                if *extra_entries > 0 {
                    let count = draw.variant(*extra_entries + 1);
                    for _ in 0..count {
                        let (index, name) = crate::draw::pick(draw, EXTRA_NAMES);
                        if index != 0 {
                            self.non_default_variants += 1;
                        }
                        let child = virtual_path.join(name);
                        if self.nodes.contains_key(&child) {
                            continue;
                        }
                        let bytes = draw.bytes(0..=16);
                        std::fs::write(self.real_path(&child), &bytes)?;
                        self.materialized_bytes += bytes.len();
                        self.nodes.insert(child, Node::File { bytes: bytes.len() });
                    }
                }
                Node::Dir
            }
            Some(NodeSpec::Symlink { targets }) => {
                let (index, target) = crate::draw::pick(draw, targets);
                if index != 0 {
                    self.non_default_variants += 1;
                }
                std::os::unix::fs::symlink(target, &real)?;
                Node::Symlink {
                    target: target.clone(),
                }
            }
            None => {
                // Implicit ancestor directory or an undeclared name below a declared directory.
                if spec
                    .nodes
                    .iter()
                    .any(|(declared, _)| declared.starts_with(virtual_path))
                {
                    std::fs::create_dir_all(&real)?;
                    self.nodes.insert(virtual_path.to_path_buf(), Node::Dir);
                    for child in spec.children(virtual_path) {
                        self.materialize(spec, draw, &child)?;
                    }
                    Node::Dir
                } else {
                    Node::Missing { errno: libc::ENOENT }
                }
            }
        };
        self.nodes.insert(virtual_path.to_path_buf(), node.clone());
        Ok(node)
    }

    /// Resolve symlinks virtually (a symlink target is another virtual path or a real one).
    pub fn resolve(
        &mut self,
        spec: &Spec,
        draw: &mut dyn Draw,
        virtual_path: &Path,
        follow: bool,
    ) -> io::Result<Resolved> {
        let mut path = virtual_path.to_path_buf();
        for _ in 0..8 {
            if spec.classify(&path) == crate::spec::Classification::Real {
                return Ok(Resolved::Real(path));
            }
            let node = self.materialize(spec, draw, &path)?;
            match node {
                Node::Symlink { target } if follow => {
                    let joined = if target.is_absolute() {
                        target
                    } else {
                        path.parent().unwrap_or(Path::new("/")).join(target)
                    };
                    path = crate::spec::normalize(&joined);
                }
                node => return Ok(Resolved::Virtual(path, node)),
            }
        }
        Err(io::Error::from_raw_os_error(libc::ELOOP))
    }

    pub fn nodes(&self) -> &HashMap<PathBuf, Node> {
        &self.nodes
    }

    /// Read back the materialized bytes of a virtual file.
    pub fn read_file(&self, virtual_path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(self.real_path(virtual_path))
    }

    /// Remove the per-case tree.
    pub fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub enum Resolved {
    Real(PathBuf),
    Virtual(PathBuf, Node),
}

fn generate(content: &Content, draw: &mut dyn Draw) -> Vec<u8> {
    match content {
        Content::Fixed(bytes) => bytes.clone(),
        Content::Random { max_len } => draw.bytes(0..=*max_len),
        Content::Generate(generator) => generator(draw),
    }
}

pub fn os_string(bytes: Vec<u8>) -> OsString {
    OsString::from_vec(bytes)
}

pub fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}
