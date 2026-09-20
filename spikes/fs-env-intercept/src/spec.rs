//! Harness-side declaration of which inputs are virtual and what shapes they may take.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::draw::Draw;

pub type Generator = Arc<dyn Fn(&mut dyn Draw) -> Vec<u8> + Send + Sync>;

/// How the bytes of a virtual file are produced.
#[derive(Clone)]
pub enum Content {
    /// Fixed bytes, no draws.
    Fixed(Vec<u8>),
    /// `range(0..=max_len)` of single-byte items: fully shrinkable, format-agnostic.
    Random { max_len: usize },
    /// Harness-supplied structured generator (still drawn from the case RNG).
    Generate(Generator),
}

#[derive(Clone)]
pub enum NodeSpec {
    File {
        content: Content,
        /// Variant 0 = exists; further variants (in order) = `ENOENT`, `EACCES`.
        may_fail: bool,
    },
    Dir {
        /// Number of extra random entries added next to the declared children.
        extra_entries: usize,
    },
    Symlink {
        /// Variant set of link targets (index 0 = default).
        targets: Vec<PathBuf>,
    },
}

#[derive(Clone)]
pub struct EnvSpec {
    pub name: String,
    /// Variant set; `None` = unset. Index 0 is the default.
    pub values: Vec<Option<String>>,
}

#[derive(Clone, Debug)]
pub struct Uname {
    pub sysname: String,
    pub nodename: String,
    pub release: String,
    pub version: String,
    pub machine: String,
    pub domainname: String,
}

impl Uname {
    pub fn realistic() -> Self {
        Self {
            sysname: "Linux".into(),
            nodename: "dowsing".into(),
            release: "6.8.0-1061-aws".into(),
            version: "#66~22.04.1-Ubuntu SMP".into(),
            machine: "x86_64".into(),
            domainname: "(none)".into(),
        }
    }

    pub fn unusual_set() -> Vec<Self> {
        vec![
            Self::realistic(),
            Self {
                release: "5.4.0".into(),
                ..Self::realistic()
            },
            Self {
                release: "7.0.0-rc1+".into(),
                ..Self::realistic()
            },
            Self {
                nodename: String::new(),
                release: "6.8.0".into(),
                ..Self::realistic()
            },
            Self {
                nodename: "x".repeat(64),
                ..Self::realistic()
            },
        ]
    }
}

#[derive(Clone, Debug)]
pub struct IdentitySpec {
    /// Variant set for `getpid` (index 0 = the real pid, filled in at case start).
    pub pids: Vec<Option<u32>>,
    /// Variant set for `gettid`.
    pub tids: Vec<Option<u32>>,
    pub unames: Vec<Uname>,
    /// Variant set of `totalram` values in bytes (index 0 = realistic).
    pub total_ram: Vec<u64>,
    /// Variant set of `procs` values.
    pub procs: Vec<u16>,
}

impl Default for IdentitySpec {
    fn default() -> Self {
        Self {
            pids: vec![None, Some(1), Some(2), Some(4_194_304), Some(0x7fff_ffff)],
            tids: vec![None, Some(1), Some(4_194_304)],
            unames: Uname::unusual_set(),
            total_ram: vec![32 << 30, 256 << 20, 1 << 40, 0],
            procs: vec![300, 1, u16::MAX],
        }
    }
}

#[derive(Clone, Debug)]
pub struct EntropySpec {
    /// Trap `/dev/urandom` and `/dev/random`.
    pub urandom: bool,
    /// Trap `getrandom`.
    pub getrandom: bool,
    /// Allow short reads and `EINTR`/`EAGAIN` results (variant 0 = full read).
    pub faults: bool,
}

impl Default for EntropySpec {
    fn default() -> Self {
        Self {
            urandom: true,
            getrandom: true,
            faults: true,
        }
    }
}

#[derive(Clone)]
pub struct Spec {
    pub nodes: Vec<(PathBuf, NodeSpec)>,
    pub env: Vec<EnvSpec>,
    pub identity: IdentitySpec,
    pub entropy: EntropySpec,
    /// Serve a virtual `/proc/self/environ` reflecting the applied environment.
    pub virtual_environ: bool,
    /// Maximum trace bytes the sandbox may draw before the case is flagged as over budget.
    pub trace_budget: usize,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            env: Vec::new(),
            identity: IdentitySpec::default(),
            entropy: EntropySpec::default(),
            virtual_environ: true,
            trace_budget: 4096,
        }
    }
}

impl Spec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn file(mut self, path: impl AsRef<Path>, content: Content) -> Self {
        self.nodes.push((
            normalize(path.as_ref()),
            NodeSpec::File {
                content,
                may_fail: false,
            },
        ));
        self
    }

    pub fn file_may_fail(mut self, path: impl AsRef<Path>, content: Content) -> Self {
        self.nodes.push((
            normalize(path.as_ref()),
            NodeSpec::File {
                content,
                may_fail: true,
            },
        ));
        self
    }

    pub fn dir(mut self, path: impl AsRef<Path>, extra_entries: usize) -> Self {
        self.nodes
            .push((normalize(path.as_ref()), NodeSpec::Dir { extra_entries }));
        self
    }

    pub fn symlink(mut self, path: impl AsRef<Path>, targets: Vec<PathBuf>) -> Self {
        self.nodes
            .push((normalize(path.as_ref()), NodeSpec::Symlink { targets }));
        self
    }

    pub fn env(mut self, name: &str, values: Vec<Option<&str>>) -> Self {
        self.env.push(EnvSpec {
            name: name.to_string(),
            values: values.into_iter().map(|v| v.map(str::to_string)).collect(),
        });
        self
    }

    pub fn node(&self, path: &Path) -> Option<&NodeSpec> {
        self.nodes.iter().find(|(p, _)| p == path).map(|(_, n)| n)
    }

    /// Declared children directly under `dir`.
    pub fn children(&self, dir: &Path) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        for (path, _) in &self.nodes {
            if let Ok(rest) = path.strip_prefix(dir) {
                if let Some(first) = rest.components().next() {
                    let child = dir.join(first);
                    if !out.contains(&child) {
                        out.push(child);
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// Whether `path` is inside the virtual tree: a declared node, below a declared directory, or
    /// an undeclared ancestor of a declared node that does not exist on the real filesystem.
    pub fn classify(&self, path: &Path) -> Classification {
        for (declared, node) in &self.nodes {
            if path == declared {
                return Classification::Virtual;
            }
            if matches!(node, NodeSpec::Dir { .. }) && path.starts_with(declared) {
                return Classification::Virtual;
            }
        }
        if self.nodes.iter().any(|(declared, _)| declared.starts_with(path))
            && path != Path::new("/")
        {
            // Implicit ancestor directory: virtual only if the real one is missing so that e.g.
            // stat("/etc") keeps working natively.
            if std::fs::symlink_metadata(path).is_err() {
                return Classification::Virtual;
            }
        }
        Classification::Real
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    Virtual,
    Real,
}

/// Lexically normalize an absolute path (`.`/`..`/duplicate separators).
pub fn normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}
