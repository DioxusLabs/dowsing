//! Memory snapshots: a tree of page sets. Snapshot 0 copies every present page of every
//! writable private mapping; later snapshots copy only pages soft-dirty since their parent
//! (`/proc/pid/clear_refs` ← `4`, bit 55 of `/proc/pid/pagemap`). Registers and the [`World`]
//! are stored alongside. Restoring is a diff between two snapshots on the tree plus the pages
//! dirtied since the current head.

use crate::{
    ptrace::{self, Pid, Regs},
    world::World,
};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::FileExt,
    rc::Rc,
};

pub const PAGE: u64 = 4096;
const PM_SOFT_DIRTY: u64 = 1 << 55;
const PM_SWAPPED: u64 = 1 << 62;
const PM_PRESENT: u64 = 1 << 63;

pub type Page = Rc<[u8; PAGE as usize]>;
pub type SnapshotId = usize;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub prot: i32,
    pub shared: bool,
    pub path: String,
}

impl Mapping {
    pub fn is_anon(&self) -> bool {
        self.path.is_empty()
            || self.path.starts_with("[heap]")
            || self.path.starts_with("[stack]")
            || self.path.starts_with("[anon")
    }

    /// Private memory the target can change (or retained `PROT_NONE` anonymous memory whose
    /// contents a restore may need): what a snapshot copies.
    pub fn snapshotted(&self) -> bool {
        (self.prot & libc::PROT_WRITE != 0 || (self.prot == libc::PROT_NONE && self.is_anon()))
            && !self.shared
            && !matches!(self.path.as_str(), "[vvar]" | "[vdso]" | "[vsyscall]")
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

pub fn read_maps(pid: Pid) -> io::Result<Vec<Mapping>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(range), Some(perms)) = (it.next(), it.next()) else {
            continue;
        };
        let _offset = it.next();
        let _dev = it.next();
        let _inode = it.next();
        let path = it.next().unwrap_or("").to_string();
        let (a, b) = range
            .split_once('-')
            .ok_or_else(|| io::Error::other("bad maps line"))?;
        let start = u64::from_str_radix(a, 16).map_err(io::Error::other)?;
        let end = u64::from_str_radix(b, 16).map_err(io::Error::other)?;
        let p = perms.as_bytes();
        let mut prot = 0;
        if p[0] == b'r' {
            prot |= libc::PROT_READ;
        }
        if p[1] == b'w' {
            prot |= libc::PROT_WRITE;
        }
        if p[2] == b'x' {
            prot |= libc::PROT_EXEC;
        }
        out.push(Mapping {
            start,
            end,
            prot,
            shared: p[3] == b's',
            path,
        });
    }
    Ok(out)
}

pub fn clear_soft_dirty(pid: Pid) -> io::Result<()> {
    let mut f = File::create(format!("/proc/{pid}/clear_refs"))?;
    f.write_all(b"4")
}

pub struct PagemapScan {
    /// Present (or swapped) pages with the soft-dirty bit.
    pub dirty: Vec<u64>,
    /// Pages currently present or swapped.
    pub present: Vec<u64>,
    /// Pages that are neither present nor swapped (their content reads as zero). The
    /// soft-dirty bit is not tracked for them: a page that was present and became absent
    /// is simply one whose content is now zero.
    pub absent: Vec<u64>,
}

/// Scan the pagemap entries of every snapshotted mapping.
pub fn scan_pagemap(pid: Pid, maps: &[Mapping]) -> io::Result<PagemapScan> {
    let mut pm = File::open(format!("/proc/{pid}/pagemap"))?;
    let mut scan = PagemapScan {
        dirty: Vec::new(),
        present: Vec::new(),
        absent: Vec::new(),
    };
    let mut buf: Vec<u8> = Vec::new();
    for m in maps.iter().filter(|m| m.snapshotted()) {
        let pages = ((m.end - m.start) / PAGE) as usize;
        buf.resize(pages * 8, 0);
        pm.seek(SeekFrom::Start(m.start / PAGE * 8))?;
        pm.read_exact(&mut buf)?;
        for (i, chunk) in buf.as_chunks::<8>().0.iter().enumerate() {
            let e = u64::from_ne_bytes(*chunk);
            let addr = m.start + i as u64 * PAGE;
            let here = e & (PM_PRESENT | PM_SWAPPED) != 0;
            if here {
                scan.present.push(addr);
                if e & PM_SOFT_DIRTY != 0 {
                    scan.dirty.push(addr);
                }
            } else {
                scan.absent.push(addr);
            }
        }
    }
    Ok(scan)
}

pub struct ThreadRegs {
    pub tid: Pid,
    pub regs: Regs,
    pub xstate: Vec<u8>,
}

pub struct Snapshot {
    pub parent: Option<SnapshotId>,
    pub depth: usize,
    pub pages: HashMap<u64, Page>,
    pub regs: Vec<ThreadRegs>,
    pub world: World,
    pub maps: Vec<Mapping>,
    pub brk: u64,
}

#[derive(Default)]
pub struct Store {
    pub snapshots: Vec<Snapshot>,
    zero: Option<Page>,
    pub bytes: usize,
}

impl Store {
    pub fn zero_page(&mut self) -> Page {
        self.zero
            .get_or_insert_with(|| Rc::new([0u8; PAGE as usize]))
            .clone()
    }

    /// Copy `addrs` out of the target into a page map (zero pages are shared). Pages whose
    /// content equals what `base` already holds are dropped: soft-dirty is a VMA-level flag
    /// too, so a new mapping merging into an old one reports the whole old range as dirty.
    pub fn read_pages(
        &mut self,
        pid: Pid,
        addrs: &[u64],
        base: Option<SnapshotId>,
    ) -> io::Result<HashMap<u64, Page>> {
        let mut pages = HashMap::with_capacity(addrs.len());
        let mut buf = [0u8; PAGE as usize];
        let zero = self.zero_page();
        for &addr in addrs {
            ptrace::read_mem(pid, addr, &mut buf)?;
            let is_zero = buf.iter().all(|b| *b == 0);
            if let Some(base) = base {
                let unchanged = match self.lookup(base, addr) {
                    Some(old) => old[..] == buf[..],
                    None => is_zero,
                };
                if unchanged {
                    continue;
                }
            }
            if is_zero {
                pages.insert(addr, zero.clone());
            } else {
                self.bytes += PAGE as usize;
                pages.insert(addr, Rc::new(buf));
            }
        }
        Ok(pages)
    }

    pub fn push(&mut self, snapshot: Snapshot) -> SnapshotId {
        self.snapshots.push(snapshot);
        self.snapshots.len() - 1
    }

    pub fn ancestors(&self, mut id: Option<SnapshotId>) -> impl Iterator<Item = SnapshotId> + '_ {
        std::iter::from_fn(move || {
            let cur = id?;
            id = self.snapshots[cur].parent;
            Some(cur)
        })
    }

    /// Content of `addr` as of snapshot `id`, or `None` if never copied on that path (zero).
    pub fn lookup(&self, id: SnapshotId, addr: u64) -> Option<&Page> {
        self.ancestors(Some(id))
            .find_map(|s| self.snapshots[s].pages.get(&addr))
    }

    pub fn lca(&self, a: SnapshotId, b: SnapshotId) -> SnapshotId {
        let (mut a, mut b) = (a, b);
        while a != b {
            let (da, db) = (self.snapshots[a].depth, self.snapshots[b].depth);
            if da >= db {
                a = self.snapshots[a].parent.expect("root reached without lca");
            } else {
                b = self.snapshots[b].parent.expect("root reached without lca");
            }
        }
        a
    }

    /// Pages that may differ between `from` and `to`: everything copied by any snapshot on
    /// either side of their common ancestor.
    pub fn differing_pages(&self, from: SnapshotId, to: SnapshotId) -> HashSet<u64> {
        let lca = self.lca(from, to);
        let mut set = HashSet::new();
        for side in [from, to] {
            for s in self.ancestors(Some(side)).take_while(|s| *s != lca) {
                set.extend(self.snapshots[s].pages.keys().copied());
            }
        }
        set
    }
}

/// Change needed to turn the live mapping table into the snapshot's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapOp {
    Munmap { start: u64, len: u64 },
    Mmap { start: u64, len: u64, prot: i32 },
    Mprotect { start: u64, len: u64, prot: i32 },
    Brk { end: u64 },
}

/// Page-granular diff of two mapping tables for anonymous private memory. File-backed private
/// mappings that differ are reported as unsupported.
pub fn plan_maps(
    live: &[Mapping],
    live_brk: u64,
    snap: &[Mapping],
    snap_brk: u64,
) -> Result<Vec<MapOp>, String> {
    let ignore =
        |m: &Mapping| m.shared || matches!(m.path.as_str(), "[vvar]" | "[vdso]" | "[vsyscall]");
    let files = |ms: &[Mapping]| -> HashSet<Mapping> {
        ms.iter()
            .filter(|m| !ignore(m) && !m.is_anon())
            .cloned()
            .collect()
    };
    let (lf, sf) = (files(live), files(snap));
    if lf != sf {
        let diff: Vec<_> = lf
            .symmetric_difference(&sf)
            .map(|m| format!("{:x}-{:x} {}", m.start, m.end, m.path))
            .collect();
        return Err(format!("file-backed mappings differ: {diff:?}"));
    }
    let mut ops = Vec::new();
    if live_brk != snap_brk {
        ops.push(MapOp::Brk { end: snap_brk });
    }
    // Sweep the anonymous (non-heap; brk handles that) intervals of both tables: every
    // elementary segment between consecutive boundaries has one protection on each side.
    let anon = |ms: &[Mapping]| -> Vec<(u64, u64, i32)> {
        let mut v: Vec<_> = ms
            .iter()
            .filter(|m| !ignore(m) && m.is_anon() && m.path != "[heap]")
            .map(|m| (m.start, m.end, m.prot))
            .collect();
        v.sort_unstable();
        v
    };
    let (la, sa) = (anon(live), anon(snap));
    let mut bounds: Vec<u64> = la
        .iter()
        .chain(&sa)
        .flat_map(|(s, e, _)| [*s, *e])
        .collect();
    bounds.sort_unstable();
    bounds.dedup();
    let prot_at = |v: &[(u64, u64, i32)], a: u64| -> Option<i32> {
        let i = v.partition_point(|(s, _, _)| *s <= a);
        v[..i].last().filter(|(_, e, _)| a < *e).map(|(_, _, p)| *p)
    };
    let (mut unmap, mut map, mut prot) = (Vec::new(), Vec::new(), Vec::new());
    for w in bounds.windows(2) {
        let (s, e) = (w[0], w[1]);
        match (prot_at(&la, s), prot_at(&sa, s)) {
            (Some(_), None) => unmap.push((s, e - s, 0)),
            (None, Some(p)) => map.push((s, e - s, p)),
            (Some(lp), Some(p)) if lp != p => prot.push((s, e - s, p)),
            _ => {}
        }
    }
    for run in coalesce(unmap) {
        ops.push(MapOp::Munmap {
            start: run.0,
            len: run.1,
        });
    }
    for run in coalesce(map) {
        ops.push(MapOp::Mmap {
            start: run.0,
            len: run.1,
            prot: run.2,
        });
    }
    for run in coalesce(prot) {
        ops.push(MapOp::Mprotect {
            start: run.0,
            len: run.1,
            prot: run.2,
        });
    }
    Ok(ops)
}

/// Merge adjacent (start, len, tag) runs with equal tags.
fn coalesce(runs: Vec<(u64, u64, i32)>) -> Vec<(u64, u64, i32)> {
    let mut out: Vec<(u64, u64, i32)> = Vec::new();
    for (start, len, tag) in runs {
        if let Some(last) = out.last_mut()
            && last.0 + last.1 == start
            && last.2 == tag
        {
            last.1 += len;
        } else {
            out.push((start, len, tag));
        }
    }
    out
}

/// Read one 8-byte word via `/proc/pid/mem` (works for read-only pages, unlike process_vm_readv
/// on some configurations).
pub fn read_word_mem(pid: Pid, addr: u64) -> io::Result<u64> {
    let f = File::open(format!("/proc/{pid}/mem"))?;
    let mut buf = [0u8; 8];
    f.read_exact_at(&mut buf, addr)?;
    Ok(u64::from_ne_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesce_merges_adjacent_equal_tags() {
        let r = coalesce(vec![
            (0, 4096, 0),
            (4096, 4096, 0),
            (8192, 4096, 1),
            (20480, 4096, 1),
        ]);
        assert_eq!(r, vec![(0, 8192, 0), (8192, 4096, 1), (20480, 4096, 1)]);
    }

    #[test]
    fn plan_maps_diff() {
        let m = |s: u64, e: u64, prot, path: &str| Mapping {
            start: s,
            end: e,
            prot,
            shared: false,
            path: path.into(),
        };
        let live = vec![m(0x1000, 0x3000, 3, ""), m(0x5000, 0x6000, 3, "")];
        let snap = vec![
            m(0x1000, 0x2000, 3, ""),
            m(0x2000, 0x3000, 0, ""),
            m(0x8000, 0x9000, 1, ""),
        ];
        let ops = plan_maps(&live, 0x100, &snap, 0x200).unwrap();
        assert_eq!(
            ops,
            vec![
                MapOp::Brk { end: 0x200 },
                MapOp::Munmap {
                    start: 0x5000,
                    len: 0x1000
                },
                MapOp::Mmap {
                    start: 0x8000,
                    len: 0x1000,
                    prot: 1
                },
                MapOp::Mprotect {
                    start: 0x2000,
                    len: 0x1000,
                    prot: 0
                },
            ]
        );
        assert!(plan_maps(&live, 0, &[m(0x1000, 0x2000, 1, "/lib/x.so")], 0).is_err());
    }
}
