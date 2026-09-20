//! Snapshot and restore of the whole state: the target's dirty pages, mappings and per-thread
//! registers (via [`crate::snapshot`]) plus the supervisor's [`World`] (scheduler, coverage,
//! trace, oracle evidence and every model), which is plain data and simply cloned.

use super::Session;
use crate::{
    ptrace::{self, Pid, WaitEvent},
    snapshot::{self, MapOp, Mapping, PAGE, Snapshot, SnapshotId, ThreadRegs},
    world::*,
};
use std::{
    collections::HashSet,
    io,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Default)]
pub struct RestoreStats {
    pub pages_written: usize,
    pub map_ops: usize,
    pub threads: usize,
    pub wall: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct SnapshotStats {
    pub pages_copied: usize,
    pub wall: Duration,
}

impl Session {
    fn all_stopped(&self) -> bool {
        self.world.sched.current.is_none() && !self.world.sched.any_running()
    }

    pub(super) fn retained(&self, start: u64, len: u64) -> bool {
        let Some(head) = self.head else {
            return false;
        };
        let end = start.saturating_add(len);
        self.store.snapshots[head]
            .maps
            .iter()
            .any(|m| m.snapshotted() && m.is_anon() && m.start < end && start < m.end)
    }

    fn heap_end(maps: &[Mapping]) -> u64 {
        maps.iter()
            .find(|m| m.path == "[heap]")
            .map(|m| m.end)
            .unwrap_or(0)
    }

    /// Capture the current state. Only valid at a decision point or after `Done`.
    pub fn snapshot(&mut self) -> io::Result<(SnapshotId, SnapshotStats)> {
        if !self.all_stopped() {
            return Err(io::Error::other("snapshot while a thread is running"));
        }
        let start = Instant::now();
        let maps = snapshot::read_maps(self.leader)?;
        let scan = snapshot::scan_pagemap(self.leader, &maps)?;
        let addrs: &[u64] = if self.head.is_none() {
            &scan.present
        } else {
            &scan.dirty
        };
        let mut pages = self.store.read_pages(self.leader, addrs, self.head)?;
        if let Some(head) = self.head {
            let zero = self.store.zero_page();
            for &a in &scan.absent {
                if self
                    .store
                    .lookup(head, a)
                    .is_some_and(|p| p.iter().any(|b| *b != 0))
                {
                    pages.insert(a, zero.clone());
                }
            }
        }
        let pages_copied = pages.len();
        let mut regs = Vec::new();
        for t in &self.world.sched.threads {
            if t.state == ThreadState::Parked {
                continue;
            }
            regs.push(ThreadRegs {
                tid: t.tid,
                regs: ptrace::getregs(t.tid)?,
                xstate: ptrace::getregset(t.tid, ptrace::NT_X86_XSTATE)?,
            });
        }
        let depth = self
            .head
            .map(|h| self.store.snapshots[h].depth + 1)
            .unwrap_or(0);
        let id = self.store.push(Snapshot {
            parent: self.head,
            depth,
            pages,
            regs,
            world: self.world.clone(),
            brk: Self::heap_end(&maps),
            maps,
        });
        snapshot::clear_soft_dirty(self.leader)?;
        self.head = Some(id);
        Ok((
            id,
            SnapshotStats {
                pages_copied,
                wall: start.elapsed(),
            },
        ))
    }

    pub fn head(&self) -> Option<SnapshotId> {
        self.head
    }

    /// Return the process to snapshot `id`.
    pub fn restore(&mut self, id: SnapshotId) -> io::Result<RestoreStats> {
        if !self.all_stopped() {
            return Err(io::Error::other("restore while a thread is running"));
        }
        let start = Instant::now();
        let head = self
            .head
            .ok_or_else(|| io::Error::other("restore without a snapshot"))?;
        let live_maps = snapshot::read_maps(self.leader)?;
        let scan = snapshot::scan_pagemap(self.leader, &live_maps)?;

        // 1. mapping table
        let ops = snapshot::plan_maps(
            &live_maps,
            Self::heap_end(&live_maps),
            &self.store.snapshots[id].maps,
            self.store.snapshots[id].brk,
        )
        .map_err(|e| io::Error::other(format!("snapshot {id} unrestorable: {e}")))?;
        let live_brk = Self::heap_end(&live_maps);
        for op in &ops {
            self.inject_map_op(op)?;
        }

        // 2. pages: soft-dirty since `head`, everything copied on either side of the two
        // snapshots' common ancestor, and every page of a range the map ops just brought
        // back (the scan above could not see it; the kernel gave us zeros).
        let mut dirty: HashSet<u64> = scan.dirty.iter().copied().collect();
        dirty.extend(self.store.differing_pages(head, id));
        let mut fresh_ranges: Vec<(u64, u64)> = Vec::new();
        for op in &ops {
            match op {
                MapOp::Mmap { start, len, .. } => fresh_ranges.push((*start, *start + *len)),
                MapOp::Brk { end } if *end > live_brk => fresh_ranges.push((live_brk, *end)),
                _ => {}
            }
        }
        let fresh = fresh_ranges
            .iter()
            .flat_map(|(s, e)| (*s..*e).step_by(PAGE as usize));
        for a in scan.absent.iter().copied().chain(fresh) {
            if self
                .store
                .lookup(id, a)
                .is_some_and(|p| p.iter().any(|b| *b != 0))
            {
                dirty.insert(a);
            }
        }
        let snap_maps = &self.store.snapshots[id].maps;
        let absent: HashSet<u64> = scan.absent.iter().copied().collect();
        let mut written = 0;
        let mut dirty: Vec<u64> = dirty.into_iter().collect();
        dirty.sort_unstable();
        let zero = [0u8; PAGE as usize];
        for addr in dirty {
            if !snap_maps
                .iter()
                .any(|m| m.snapshotted() && m.contains(addr))
            {
                continue;
            }
            let content: &[u8] = match self.store.lookup(id, addr) {
                Some(page) => &page[..],
                None => &zero,
            };
            // An absent page already reads as zero; writing zeros would only allocate it.
            if absent.contains(&addr) && content.iter().all(|b| *b == 0) {
                continue;
            }
            ptrace::write_mem(self.leader, addr, content)?;
            written += 1;
        }

        // 3. registers
        let snap = &self.store.snapshots[id];
        for tr in &snap.regs {
            let mut regs = tr.regs;
            regs.orig_rax = u64::MAX;
            ptrace::setregs(tr.tid, &regs)?;
            ptrace::setregset(tr.tid, ptrace::NT_X86_XSTATE, &tr.xstate)?;
        }
        let snap_tids: HashSet<Pid> = snap.world.sched.threads.iter().map(|t| t.tid).collect();
        for t in &self.world.sched.threads {
            if !snap_tids.contains(&t.tid) && !self.zombies.contains(&t.tid) {
                self.zombies.push(t.tid);
            }
        }

        // 4. world + shared mapping
        self.world = snap.world.clone();
        self.shm.set_budget(0);
        self.shm.set_edges(self.world.cov.edges);
        self.shm.set_guard(self.world.cov.guard);
        self.shm.drain_bitmap(&mut crate::shm::Bitmap::default());
        self.new_coverage.clear();
        let threads = snap.regs.len();
        self.take_stderr();
        snapshot::clear_soft_dirty(self.leader)?;
        self.head = Some(id);
        Ok(RestoreStats {
            pages_written: written,
            map_ops: ops.len(),
            threads,
            wall: start.elapsed(),
        })
    }

    /// Execute one mmap-family syscall inside the (stopped) leader.
    fn inject_map_op(&mut self, op: &MapOp) -> io::Result<()> {
        let (nr, args): (i64, [u64; 6]) = match *op {
            MapOp::Munmap { start, len } => (libc::SYS_munmap, [start, len, 0, 0, 0, 0]),
            MapOp::Mmap { start, len, prot } => (
                libc::SYS_mmap,
                [
                    start,
                    len,
                    prot as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as u64,
                    u64::MAX,
                    0,
                ],
            ),
            MapOp::Mprotect { start, len, prot } => {
                (libc::SYS_mprotect, [start, len, prot as u64, 0, 0, 0])
            }
            MapOp::Brk { end } => (libc::SYS_brk, [end, 0, 0, 0, 0, 0]),
        };
        let ret = self.inject_syscall(nr, args)?;
        let ok = match op {
            MapOp::Brk { end } => ret as u64 == *end,
            MapOp::Mmap { start, .. } => ret as u64 == *start,
            _ => ret == 0,
        };
        if !ok {
            return Err(io::Error::other(format!("injected {op:?} returned {ret}")));
        }
        Ok(())
    }

    fn inject_syscall(&mut self, nr: i64, args: [u64; 6]) -> io::Result<i64> {
        if self.syscall_insn == 0 {
            return Err(io::Error::other("no syscall instruction address known yet"));
        }
        let tid = self.leader;
        let saved = ptrace::getregs(tid)?;
        let mut regs = saved;
        regs.orig_rax = u64::MAX;
        regs.rip = self.syscall_insn;
        regs.rax = nr as u64;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
        ptrace::setregs(tid, &regs)?;
        let mut result = None;
        for _ in 0..4 {
            ptrace::singlestep(tid)?;
            match ptrace::wait_pid(tid)? {
                WaitEvent::Signal { sig, .. } if sig == libc::SIGTRAP => {}
                // A traced syscall stops here before executing; rax is still -ENOSYS.
                WaitEvent::Event { event, .. } if event == libc::PTRACE_EVENT_SECCOMP => continue,
                WaitEvent::Event { .. } | WaitEvent::Syscall { .. } => {}
                other => return Err(io::Error::other(format!("inject: unexpected {other:?}"))),
            }
            let now = ptrace::getregs(tid)?;
            if now.rip == self.syscall_insn + 2 {
                result = Some(now.rax as i64);
                break;
            }
        }
        let mut restore = saved;
        restore.orig_rax = u64::MAX;
        ptrace::setregs(tid, &restore)?;
        result.ok_or_else(|| io::Error::other("injected syscall did not execute"))
    }
}
