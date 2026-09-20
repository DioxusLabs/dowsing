//! Supervisor side of the mapping shared with the target (layout mirrored from
//! `target-rt/src/lib.rs`): edge budget, edge counter and the coverage bitmap.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};

pub const ENV_SHM_FD: &str = "DOWSING_SHM_FD";
pub const HEADER_BYTES: usize = 4096;
pub const BITMAP_BYTES: usize = 1 << 16;
pub const SHM_BYTES: usize = HEADER_BYTES + BITMAP_BYTES;
pub const MARKER_SYSCALL: libc::c_long = libc::SYS_getppid;
pub const MARKER_MAGIC: u64 = 0xd0_5e_ed_5c_ed;
pub const MARKER_PREEMPT: u64 = 0;
pub const MARKER_VARIANT: u64 = 1;

const OFF_BUDGET: usize = 0;
const OFF_EDGES: usize = 8;

/// Coverage bitmap of one execution path; cloned into snapshots and written back on restore.
#[derive(Clone, PartialEq, Eq)]
pub struct Bitmap(pub Box<[u64; BITMAP_BYTES / 8]>);

impl Default for Bitmap {
    fn default() -> Self {
        Self(Box::new([0; BITMAP_BYTES / 8]))
    }
}

impl Bitmap {
    pub fn set_bits(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().enumerate().flat_map(|(i, &word)| {
            let mut w = word;
            std::iter::from_fn(move || {
                if w == 0 {
                    return None;
                }
                let bit = w.trailing_zeros();
                w &= w - 1;
                Some((i * 64) as u32 + bit)
            })
        })
    }

    pub fn count(&self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }
}

/// A memfd-backed mapping shared with one target process.
pub struct Shm {
    fd: OwnedFd,
    base: *mut u8,
}

impl Shm {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::memfd_create(c"dowsing-shm".as_ptr(), 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::ftruncate(fd.as_raw_fd(), SHM_BYTES as libc::off_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SHM_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            base: base as *mut u8,
        })
    }

    pub fn fd(&self) -> &OwnedFd {
        &self.fd
    }

    fn u32_at(&self, off: usize) -> &AtomicU32 {
        unsafe { &*(self.base.add(off) as *const AtomicU32) }
    }

    fn u64_at(&self, off: usize) -> &AtomicU64 {
        unsafe { &*(self.base.add(off) as *const AtomicU64) }
    }

    pub fn set_budget(&self, budget: u32) {
        self.u32_at(OFF_BUDGET).store(budget, Ordering::SeqCst);
    }

    pub fn edges(&self) -> u64 {
        self.u64_at(OFF_EDGES).load(Ordering::SeqCst)
    }

    pub fn set_edges(&self, edges: u64) {
        self.u64_at(OFF_EDGES).store(edges, Ordering::SeqCst);
    }

    fn bitmap_words(&self) -> &[AtomicU64] {
        unsafe {
            std::slice::from_raw_parts(
                self.base.add(HEADER_BYTES) as *const AtomicU64,
                BITMAP_BYTES / 8,
            )
        }
    }

    /// Bits set since the last `drain_bitmap`, then cleared. The caller folds them into the
    /// path bitmap it owns.
    pub fn drain_bitmap(&self, into: &mut Bitmap) -> Vec<u32> {
        let mut new = Vec::new();
        for (i, word) in self.bitmap_words().iter().enumerate() {
            let w = word.load(Ordering::SeqCst);
            if w == 0 {
                continue;
            }
            word.store(0, Ordering::SeqCst);
            let fresh = w & !into.0[i];
            into.0[i] |= w;
            let mut f = fresh;
            while f != 0 {
                let bit = f.trailing_zeros();
                f &= f - 1;
                new.push((i * 64) as u32 + bit);
            }
        }
        new
    }

    pub fn clear(&self) {
        unsafe {
            std::ptr::write_bytes(self.base, 0, SHM_BYTES);
        }
        std::sync::atomic::fence(Ordering::SeqCst);
    }
}

impl Drop for Shm {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, SHM_BYTES);
        }
    }
}
