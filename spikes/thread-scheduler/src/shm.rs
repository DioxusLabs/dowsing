//! Supervisor side of the shared mapping (layout mirrored from `target-rt/src/lib.rs`) and the
//! `ShmCoverage` [`CoverageCapture`] backend that folds the target's edge bitmap into dowsing.

use iterator_fuzz::coverage::{CoverageCapture, CoverageId, CoverageSet, ExecutionFeedback};
use std::{
    cell::Cell,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    rc::Rc,
    sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
};

pub const ENV_SHM_FD: &str = "SCHED_SHM_FD";
pub const HEADER_BYTES: usize = 4096;
pub const BITMAP_BYTES: usize = 1 << 20;
pub const SHM_BYTES: usize = HEADER_BYTES + BITMAP_BYTES;
pub const MARKER_SYSCALL: libc::c_long = libc::SYS_getppid;
pub const MARKER_MAGIC: u64 = 0x5eed_5ced;

const OFF_BUDGET: usize = 0;
const OFF_EDGES: usize = 8;
const OFF_MARKER_HITS: usize = 16;

/// A memfd-backed mapping shared with one target process at a time.
pub struct Shm {
    fd: OwnedFd,
    base: *mut u8,
}

impl Shm {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::memfd_create(c"sched-shm".as_ptr(), 0) };
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

    pub fn budget(&self) -> u32 {
        self.u32_at(OFF_BUDGET).load(Ordering::SeqCst)
    }

    pub fn edges(&self) -> u64 {
        self.u64_at(OFF_EDGES).load(Ordering::SeqCst)
    }

    pub fn marker_hits(&self) -> u64 {
        self.u64_at(OFF_MARKER_HITS).load(Ordering::SeqCst)
    }

    /// Zero header counters and the bitmap (start of a case).
    pub fn clear(&self) {
        unsafe {
            std::ptr::write_bytes(self.base, 0, SHM_BYTES);
        }
        std::sync::atomic::fence(Ordering::SeqCst);
    }

    /// Indices of set bits in the bitmap.
    pub fn hit_guards(&self) -> Vec<u32> {
        let mut out = Vec::new();
        let bitmap =
            unsafe { std::slice::from_raw_parts(self.base.add(HEADER_BYTES), BITMAP_BYTES) };
        for (i, chunk) in bitmap.as_chunks::<8>().0.iter().enumerate() {
            let word = u64::from_ne_bytes(*chunk);
            if word == 0 {
                continue;
            }
            let mut w = word;
            while w != 0 {
                let bit = w.trailing_zeros();
                out.push((i * 64) as u32 + bit);
                w &= w - 1;
            }
        }
        out
    }

    pub fn bitmap_byte(&self, index: usize) -> u8 {
        unsafe {
            (*(self.base.add(HEADER_BYTES + index) as *const AtomicU8)).load(Ordering::Relaxed)
        }
    }
}

impl Drop for Shm {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, SHM_BYTES);
        }
    }
}

/// dowsing coverage backend reading the target's shared bitmap.
///
/// `start_capture` clears the mapping; the harness then runs the target under the scheduler;
/// `finish_capture` turns the set bits into [`CoverageId`]s. The mapping is per supervisor (one
/// target at a time), so attribution is naturally serial.
#[derive(Clone)]
pub struct ShmCoverage {
    shm: Rc<Shm>,
    /// Harness-supplied extra features (e.g. hashed schedule events) appended to the next capture.
    extra: Rc<Cell<Vec<u64>>>,
}

impl ShmCoverage {
    pub fn new(shm: Rc<Shm>) -> Self {
        Self {
            shm,
            extra: Rc::new(Cell::new(Vec::new())),
        }
    }

    pub fn shm(&self) -> &Rc<Shm> {
        &self.shm
    }

    /// Add synthetic features for the case currently being captured.
    pub fn add_features(&self, ids: impl IntoIterator<Item = u64>) {
        let mut v = self.extra.take();
        v.extend(ids);
        self.extra.set(v);
    }
}

impl CoverageCapture for ShmCoverage {
    type Token = ();

    fn start_capture(&mut self) -> Result<(), String> {
        self.shm.clear();
        self.extra.set(Vec::new());
        Ok(())
    }

    fn finish_capture(&mut self, _token: ()) -> Result<ExecutionFeedback, String> {
        let mut set = CoverageSet::new();
        for guard in self.shm.hit_guards() {
            set.insert(CoverageId::new(guard as u64));
        }
        for extra in self.extra.take() {
            set.insert(CoverageId::new((1u64 << 40) | extra));
        }
        let edges = self.shm.edges();
        Ok(ExecutionFeedback::from_features(set).with_hit_count_weight(edges))
    }

    fn discard_capture(&mut self, _token: ()) -> Result<(), String> {
        self.extra.set(Vec::new());
        Ok(())
    }
}
