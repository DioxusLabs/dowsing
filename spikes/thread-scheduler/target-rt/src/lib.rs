//! Runtime linked into a *scheduled target* binary.
//!
//! It defines the SanitizerCoverage `trace-pc-guard` callbacks. Every instrumented edge
//!
//! 1. sets one bit in a `MAP_SHARED` bitmap the supervisor reads as coverage,
//! 2. bumps a shared edge counter (the supervisor uses it for the schedule trace),
//! 3. decrements the shared *edge budget*; when it reaches zero the thread executes the
//!    **yield marker** syscall (`getppid(MAGIC)`), which the supervisor's seccomp filter turns into a
//!    ptrace stop. The supervisor writes the next budget into the header before resuming a thread.
//!
//! Because the supervisor lets exactly one target thread run at a time, a single shared budget
//! word is enough: whichever thread is running is the one the budget was written for.
//!
//! The shared mapping is inherited as file descriptor `SCHED_SHM_FD` (a memfd). When that variable
//! is absent the callbacks only assign guard ids and otherwise do nothing, so the same binary runs
//! natively. This crate must be built *without* sancov flags (`cargo rustc -- <flags>` only
//! instruments the final crate), otherwise the callback would instrument itself.
//!
//! Layout (mirrored in `thread-scheduler/src/shm.rs`):
//!
//! ```text
//! offset 0      u32 budget        (0 = unlimited, n = preempt after n more edges)
//! offset 8      u64 edges         (monotonic edge counter for this process)
//! offset 16     u64 marker_hits   (number of yield-marker syscalls issued)
//! offset 4096   bitmap            (BITMAP_BYTES bytes, bit i = guard i was hit)
//! ```

use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32, AtomicU64, Ordering};

pub const ENV_SHM_FD: &str = "SCHED_SHM_FD";
pub const HEADER_BYTES: usize = 4096;
pub const BITMAP_BYTES: usize = 1 << 20;
pub const SHM_BYTES: usize = HEADER_BYTES + BITMAP_BYTES;
pub const MARKER_SYSCALL: libc::c_long = libc::SYS_getppid;
pub const MARKER_MAGIC: u64 = 0x5eed_5ced;

const OFF_BUDGET: usize = 0;
const OFF_EDGES: usize = 8;
const OFF_MARKER_HITS: usize = 16;

static SHM: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static NEXT_GUARD: AtomicU32 = AtomicU32::new(1);

#[inline(always)]
unsafe fn header_u32(base: *mut u8, off: usize) -> &'static AtomicU32 {
    unsafe { &*(base.add(off) as *const AtomicU32) }
}

#[inline(always)]
unsafe fn header_u64(base: *mut u8, off: usize) -> &'static AtomicU64 {
    unsafe { &*(base.add(off) as *const AtomicU64) }
}

#[inline(never)]
fn attach_shm() {
    let value = unsafe { libc::getenv(c"SCHED_SHM_FD".as_ptr()) };
    if value.is_null() {
        return;
    }
    let mut fd: libc::c_int = 0;
    let mut p = value;
    loop {
        let c = unsafe { *p };
        if c == 0 {
            break;
        }
        if !(b'0'..=b'9').contains(&(c as u8)) {
            return;
        }
        fd = fd * 10 + (c as u8 - b'0') as libc::c_int;
        p = unsafe { p.add(1) };
    }
    let base = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            SHM_BYTES,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return;
    }
    SHM.store(base as *mut u8, Ordering::Release);
}

#[inline(never)]
fn yield_marker() {
    unsafe {
        libc::syscall(MARKER_SYSCALL, MARKER_MAGIC);
    }
}

/// Call once from `main` so the linker keeps this crate's sancov callbacks (an rlib member is
/// only pulled in when something references it).
#[inline(never)]
pub fn init() {
    core::hint::black_box(__sanitizer_cov_trace_pc_guard as extern "C" fn(*mut u32) as usize);
    core::hint::black_box(
        __sanitizer_cov_trace_pc_guard_init as unsafe extern "C" fn(*mut u32, *mut u32) as usize,
    );
    core::hint::black_box(
        __sanitizer_cov_pcs_init as unsafe extern "C" fn(*const usize, *const usize) as usize,
    );
    core::hint::black_box(
        __sanitizer_cov_8bit_counters_init as unsafe extern "C" fn(*mut u8, *mut u8) as usize,
    );
}

/// Number of guards assigned so far (for diagnostics from the target side).
pub fn guard_count() -> u32 {
    NEXT_GUARD.load(Ordering::Relaxed) - 1
}

/// Whether this process is attached to a supervisor mapping.
pub fn supervised() -> bool {
    !SHM.load(Ordering::Relaxed).is_null()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(start: *mut u32, end: *mut u32) {
    if start.is_null() || end.is_null() || start >= end {
        return;
    }
    if unsafe { start.read() } != 0 {
        return;
    }
    if SHM.load(Ordering::Relaxed).is_null() {
        attach_shm();
    }
    let mut current = start;
    while current < end {
        let id = NEXT_GUARD.fetch_add(1, Ordering::Relaxed);
        unsafe {
            current.write(id);
            current = current.add(1);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_pcs_init(_start: *const usize, _end: *const usize) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_8bit_counters_init(_start: *mut u8, _end: *mut u8) {}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    let base = SHM.load(Ordering::Relaxed);
    if base.is_null() {
        return;
    }
    let id = unsafe { guard.read() } as usize;
    if id >= BITMAP_BYTES * 8 {
        return;
    }
    unsafe {
        let byte = &*(base.add(HEADER_BYTES + id / 8) as *const AtomicU8);
        byte.fetch_or(1 << (id % 8), Ordering::Relaxed);
        header_u64(base, OFF_EDGES).fetch_add(1, Ordering::Relaxed);
        let budget = header_u32(base, OFF_BUDGET);
        let remaining = budget.load(Ordering::Relaxed);
        if remaining == 0 {
            return;
        }
        if remaining == 1 {
            budget.store(0, Ordering::Relaxed);
            header_u64(base, OFF_MARKER_HITS).fetch_add(1, Ordering::Relaxed);
            yield_marker();
        } else {
            budget.store(remaining - 1, Ordering::Relaxed);
        }
    }
}
