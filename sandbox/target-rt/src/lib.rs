//! Runtime linked into a sandboxed target binary.
//!
//! Defines the SanitizerCoverage `trace-pc-guard` callbacks. Every instrumented edge
//!
//! 1. sets one bit in a `MAP_SHARED` bitmap the supervisor reads as coverage,
//! 2. bumps a shared edge counter,
//! 3. decrements the shared *edge budget*; at zero the thread issues the marker syscall
//!    (`getppid(MAGIC, PREEMPT)`), which the supervisor's seccomp filter turns into a ptrace stop.
//!
//! One shared budget word suffices because the supervisor runs exactly one target thread at a
//! time. The mapping is inherited as fd `DOWSING_SHM_FD` (a memfd); without it the callbacks only
//! assign guard ids and [`variant`] falls back to a local RNG, so the same binary runs natively.
//!
//! Must be built *without* sancov flags (`cargo rustc -- <flags>` instruments only the final
//! crate), otherwise the callbacks would instrument themselves.
//!
//! Layout (mirrored in `dowsing-sandbox/src/shm.rs`):
//!
//! ```text
//! offset 0      u32 budget        (0 = unlimited, n = preempt after n more edges)
//! offset 8      u64 edges         (monotonic edge counter)
//! offset 4096   bitmap            (BITMAP_BYTES, bit i = guard i was hit)
//! ```

use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32, AtomicU64, Ordering};

pub const ENV_SHM_FD: &str = "DOWSING_SHM_FD";
pub const HEADER_BYTES: usize = 4096;
pub const BITMAP_BYTES: usize = 1 << 16;
pub const SHM_BYTES: usize = HEADER_BYTES + BITMAP_BYTES;
pub const MARKER_SYSCALL: libc::c_long = libc::SYS_getppid;
pub const MARKER_MAGIC: u64 = 0xd0_5e_ed_5c_ed;
/// Marker kinds (second syscall argument).
pub const MARKER_PREEMPT: u64 = 0;
pub const MARKER_VARIANT: u64 = 1;

const OFF_BUDGET: usize = 0;
const OFF_EDGES: usize = 8;

static SHM: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static NEXT_GUARD: AtomicU32 = AtomicU32::new(1);
static NATIVE_RNG: AtomicU64 = AtomicU64::new(0);

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
    let value = unsafe { libc::getenv(c"DOWSING_SHM_FD".as_ptr()) };
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
        if !(c as u8).is_ascii_digit() {
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
fn marker(kind: u64, arg: u64) -> i64 {
    unsafe { libc::syscall(MARKER_SYSCALL, MARKER_MAGIC, kind, arg) as i64 }
}

/// Call once from `main` so the linker keeps this crate's sancov callbacks (an rlib member is
/// only pulled in when something references it).
#[inline(never)]
pub fn init() {
    core::hint::black_box(
        __sanitizer_cov_trace_pc_guard as unsafe extern "C" fn(*mut u32) as usize,
    );
    core::hint::black_box(
        __sanitizer_cov_trace_pc_guard_init as unsafe extern "C" fn(*mut u32, *mut u32) as usize,
    );
    core::hint::black_box(
        __sanitizer_cov_pcs_init as unsafe extern "C" fn(*const usize, *const usize) as usize,
    );
    core::hint::black_box(
        __sanitizer_cov_8bit_counters_init as unsafe extern "C" fn(*mut u8, *mut u8) as usize,
    );
    if SHM.load(Ordering::Relaxed).is_null() {
        attach_shm();
    }
}

/// Whether this process is attached to a supervisor mapping.
pub fn supervised() -> bool {
    !SHM.load(Ordering::Relaxed).is_null()
}

/// A harness decision with `n` choices: under the supervisor this is a decision node the
/// fuzzer explores and shrinks; natively it is a pseudo-random pick.
pub fn variant(n: u32) -> u32 {
    if n <= 1 {
        return 0;
    }
    if supervised() {
        let r = marker(MARKER_VARIANT, n as u64);
        return (r.max(0) as u32).min(n - 1);
    }
    let mut s = NATIVE_RNG.load(Ordering::Relaxed);
    if s == 0 {
        let mut t: libc::timespec = unsafe { core::mem::zeroed() };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
        s = (t.tv_nsec as u64) | 1;
    }
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    NATIVE_RNG.store(s, Ordering::Relaxed);
    (s % n as u64) as u32
}

/// `variant` over a range.
pub fn range(lo: u32, hi: u32) -> u32 {
    lo + variant(hi.saturating_sub(lo))
}

/// Edges recorded in the shared mapping so far (0 when not attached).
pub fn edges() -> u64 {
    let base = SHM.load(Ordering::Relaxed);
    if base.is_null() {
        return 0;
    }
    unsafe { header_u64(base, OFF_EDGES).load(Ordering::Relaxed) }
}

/// # Safety
/// Called by the sancov module constructor with the guard table bounds.
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

/// # Safety
/// Called by the sancov module constructor; the PC table is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_pcs_init(_start: *const usize, _end: *const usize) {}

/// # Safety
/// Called by the sancov module constructor; inline counters are ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_8bit_counters_init(_start: *mut u8, _end: *mut u8) {}

/// # Safety
/// Called by instrumented code with a pointer into the guard table.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    let base = SHM.load(Ordering::Relaxed);
    if base.is_null() {
        return;
    }
    let id = unsafe { guard.read() } as usize;
    if id >= BITMAP_BYTES * 8 {
        return;
    }
    // Plain load/store (no RMW): exactly one target thread runs at a time.
    unsafe {
        let byte = &*(base.add(HEADER_BYTES + id / 8) as *const AtomicU8);
        let bit = 1u8 << (id % 8);
        let old = byte.load(Ordering::Relaxed);
        if old & bit == 0 {
            byte.store(old | bit, Ordering::Relaxed);
        }
        let edges = header_u64(base, OFF_EDGES);
        edges.store(edges.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        let budget = header_u32(base, OFF_BUDGET);
        let remaining = budget.load(Ordering::Relaxed);
        if remaining == 0 {
            return;
        }
        if remaining == 1 {
            budget.store(0, Ordering::Relaxed);
            marker(MARKER_PREEMPT, 0);
        } else {
            budget.store(remaining - 1, Ordering::Relaxed);
        }
    }
}
