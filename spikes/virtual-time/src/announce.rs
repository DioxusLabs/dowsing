//! SanitizerCoverage callbacks for sandboxed targets.
//!
//! Included with `#[path = "../announce.rs"]` by every target binary (not part of the lib).  When the binary is built with
//! `-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-inline-8bit-counters`, LLVM calls
//! `__sanitizer_cov_8bit_counters_init` at startup; we forward the counter range to the
//! supervisor through a reserved syscall number (`ENOSYS` when not sandboxed).  The supervisor
//! reads the counters straight out of our memory when we exit, so nothing else is needed here.

#![allow(dead_code)]

const ANNOUNCE_NR: libc::c_long = 0x1337;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, end: *mut u8) {
    if start.is_null() || end.is_null() || start >= end {
        return;
    }
    unsafe {
        libc::syscall(ANNOUNCE_NR, start as usize, end as usize);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_pcs_init(_start: *const usize, _end: *const usize) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(_start: *mut u32, _end: *mut u32) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(_guard: *mut u32) {}

macro_rules! cmp_stub {
    ($name:ident, $ty:ty) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(_a: $ty, _b: $ty) {}
    };
}

cmp_stub!(__sanitizer_cov_trace_cmp1, u8);
cmp_stub!(__sanitizer_cov_trace_cmp2, u16);
cmp_stub!(__sanitizer_cov_trace_cmp4, u32);
cmp_stub!(__sanitizer_cov_trace_cmp8, u64);
cmp_stub!(__sanitizer_cov_trace_const_cmp1, u8);
cmp_stub!(__sanitizer_cov_trace_const_cmp2, u16);
cmp_stub!(__sanitizer_cov_trace_const_cmp4, u32);
cmp_stub!(__sanitizer_cov_trace_const_cmp8, u64);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_switch(_val: u64, _cases: *const u64) {}
