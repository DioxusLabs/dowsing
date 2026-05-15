use crate::{CoverageCapture, CoverageId, CoverageSet};
use std::{
    ffi::{CStr, c_char, c_void},
    mem,
    sync::{Mutex, MutexGuard, OnceLock},
};

/// In-process LLVM counter coverage for `curious()` and `shy()`.
///
/// Build the harness with `RUSTFLAGS="-Cinstrument-coverage"` so LLVM exposes coverage counters
/// in the current process. Each nonzero counter becomes a coverage feature. With bucketing enabled,
/// the hit-count bucket is part of the feature ID, so changing loop counts can also guide search.
#[derive(Debug, Clone)]
pub struct LlvmCoverage {
    runtime: LlvmRuntime,
    counter_count: usize,
    bucketing: bool,
}

#[derive(Debug, Clone, Copy)]
struct LlvmRuntime {
    reset_counters: unsafe extern "C" fn(),
    begin_counters: unsafe extern "C" fn() -> *const u64,
    end_counters: unsafe extern "C" fn() -> *const u64,
}

impl LlvmCoverage {
    /// Initialize coverage from the current instrumented process.
    pub fn new() -> Result<Self, String> {
        let runtime = LlvmRuntime::new()?;
        let (begin, end) = runtime.counter_bounds()?;
        let counter_count = unsafe { end.offset_from(begin) };
        if counter_count <= 0 {
            return Err("LLVM coverage runtime reported no counters".to_string());
        }
        Ok(Self {
            runtime,
            counter_count: counter_count as usize,
            bucketing: true,
        })
    }

    /// Toggle hit-count bucketing. Enabled by default.
    pub fn with_bucketing(mut self, enabled: bool) -> Self {
        self.bucketing = enabled;
        self
    }
}

impl CoverageCapture for LlvmCoverage {
    type Token = LlvmToken;

    fn start_capture(&mut self) -> Result<Self::Token, String> {
        let guard = capture_lock()
            .lock()
            .map_err(|_| "LLVM coverage capture lock poisoned".to_string())?;
        self.runtime.reset_counters();
        Ok(LlvmToken { _guard: guard })
    }

    fn finish_capture(&mut self, _token: Self::Token) -> Result<CoverageSet, String> {
        counter_coverage(self.runtime, self.counter_count, self.bucketing)
    }
}

#[derive(Debug)]
pub struct LlvmToken {
    _guard: MutexGuard<'static, ()>,
}

/// Reset the process-wide LLVM coverage counters.
pub fn reset_llvm_counters() -> Result<(), String> {
    let _guard = capture_lock()
        .lock()
        .map_err(|_| "LLVM coverage capture lock poisoned".to_string())?;
    LlvmRuntime::new()?.reset_counters();
    Ok(())
}

fn capture_lock() -> &'static Mutex<()> {
    static CAPTURE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    CAPTURE_LOCK.get_or_init(|| Mutex::new(()))
}

unsafe extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

impl LlvmRuntime {
    fn new() -> Result<Self, String> {
        Ok(Self {
            reset_counters: load_symbol(c"__llvm_profile_reset_counters")?,
            begin_counters: load_symbol(c"__llvm_profile_begin_counters")?,
            end_counters: load_symbol(c"__llvm_profile_end_counters")?,
        })
    }

    fn reset_counters(self) {
        unsafe {
            (self.reset_counters)();
        }
    }

    fn counter_bounds(self) -> Result<(*const u64, *const u64), String> {
        let begin = unsafe { (self.begin_counters)() };
        let end = unsafe { (self.end_counters)() };
        if begin.is_null() || end.is_null() {
            return Err("LLVM coverage runtime returned null counter bounds".to_string());
        }
        Ok((begin, end))
    }
}

fn load_symbol<F>(symbol: &'static CStr) -> Result<F, String>
where
    F: Copy,
{
    let pointer = unsafe { dlsym(rtld_default(), symbol.as_ptr()) };
    if pointer.is_null() {
        return Err(format!(
            "LLVM coverage runtime symbol {} is unavailable; build with RUSTFLAGS=\"-Cinstrument-coverage\"",
            symbol.to_string_lossy()
        ));
    }
    Ok(unsafe { mem::transmute_copy(&pointer) })
}

#[cfg(unix)]
fn rtld_default() -> *mut c_void {
    (-2_isize) as *mut c_void
}

fn counter_coverage(
    runtime: LlvmRuntime,
    counter_count: usize,
    bucketing: bool,
) -> Result<CoverageSet, String> {
    let (begin, end) = runtime.counter_bounds()?;
    let current_count = unsafe { end.offset_from(begin) };
    if current_count < 0 || current_count as usize != counter_count {
        return Err(format!(
            "LLVM coverage counter count changed from {counter_count} to {current_count}"
        ));
    }

    let mut coverage = CoverageSet::new();
    for index in 0..counter_count {
        let counter = unsafe { std::ptr::read_volatile(begin.add(index)) };
        if counter == 0 {
            continue;
        }
        let id = if bucketing {
            ((index as u64) << 8) | u64::from(hit_count_bucket(counter))
        } else {
            index as u64
        };
        coverage.insert(CoverageId::new(id));
    }
    Ok(coverage)
}

fn hit_count_bucket(counter: u64) -> u8 {
    match counter {
        0 | 1 => 0,
        2 => 1,
        3 => 2,
        4..=7 => 3,
        8..=15 => 4,
        16..=31 => 5,
        32..=127 => 6,
        _ => 7,
    }
}
