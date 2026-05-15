use crate::{
    CoverageCapture, CoverageId, CoverageSet, ExecutionFeedback, ParallelCoverageCapture,
    coverage::CAPTURE_BUSY,
};
use std::{
    cell::{Cell, RefCell},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

const EDGE_NAMESPACE: u64 = 0;
const CMP_NAMESPACE: u64 = 1;
const MAX_CMP_FEATURES: usize = 4096;
const MAX_DICTIONARY_VALUES: usize = 256;

/// In-process LLVM SanitizerCoverage feedback for `curious()` and `cautious()`.
///
/// Build the harness with `-Cpasses=sancov-module` plus LLVM sanitizer-coverage arguments so
/// LLVM emits edge feedback and comparison callbacks. Native parallel iteration requires
/// trace-pc-guard edge feedback; inline counters are process-global and are used serially.
#[derive(Debug, Clone, Copy, Default)]
pub struct SancovCoverage {
    cmp_feedback: bool,
}

#[derive(Debug)]
pub struct SancovToken {
    _guard: Option<CaptureGuard>,
}

#[derive(Debug)]
struct CaptureGuard(&'static AtomicBool);

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Debug, Clone, Copy)]
struct CounterRange {
    start: usize,
    end: usize,
}

#[derive(Debug, Default)]
struct SancovState {
    counters: Vec<CounterRange>,
    has_guards: bool,
    next_guard: u32,
}

thread_local! {
    static IN_CALLBACK: Cell<bool> = const { Cell::new(false) };
    static CAPTURE_ACTIVE: Cell<bool> = const { Cell::new(false) };
    static GUARD_EPOCH: Cell<u32> = const { Cell::new(1) };
    static GUARD_SEEN: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    static GUARD_FEATURES: RefCell<Vec<CoverageId>> = const { RefCell::new(Vec::new()) };
    static CMP_FEATURES: RefCell<Vec<CoverageId>> = const { RefCell::new(Vec::new()) };
    static CMP_DICTIONARY: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

impl SancovCoverage {
    /// Create a SanitizerCoverage backend. If the binary is not instrumented, it yields empty
    /// coverage instead of failing so the fuzzing constructors remain simple.
    pub fn new() -> Self {
        Self { cmp_feedback: true }
    }

    /// Toggle comparison feedback. Enabled by default.
    pub fn with_cmp_feedback(mut self, enabled: bool) -> Self {
        self.cmp_feedback = enabled;
        self
    }
}

impl CoverageCapture for SancovCoverage {
    type Token = SancovToken;

    fn start_capture(&mut self) -> Result<Self::Token, String> {
        let guard = if has_guards() {
            None
        } else {
            Some(try_lock_capture()?)
        };
        if guard.is_some() {
            reset_counters();
        }
        set_capture_active(false);
        clear_guard_feedback();
        clear_cmp_feedback();
        set_capture_active(true);
        Ok(SancovToken { _guard: guard })
    }

    fn finish_capture(&mut self, _token: Self::Token) -> Result<ExecutionFeedback, String> {
        set_capture_active(false);
        let guard_mode = has_guards();
        let mut feedback = if guard_mode {
            ExecutionFeedback::from_features(guard_coverage())
        } else {
            counter_coverage()
        };
        if self.cmp_feedback {
            CMP_FEATURES
                .with(|features| feedback.features.extend(features.borrow().iter().copied()));
            feedback.dictionary = cmp_dictionary_values();
        }
        if guard_mode {
            feedback.hit_count_weight = feedback.features.len() as u64;
        }
        Ok(feedback)
    }

    fn discard_capture(&mut self, _token: Self::Token) -> Result<(), String> {
        set_capture_active(false);
        clear_guard_feedback();
        clear_cmp_feedback();
        Ok(())
    }
}

impl ParallelCoverageCapture for SancovCoverage {
    fn validate_parallel(&self) -> Result<(), String> {
        if has_guards() {
            Ok(())
        } else {
            Err(
                "parallel SanitizerCoverage requires trace-pc-guard instrumentation; inline counters are process-global"
                    .to_string(),
            )
        }
    }
}

#[cfg(test)]
pub(crate) fn has_trace_pc_guards() -> bool {
    has_guards()
}

fn cmp_dictionary_values() -> Vec<Vec<u8>> {
    suppress_callbacks(|| CMP_DICTIONARY.with(|dictionary| dictionary.borrow().clone()))
}

struct CallbackSuppression {
    previous: bool,
}

impl Drop for CallbackSuppression {
    fn drop(&mut self) {
        IN_CALLBACK.with(|active| active.set(self.previous));
    }
}

fn suppress_callbacks<T>(f: impl FnOnce() -> T) -> T {
    IN_CALLBACK.with(|active| {
        let guard = CallbackSuppression {
            previous: active.replace(true),
        };
        let result = f();
        drop(guard);
        result
    })
}

fn set_capture_active(active: bool) {
    CAPTURE_ACTIVE.with(|capture| capture.set(active));
}

fn state() -> &'static Mutex<SancovState> {
    static STATE: OnceLock<Mutex<SancovState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(SancovState::default()))
}

fn try_lock_capture() -> Result<CaptureGuard, String> {
    static CAPTURE_LOCK: AtomicBool = AtomicBool::new(false);
    if CAPTURE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(CAPTURE_BUSY.to_string());
    }
    Ok(CaptureGuard(&CAPTURE_LOCK))
}

fn has_guards() -> bool {
    state().lock().is_ok_and(|state| state.has_guards)
}

fn clear_guard_feedback() {
    GUARD_EPOCH.with(|epoch| {
        let current = epoch.get();
        let next = current.wrapping_add(1);
        if next == 0 {
            GUARD_SEEN.with(|seen| seen.borrow_mut().fill(0));
            epoch.set(1);
        } else {
            epoch.set(next);
        }
    });
    GUARD_FEATURES.with(|features| features.borrow_mut().clear());
}

fn guard_coverage() -> CoverageSet {
    GUARD_FEATURES.with(|features| CoverageSet::from_unsorted(features.borrow().clone()))
}

fn reset_counters() {
    let Ok(state) = state().lock() else {
        return;
    };
    for range in &state.counters {
        let len = range.end.saturating_sub(range.start);
        if len != 0 {
            unsafe {
                std::ptr::write_bytes(range.start as *mut u8, 0, len);
            }
        }
    }
}

fn counter_coverage() -> ExecutionFeedback {
    let Ok(state) = state().lock() else {
        return ExecutionFeedback::default();
    };
    let mut ids = Vec::new();
    let mut hit_count_weight = 0_u64;
    let mut index = 0_u64;
    for range in &state.counters {
        let len = range.end.saturating_sub(range.start);
        let counters = unsafe { std::slice::from_raw_parts(range.start as *const u8, len) };
        for counter in counters.iter().copied() {
            if counter != 0 {
                let bucket = hit_count_bucket(counter);
                ids.push(feature_id(EDGE_NAMESPACE, (index << 8) | u64::from(bucket)));
                hit_count_weight = hit_count_weight.saturating_add(1 + u64::from(bucket));
            }
            index = index.wrapping_add(1);
        }
    }
    ExecutionFeedback {
        features: CoverageSet::from_unsorted(ids),
        hit_count_weight,
        dictionary: Vec::new(),
    }
}

fn clear_cmp_feedback() {
    CMP_FEATURES.with(|features| features.borrow_mut().clear());
    CMP_DICTIONARY.with(|dictionary| dictionary.borrow_mut().clear());
}

fn record_cmp(width: u8, left: u64, right: u64) {
    if !CAPTURE_ACTIVE.with(|active| active.get()) {
        return;
    }
    IN_CALLBACK.with(|active| {
        if active.replace(true) {
            return;
        }
        CMP_FEATURES.with(|features| {
            let mut features = features.borrow_mut();
            if features.len() < MAX_CMP_FEATURES {
                features.push(feature_id(CMP_NAMESPACE, cmp_hash(width, left, right)));
            }
        });
        CMP_DICTIONARY.with(|dictionary| {
            let mut dictionary = dictionary.borrow_mut();
            push_dictionary_value(&mut dictionary, left, width);
            push_dictionary_value(&mut dictionary, right, width);
        });
        active.set(false);
    });
}

fn record_guard(guard: *mut u32) {
    if !CAPTURE_ACTIVE.with(|active| active.get()) {
        return;
    }
    if guard.is_null() {
        return;
    }
    let id = unsafe { guard.read() };
    if id == 0 {
        return;
    }

    IN_CALLBACK.with(|active| {
        if active.replace(true) {
            return;
        }
        GUARD_EPOCH.with(|epoch| {
            let stamp = epoch.get();
            GUARD_SEEN.with(|seen| {
                let mut seen = seen.borrow_mut();
                let index = id as usize;
                if seen.len() <= index {
                    seen.resize(index + 1, 0);
                }
                if seen[index] == stamp {
                    return;
                }
                seen[index] = stamp;
                GUARD_FEATURES.with(|features| {
                    features
                        .borrow_mut()
                        .push(feature_id(EDGE_NAMESPACE, u64::from(id)));
                });
            });
        });
        active.set(false);
    });
}

fn push_dictionary_value(dictionary: &mut Vec<Vec<u8>>, value: u64, width: u8) {
    if dictionary.len() >= MAX_DICTIONARY_VALUES {
        return;
    }
    let bytes = value.to_le_bytes();
    let bytes = bytes[..usize::from(width)].to_vec();
    if bytes.iter().all(|byte| *byte == 0) || dictionary.iter().any(|existing| existing == &bytes) {
        return;
    }
    dictionary.push(bytes);
}

fn feature_id(namespace: u64, value: u64) -> CoverageId {
    CoverageId::new((namespace << 60) | (value & 0x0fff_ffff_ffff_ffff))
}

fn cmp_hash(width: u8, left: u64, right: u64) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in width
        .to_le_bytes()
        .into_iter()
        .chain(left.to_le_bytes())
        .chain(right.to_le_bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

fn hit_count_bucket(counter: u8) -> u8 {
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, end: *mut u8) {
    if start.is_null() || end.is_null() || start >= end {
        return;
    }
    let Ok(mut state) = state().lock() else {
        return;
    };
    let range = CounterRange {
        start: start as usize,
        end: end as usize,
    };
    if !state
        .counters
        .iter()
        .any(|existing| existing.start == range.start && existing.end == range.end)
    {
        state.counters.push(range);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_pcs_init(_start: *const usize, _end: *const usize) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(start: *mut u32, end: *mut u32) {
    if start.is_null() || end.is_null() || start >= end {
        return;
    }
    if unsafe { start.read() } != 0 {
        return;
    }

    let Ok(mut state) = state().lock() else {
        return;
    };
    state.has_guards = true;
    if state.next_guard == 0 {
        state.next_guard = 1;
    }
    let mut current = start;
    while current < end {
        unsafe {
            current.write(state.next_guard);
            current = current.add(1);
        }
        state.next_guard = state.next_guard.wrapping_add(1).max(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    record_guard(guard);
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_cmp1(left: u8, right: u8) {
    record_cmp(1, u64::from(left), u64::from(right));
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_cmp2(left: u16, right: u16) {
    record_cmp(2, u64::from(left), u64::from(right));
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_cmp4(left: u32, right: u32) {
    record_cmp(4, u64::from(left), u64::from(right));
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_cmp8(left: u64, right: u64) {
    record_cmp(8, left, right);
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_const_cmp1(left: u8, right: u8) {
    record_cmp(1, u64::from(left), u64::from(right));
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_const_cmp2(left: u16, right: u16) {
    record_cmp(2, u64::from(left), u64::from(right));
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_const_cmp4(left: u32, right: u32) {
    record_cmp(4, u64::from(left), u64::from(right));
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_const_cmp8(left: u64, right: u64) {
    record_cmp(8, left, right);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_switch(value: u64, cases: *const u64) {
    if cases.is_null() {
        return;
    }
    let count = unsafe { cases.read_unaligned() as usize };
    let bit_width = unsafe { cases.add(1).read_unaligned() };
    let width = match bit_width {
        0..=8 => 1,
        9..=16 => 2,
        17..=32 => 4,
        _ => 8,
    };
    for index in 0..count.min(MAX_CMP_FEATURES) {
        let case = unsafe { cases.add(2 + index).read_unaligned() };
        record_cmp(width, value, case);
    }
}

#[cfg(test)]
pub(crate) fn test_record_cmp(width: u8, left: u64, right: u64) {
    record_cmp(width, left, right);
}
