use crate::RawFeature;
use std::{
    cell::{Cell, RefCell},
    ptr::NonNull,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

const EDGE_NAMESPACE: u64 = 0;
const CMP_NAMESPACE: u64 = 1;
const MAX_CMP_FEATURES: usize = 4096;
const MAX_DICTIONARY_VALUES: usize = 256;

/// Raw LLVM SanitizerCoverage collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sancov;

/// SanitizerCoverage capture options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SancovOptions {
    /// Include comparison callbacks as value-profile features and dictionary entries.
    pub cmp_feedback: bool,
}

impl SancovOptions {
    /// Build options with comparison feedback enabled.
    pub const fn new() -> Self {
        Self { cmp_feedback: true }
    }
}

impl Default for SancovOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of starting a SanitizerCoverage capture.
#[derive(Debug)]
pub enum SancovStart {
    /// Capture started and must be finished or discarded.
    Started(SancovSession),

    /// Inline counter capture is currently owned by another session.
    Busy,
}

/// Raw SanitizerCoverage feedback observed during one execution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SancovFeedback {
    /// Coverage and value-profile features.
    pub features: Vec<RawFeature>,

    /// Coarse execution intensity derived from edge hit counts when available.
    pub hit_count_weight: u64,

    /// Values learned from comparison feedback.
    pub dictionary: Vec<Vec<u8>>,
}

/// Active SanitizerCoverage capture session.
#[derive(Debug)]
pub struct SancovSession {
    guard: Option<CaptureGuard>,
    cmp_feedback: bool,
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
    start: NonNull<u8>,
    len: usize,
}

// SanitizerCoverage registers process-lifetime counter sections. Access is synchronized through
// `SancovState`; the pointer is only dereferenced while collecting/resetting coverage.
unsafe impl Send for CounterRange {}

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
    static GUARD_FEATURES: RefCell<Vec<RawFeature>> = const { RefCell::new(Vec::new()) };
    static CMP_FEATURES: RefCell<Vec<RawFeature>> = const { RefCell::new(Vec::new()) };
    static CMP_DICTIONARY: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

impl Sancov {
    /// Start capturing SanitizerCoverage feedback for the current thread.
    pub fn start(options: SancovOptions) -> SancovStart {
        let guard = if Self::has_trace_pc_guards() {
            None
        } else {
            let Some(guard) = try_lock_capture() else {
                return SancovStart::Busy;
            };
            Some(guard)
        };
        if guard.is_some() {
            reset_counters();
        }
        set_capture_active(false);
        clear_guard_feedback();
        clear_cmp_feedback();
        set_capture_active(true);
        SancovStart::Started(SancovSession {
            guard,
            cmp_feedback: options.cmp_feedback,
        })
    }

    /// Return whether trace-pc-guard instrumentation has registered guards.
    pub fn has_trace_pc_guards() -> bool {
        has_guards()
    }

    /// Validate that SanitizerCoverage can attribute parallel executions.
    pub fn validate_parallel() -> crate::Result<()> {
        if has_guards() {
            Ok(())
        } else {
            Err(crate::Error::new(
                "parallel SanitizerCoverage requires trace-pc-guard instrumentation; inline counters are process-global",
            ))
        }
    }
}

impl SancovSession {
    /// Finish capture and return raw feedback.
    pub fn finish(self) -> SancovFeedback {
        let Self {
            guard,
            cmp_feedback,
        } = self;
        set_capture_active(false);
        let guard_mode = has_guards();
        let mut feedback = if guard_mode {
            SancovFeedback {
                features: guard_coverage(),
                hit_count_weight: 0,
                dictionary: Vec::new(),
            }
        } else {
            counter_coverage()
        };
        if cmp_feedback {
            CMP_FEATURES.with(|features| {
                feedback.features.extend(features.borrow().iter().copied());
            });
            sort_features(&mut feedback.features);
            feedback.dictionary = cmp_dictionary_values();
        }
        if guard_mode {
            feedback.hit_count_weight = feedback.features.len() as u64;
        }
        drop(guard);
        feedback
    }

    /// Stop capture without exporting feedback.
    pub fn discard(self) {
        set_capture_active(false);
        clear_guard_feedback();
        clear_cmp_feedback();
    }
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

fn try_lock_capture() -> Option<CaptureGuard> {
    static CAPTURE_LOCK: AtomicBool = AtomicBool::new(false);
    if CAPTURE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return None;
    }
    Some(CaptureGuard(&CAPTURE_LOCK))
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

fn guard_coverage() -> Vec<RawFeature> {
    GUARD_FEATURES.with(|features| sorted_features(features.borrow().clone()))
}

fn reset_counters() {
    let Ok(state) = state().lock() else {
        return;
    };
    for range in &state.counters {
        if range.len != 0 {
            unsafe {
                std::ptr::write_bytes(range.start.as_ptr(), 0, range.len);
            }
        }
    }
}

fn counter_coverage() -> SancovFeedback {
    let Ok(state) = state().lock() else {
        return SancovFeedback::default();
    };
    let mut features = Vec::new();
    let mut hit_count_weight = 0_u64;
    let mut index = 0_u64;
    for range in &state.counters {
        let counters =
            unsafe { std::slice::from_raw_parts(range.start.as_ptr().cast_const(), range.len) };
        for counter in counters.iter().copied() {
            if counter != 0 {
                let bucket = hit_count_bucket(counter);
                features.push(feature_id(EDGE_NAMESPACE, (index << 8) | u64::from(bucket)));
                hit_count_weight = hit_count_weight.saturating_add(1 + u64::from(bucket));
            }
            index = index.wrapping_add(1);
        }
    }
    SancovFeedback {
        features: sorted_features(features),
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

fn feature_id(namespace: u64, value: u64) -> RawFeature {
    RawFeature::new((namespace << 60) | (value & 0x0fff_ffff_ffff_ffff))
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

fn sorted_features(mut features: Vec<RawFeature>) -> Vec<RawFeature> {
    sort_features(&mut features);
    features
}

fn sort_features(features: &mut Vec<RawFeature>) {
    features.sort_unstable();
    features.dedup();
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, end: *mut u8) {
    if start.is_null() || end.is_null() || start >= end {
        return;
    }
    let Ok(mut state) = state().lock() else {
        return;
    };
    let len = end.addr().saturating_sub(start.addr());
    let Some(start) = NonNull::new(start) else {
        return;
    };
    let range = CounterRange { start, len };
    if !state
        .counters
        .iter()
        .any(|existing| existing.start == range.start && existing.len == range.len)
    {
        state.counters.push(range);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __sanitizer_cov_pcs_init(_start: *const usize, _end: *const usize) {}

#[unsafe(no_mangle)]
unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(start: *mut u32, end: *mut u32) {
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
extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    record_guard(guard);
}

#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_cmp1(left: u8, right: u8) {
    record_cmp(1, u64::from(left), u64::from(right));
}

#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_cmp2(left: u16, right: u16) {
    record_cmp(2, u64::from(left), u64::from(right));
}

#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_cmp4(left: u32, right: u32) {
    record_cmp(4, u64::from(left), u64::from(right));
}

#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_cmp8(left: u64, right: u64) {
    record_cmp(8, left, right);
}

#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_const_cmp1(left: u8, right: u8) {
    record_cmp(1, u64::from(left), u64::from(right));
}

#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_const_cmp2(left: u16, right: u16) {
    record_cmp(2, u64::from(left), u64::from(right));
}

#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_const_cmp4(left: u32, right: u32) {
    record_cmp(4, u64::from(left), u64::from(right));
}

#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_const_cmp8(left: u64, right: u64) {
    record_cmp(8, left, right);
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __sanitizer_cov_trace_switch(value: u64, cases: *const u64) {
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
mod tests {
    use super::*;

    #[test]
    fn counter_feedback_records_edge_buckets() {
        let counters = Box::leak(vec![0_u8; 4].into_boxed_slice());
        let start = counters.as_mut_ptr();
        let end = unsafe { start.add(counters.len()) };
        unsafe {
            __sanitizer_cov_8bit_counters_init(start, end);
        }

        let session = start_sancov_capture(SancovOptions {
            cmp_feedback: false,
        });
        unsafe {
            start.add(1).write(1);
            start.add(2).write(9);
        }
        let feedback = session.finish();

        assert!(
            feedback.features.len() >= 2,
            "two nonzero sanitizer counters should produce edge features"
        );
        assert!(
            feedback.features.iter().any(|id| id.raw() >> 60 == 0),
            "edge counter features should use the edge namespace"
        );
        assert!(
            feedback.hit_count_weight >= 6,
            "hit-count weight should include nonzero counter bucket weights"
        );
    }

    #[test]
    fn comparison_feedback_records_features_and_dictionary_values() {
        let session = start_sancov_capture(SancovOptions::new());
        __sanitizer_cov_trace_cmp1(0x41, 0x42);
        let feedback = session.finish();

        assert!(
            feedback.features.iter().any(|id| id.raw() >> 60 == 1),
            "comparison callbacks should contribute value-profile features"
        );
        assert!(feedback.dictionary.contains(&vec![0x41]));
        assert!(feedback.dictionary.contains(&vec![0x42]));
    }

    #[test]
    fn switch_feedback_records_all_case_values() {
        let session = start_sancov_capture(SancovOptions::new());
        let cases = [2_u64, 8, 0x41, 0x42];
        unsafe {
            __sanitizer_cov_trace_switch(0x40, cases.as_ptr());
        }
        let feedback = session.finish();

        assert!(
            feedback.features.iter().any(|id| id.raw() >> 60 == 1),
            "switch callbacks should contribute value-profile features"
        );
        assert!(feedback.dictionary.contains(&vec![0x41]));
        assert!(feedback.dictionary.contains(&vec![0x42]));
    }

    fn start_sancov_capture(options: SancovOptions) -> SancovSession {
        loop {
            match Sancov::start(options) {
                SancovStart::Started(session) => return session,
                SancovStart::Busy => std::thread::yield_now(),
            }
        }
    }
}
