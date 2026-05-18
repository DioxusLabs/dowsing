use crate::coverage::{CaptureStart, CoverageCapture, CoverageId, CoverageSet, ExecutionFeedback};
use std::{
    ffi::{CStr, c_char, c_void},
    mem,
    sync::atomic::{AtomicBool, Ordering},
};

/// In-process LLVM counter coverage for `curious()` and `cautious()`.
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
    counters: LlvmCounters,
}

#[derive(Debug, Clone, Copy)]
enum LlvmCounters {
    RuntimeFunctions {
        reset_counters: unsafe extern "C" fn(),
        begin_counters: unsafe extern "C" fn() -> *const u64,
        end_counters: unsafe extern "C" fn() -> *const u64,
    },
    #[cfg(target_os = "macos")]
    MachOSection { begin: *mut u64, end: *mut u64 },
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
    type Session = LlvmSession;

    fn start_capture(&mut self) -> Result<CaptureStart<Self::Session>, String> {
        let Some(guard) = try_lock_capture() else {
            return Ok(CaptureStart::Busy);
        };
        self.runtime.reset_counters();
        Ok(CaptureStart::Started(LlvmSession { _guard: guard }))
    }

    fn finish_capture(&mut self, _session: Self::Session) -> Result<ExecutionFeedback, String> {
        counter_coverage(self.runtime, self.counter_count, self.bucketing)
    }
}

#[derive(Debug)]
pub struct LlvmSession {
    _guard: CaptureGuard,
}

#[derive(Debug)]
struct CaptureGuard(&'static AtomicBool);

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Reset the process-wide LLVM coverage counters.
pub fn reset_llvm_counters() -> Result<(), String> {
    let _guard = wait_for_capture_lock();
    LlvmRuntime::new()?.reset_counters();
    Ok(())
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

fn wait_for_capture_lock() -> CaptureGuard {
    loop {
        if let Some(guard) = try_lock_capture() {
            return guard;
        }
        std::thread::yield_now();
    }
}
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

impl LlvmRuntime {
    fn new() -> Result<Self, String> {
        #[cfg(target_os = "macos")]
        if let Some(counters) = macos_profile_counters() {
            return Ok(Self { counters });
        }

        Ok(Self {
            counters: LlvmCounters::RuntimeFunctions {
                reset_counters: load_symbol(c"__llvm_profile_reset_counters")?,
                begin_counters: load_symbol(c"__llvm_profile_begin_counters")?,
                end_counters: load_symbol(c"__llvm_profile_end_counters")?,
            },
        })
    }

    fn reset_counters(self) {
        match self.counters {
            LlvmCounters::RuntimeFunctions { reset_counters, .. } => unsafe {
                reset_counters();
            },
            #[cfg(target_os = "macos")]
            LlvmCounters::MachOSection { begin, end } => {
                let len = unsafe { end.offset_from(begin) };
                if len > 0 {
                    unsafe {
                        std::ptr::write_bytes(begin, 0, len as usize);
                    }
                }
            }
        }
    }

    fn counter_bounds(self) -> Result<(*const u64, *const u64), String> {
        let (begin, end) = match self.counters {
            LlvmCounters::RuntimeFunctions {
                begin_counters,
                end_counters,
                ..
            } => unsafe { (begin_counters(), end_counters()) },
            #[cfg(target_os = "macos")]
            LlvmCounters::MachOSection { begin, end } => (begin.cast_const(), end.cast_const()),
        };
        if begin.is_null() || end.is_null() {
            return Err("LLVM coverage runtime returned null counter bounds".to_string());
        }
        Ok((begin, end))
    }
}

#[cfg(target_os = "macos")]
fn macos_profile_counters() -> Option<LlvmCounters> {
    let image_count = unsafe { _dyld_image_count() };
    for image_index in 0..image_count {
        let header = unsafe { _dyld_get_image_header(image_index) };
        if header.is_null() || unsafe { (*header).magic } != MH_MAGIC_64 {
            continue;
        }
        let slide = unsafe { _dyld_get_image_vmaddr_slide(image_index) };
        let Some((begin, end)) = (unsafe { macho_profile_counter_section(header, slide) }) else {
            continue;
        };
        if begin < end {
            return Some(LlvmCounters::MachOSection { begin, end });
        }
    }
    None
}

#[cfg(target_os = "macos")]
unsafe fn macho_profile_counter_section(
    header: *const MachHeader64,
    slide: isize,
) -> Option<(*mut u64, *mut u64)> {
    let mut command = unsafe { header.add(1).cast::<LoadCommand>() };
    for _ in 0..unsafe { (*header).ncmds } {
        if unsafe { (*command).cmd } == LC_SEGMENT_64 {
            let segment = command.cast::<SegmentCommand64>();
            let mut section = unsafe { segment.add(1).cast::<Section64>() };
            for _ in 0..unsafe { (*segment).nsects } {
                if fixed_name_eq(unsafe { &(*section).sectname }, b"__llvm_prf_cnts") {
                    let addr = unsafe { (*section).addr };
                    let size = unsafe { (*section).size };
                    if size != 0 && size % mem::size_of::<u64>() as u64 == 0 {
                        let begin = (addr.wrapping_add(slide as u64)) as *mut u64;
                        let end = unsafe { begin.add(size as usize / mem::size_of::<u64>()) };
                        return Some((begin, end));
                    }
                }
                section = unsafe { section.add(1) };
            }
        }
        command = unsafe { (command.cast::<u8>()).add((*command).cmdsize as usize) }
            .cast::<LoadCommand>();
    }
    None
}

#[cfg(target_os = "macos")]
fn fixed_name_eq(fixed: &[c_char; 16], expected: &[u8]) -> bool {
    let len = fixed
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(fixed.len());
    len == expected.len()
        && fixed[..len]
            .iter()
            .map(|byte| *byte as u8)
            .eq(expected.iter().copied())
}

#[cfg(target_os = "macos")]
const MH_MAGIC_64: u32 = 0xfeed_facf;
#[cfg(target_os = "macos")]
const LC_SEGMENT_64: u32 = 0x19;

#[cfg(target_os = "macos")]
#[repr(C)]
struct MachHeader64 {
    magic: u32,
    cputype: i32,
    cpusubtype: i32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct LoadCommand {
    cmd: u32,
    cmdsize: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct SegmentCommand64 {
    cmd: u32,
    cmdsize: u32,
    segname: [c_char; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: i32,
    initprot: i32,
    nsects: u32,
    flags: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct Section64 {
    sectname: [c_char; 16],
    segname: [c_char; 16],
    addr: u64,
    size: u64,
    offset: u32,
    align: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_header(image_index: u32) -> *const MachHeader64;
    fn _dyld_get_image_vmaddr_slide(image_index: u32) -> isize;
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
) -> Result<ExecutionFeedback, String> {
    let (begin, end) = runtime.counter_bounds()?;
    let current_count = unsafe { end.offset_from(begin) };
    if current_count < 0 || current_count as usize != counter_count {
        return Err(format!(
            "LLVM coverage counter count changed from {counter_count} to {current_count}"
        ));
    }

    let mut coverage = CoverageSet::new();
    let mut hit_count_weight = 0_u64;
    for index in 0..counter_count {
        let counter = unsafe { std::ptr::read_volatile(begin.add(index)) };
        if counter == 0 {
            continue;
        }
        let bucket = hit_count_bucket(counter);
        let id = if bucketing {
            ((index as u64) << 8) | u64::from(bucket)
        } else {
            index as u64
        };
        coverage.insert(CoverageId::new(id));
        hit_count_weight = hit_count_weight.saturating_add(1 + u64::from(bucket));
    }
    Ok(ExecutionFeedback {
        features: coverage,
        hit_count_weight,
        dictionary: Vec::new(),
    })
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
