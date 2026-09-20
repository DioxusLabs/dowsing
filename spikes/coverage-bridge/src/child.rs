//! Target-side runtime: forkserver loop, per-case replay, and export into shared memory.
//!
//! The target binary calls [`serve`] from `main` when it detects the bridge environment. In
//! fork mode the process maps the region once, reports a hello on the status pipe, and then
//! forks one short-lived child per request; that child replays the supplied byte budget through
//! an ordinary `CaseRng<NoCoverage>`, runs the harness once, exports everything, and `_exit`s.

use crate::{
    CTL_FD, ChildMode, REQUEST_EXIT, SHM_FD, STATUS_FD, Verdict,
    shm::{
        self, CASE_FLAG_CMP_FEEDBACK, HELLO_INSTRUMENTED, ItemRec, MAGIC, OVERFLOW_COUNTERS,
        OVERFLOW_DICT, OVERFLOW_DRAWS, OVERFLOW_FEATURES, OVERFLOW_INPUT, OVERFLOW_ITEMS,
        OVERFLOW_SEMANTICS, OVERFLOW_SEQUENCES, Region, STATE_CRASHED, STATE_DONE, STATE_STARTED,
        SequenceRec, SpanRec, VERDICT_FAILED, VERDICT_OK, VERDICT_PANICKED,
    },
};
use iterator_fuzz::{
    Case, CaseRng, NoCoverage,
    backends::SancovCoverage,
    coverage::{CoverageCapture, ExecutionFeedback},
    raw::{RawCase, sancov_counter_ranges},
};
use std::{
    io::{self, Read, Write},
    os::fd::FromRawFd,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};

/// Harness signature: run one case against `rng` and report how it went.
pub trait Harness {
    fn run(&mut self, rng: &mut CaseRng<NoCoverage>) -> Verdict;
}

impl<F: FnMut(&mut CaseRng<NoCoverage>) -> Verdict> Harness for F {
    fn run(&mut self, rng: &mut CaseRng<NoCoverage>) -> Verdict {
        self(rng)
    }
}

/// Serve cases for the supervisor until it asks us to stop. Never returns.
///
/// Panics if the process was not started by a supervisor (see [`ChildMode::from_env`]).
pub fn serve<H: Harness>(harness: H) -> ! {
    let mode = ChildMode::from_env().expect("coverage-bridge: not started by a supervisor");
    match serve_mode(mode, harness) {
        Ok(()) => unsafe { libc::_exit(0) },
        Err(err) => {
            let _ = writeln!(io::stderr(), "coverage-bridge child: {err}");
            unsafe { libc::_exit(2) }
        }
    }
}

fn serve_mode<H: Harness>(mode: ChildMode, mut harness: H) -> io::Result<()> {
    let mut region = Region::open(SHM_FD)?;
    let ranges = sancov_counter_ranges();
    install_crash_handlers(&region, &ranges);

    match mode {
        ChildMode::Exec => {
            run_case(&mut region, &ranges, &mut harness);
            Ok(())
        }
        ChildMode::Fork => {
            let mut ctl = unsafe { std::fs::File::from_raw_fd(CTL_FD) };
            let mut status = unsafe { std::fs::File::from_raw_fd(STATUS_FD) };
            let flags = if ranges.is_empty() {
                0
            } else {
                HELLO_INSTRUMENTED
            };
            status.write_all(&MAGIC.to_le_bytes())?;
            status.write_all(&flags.to_le_bytes())?;

            loop {
                let mut request = [0u8; 4];
                if let Err(err) = ctl.read_exact(&mut request) {
                    if err.kind() == io::ErrorKind::UnexpectedEof {
                        return Ok(());
                    }
                    return Err(err);
                }
                if u32::from_le_bytes(request) == REQUEST_EXIT {
                    return Ok(());
                }

                let pid = unsafe { libc::fork() };
                if pid < 0 {
                    return Err(io::Error::last_os_error());
                }
                if pid == 0 {
                    // Case children must not outlive the forkserver (a spinning case whose
                    // supervisor died would otherwise be reparented to init and run forever).
                    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
                    if unsafe { libc::getppid() } == 1 {
                        unsafe { libc::_exit(0) }
                    }
                    drop(ctl);
                    drop(status);
                    run_case(&mut region, &ranges, &mut harness);
                    unsafe { libc::_exit(0) }
                }
                status.write_all(&(pid as u32).to_le_bytes())?;
                let mut wait_status = 0;
                loop {
                    let waited = unsafe { libc::waitpid(pid, &mut wait_status, 0) };
                    if waited == pid {
                        break;
                    }
                    if waited < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                    {
                        continue;
                    }
                    return Err(io::Error::last_os_error());
                }
                status.write_all(&(wait_status as u32).to_le_bytes())?;
            }
        }
    }
}

fn run_case<H: Harness>(region: &mut Region, ranges: &[(usize, usize)], harness: &mut H) {
    let profile = std::env::var_os("COVERAGE_BRIDGE_PROFILE").is_some();
    let t0 = std::time::Instant::now();
    let mut header = region.header();
    header.state = STATE_STARTED;
    region.write_header(&header);

    let mut capture = if ranges.is_empty() {
        // Uninstrumented builds still get an empty (but valid) capture so the flow is identical.
        None
    } else {
        Some(
            SancovCoverage::new()
                .with_cmp_feedback(header.case_flags & CASE_FLAG_CMP_FEEDBACK != 0),
        )
    };
    let token = capture
        .as_mut()
        .map(|capture| capture.start_capture().expect("sancov capture"));

    let input_len = (header.input_len as usize).min(region.layout().caps.input);
    let case = Case::from_raw(RawCase {
        seed: header.seed,
        prefix: region.input()[..input_len].to_vec(),
        zero_tail: true,
        draws: Vec::new(),
        semantics: Vec::new(),
        sequences: Vec::new(),
    });
    let mut rng = case.replay();
    let t1 = std::time::Instant::now();
    let verdict = catch_unwind(AssertUnwindSafe(|| harness.run(&mut rng)));
    let t2 = std::time::Instant::now();
    let raw = rng.fork_case().into_raw();
    rng.discard();

    // Snapshot raw counters first so the decoded export below describes exactly these bytes.
    let counters_len = copy_counters(region, ranges);
    let t3 = std::time::Instant::now();
    let feedback = match (capture.as_mut(), token) {
        (Some(capture), Some(token)) => capture
            .finish_capture(token)
            .unwrap_or_else(|_| ExecutionFeedback::default()),
        _ => ExecutionFeedback::default(),
    };
    let t4 = std::time::Instant::now();

    let mut header = region.header();
    header.consumed = raw.prefix.len() as u32;
    if raw.prefix.len() > input_len {
        header.overflow |= OVERFLOW_INPUT;
    }
    header.counters_len = counters_len.0 as u32;
    if counters_len.1 {
        header.overflow |= OVERFLOW_COUNTERS;
    }
    match verdict {
        Ok(verdict) => {
            header.verdict = if verdict.failed {
                VERDICT_FAILED
            } else {
                VERDICT_OK
            };
            header.cost = verdict.cost;
        }
        Err(_) => {
            header.verdict = VERDICT_PANICKED;
            header.cost = 0;
        }
    }
    export_spans(region, &raw, &mut header);
    export_feedback(region, &feedback, &mut header);
    header.state = STATE_DONE;
    region.write_header(&header);
    if profile {
        eprintln!(
            "child profile: start {:?}, harness {:?}, counters copy {:?} ({} bytes), decode {:?} ({} features), export {:?}",
            t1 - t0,
            t2 - t1,
            t3 - t2,
            counters_len.0,
            t4 - t3,
            feedback.features().len(),
            t4.elapsed()
        );
    }
}

fn copy_counters(region: &mut Region, ranges: &[(usize, usize)]) -> (usize, bool) {
    let cap = region.layout().caps.counters;
    let out = region.counters_mut();
    let mut written = 0;
    let mut overflow = false;
    for (start, end) in ranges {
        let len = end.saturating_sub(*start);
        let take = len.min(cap - written);
        if take < len {
            overflow = true;
        }
        if take > 0 {
            unsafe {
                ptr::copy_nonoverlapping(*start as *const u8, out[written..].as_mut_ptr(), take);
            }
            written += take;
        }
    }
    (written, overflow)
}

fn export_spans(region: &mut Region, raw: &RawCase, header: &mut shm::Header) {
    let caps = *region.layout();

    let n_draws = raw.draws.len().min(caps.caps.spans);
    if n_draws < raw.draws.len() {
        header.overflow |= OVERFLOW_DRAWS;
    }
    for (slot, span) in region.draws_mut().iter_mut().zip(&raw.draws[..n_draws]) {
        *slot = SpanRec {
            start: span.start as u32,
            len: span.len as u32,
            kind: u32::from(span.kind),
            _pad: 0,
        };
    }
    header.n_draws = n_draws as u32;

    let n_semantics = raw.semantics.len().min(caps.caps.spans);
    if n_semantics < raw.semantics.len() {
        header.overflow |= OVERFLOW_SEMANTICS;
    }
    for (slot, span) in region
        .semantics_mut()
        .iter_mut()
        .zip(&raw.semantics[..n_semantics])
    {
        *slot = SpanRec {
            start: span.start as u32,
            len: span.len as u32,
            kind: u32::from(span.kind),
            _pad: 0,
        };
    }
    header.n_semantics = n_semantics as u32;

    let mut n_sequences = 0;
    let mut n_items = 0;
    for sequence in &raw.sequences {
        if n_sequences >= caps.caps.sequences {
            header.overflow |= OVERFLOW_SEQUENCES;
            break;
        }
        if n_items + sequence.items.len() > caps.caps.items {
            header.overflow |= OVERFLOW_ITEMS;
            break;
        }
        region.sequences_mut()[n_sequences] = SequenceRec {
            length_start: sequence.length_start as u32,
            length_len: sequence.length_len as u32,
            items_start: n_items as u32,
            items_len: sequence.items.len() as u32,
        };
        for (slot, (start, len)) in region.items_mut()[n_items..]
            .iter_mut()
            .zip(&sequence.items)
        {
            *slot = ItemRec {
                start: *start as u32,
                len: *len as u32,
            };
        }
        n_items += sequence.items.len();
        n_sequences += 1;
    }
    header.n_sequences = n_sequences as u32;
    header.n_items = n_items as u32;
}

fn export_feedback(region: &mut Region, feedback: &ExecutionFeedback, header: &mut shm::Header) {
    let caps = region.layout().caps;
    let mut n_features = 0;
    {
        let out = region.features_mut();
        for id in feedback.features().iter() {
            if n_features >= caps.features {
                header.overflow |= OVERFLOW_FEATURES;
                break;
            }
            out[n_features] = id.raw();
            n_features += 1;
        }
    }
    header.n_features = n_features as u32;
    header.hit_count_weight = feedback.hit_count_weight();

    let mut n_dict = 0;
    let mut dict_bytes = 0;
    for value in feedback.dictionary() {
        if n_dict >= caps.dict || dict_bytes + value.len() > caps.dict_bytes {
            header.overflow |= OVERFLOW_DICT;
            break;
        }
        region.dict_lens_mut()[n_dict] = value.len() as u32;
        region.dict_bytes_mut()[dict_bytes..dict_bytes + value.len()].copy_from_slice(value);
        dict_bytes += value.len();
        n_dict += 1;
    }
    header.n_dict = n_dict as u32;
    header.dict_bytes = dict_bytes as u32;
}

// ---- crash path -------------------------------------------------------------------------
//
// If the harness dies from a signal the normal export never runs. A signal handler copies the
// raw counters into the region (memcpy only, async-signal-safe), stamps the header, restores
// the default disposition and re-raises so the forkserver sees the real termination status.

static CRASH_HEADER: AtomicPtr<shm::Header> = AtomicPtr::new(ptr::null_mut());
static CRASH_COUNTERS: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static CRASH_COUNTERS_CAP: AtomicUsize = AtomicUsize::new(0);
static CRASH_RANGES: AtomicPtr<(usize, usize)> = AtomicPtr::new(ptr::null_mut());
static CRASH_RANGES_LEN: AtomicUsize = AtomicUsize::new(0);

const CRASH_SIGNALS: [libc::c_int; 6] = [
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGABRT,
    libc::SIGFPE,
    libc::SIGILL,
    libc::SIGTRAP,
];

fn install_crash_handlers(region: &Region, ranges: &[(usize, usize)]) {
    CRASH_HEADER.store(region.header_ptr(), Ordering::SeqCst);
    CRASH_COUNTERS.store(region.counters_ptr(), Ordering::SeqCst);
    CRASH_COUNTERS_CAP.store(region.layout().caps.counters, Ordering::SeqCst);
    let leaked: &'static [(usize, usize)] = Box::leak(ranges.to_vec().into_boxed_slice());
    CRASH_RANGES.store(leaked.as_ptr() as *mut _, Ordering::SeqCst);
    CRASH_RANGES_LEN.store(leaked.len(), Ordering::SeqCst);

    unsafe {
        // Alternate stack so stack overflows still reach the handler.
        let size = 64 * 1024;
        let stack = libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if stack != libc::MAP_FAILED {
            let alt = libc::stack_t {
                ss_sp: stack,
                ss_flags: 0,
                ss_size: size,
            };
            libc::sigaltstack(&alt, ptr::null_mut());
        }
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = crash_handler as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in CRASH_SIGNALS {
            libc::sigaction(signal, &action, ptr::null_mut());
        }
    }
}

extern "C" fn crash_handler(
    signal: libc::c_int,
    _info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    unsafe {
        let header = CRASH_HEADER.load(Ordering::SeqCst);
        if !header.is_null() {
            let out = CRASH_COUNTERS.load(Ordering::SeqCst);
            let cap = CRASH_COUNTERS_CAP.load(Ordering::SeqCst);
            let ranges = CRASH_RANGES.load(Ordering::SeqCst);
            let n = CRASH_RANGES_LEN.load(Ordering::SeqCst);
            let mut written = 0;
            for index in 0..n {
                let (start, end) = *ranges.add(index);
                let len = end.saturating_sub(start).min(cap - written);
                if len > 0 {
                    ptr::copy_nonoverlapping(start as *const u8, out.add(written), len);
                    written += len;
                }
            }
            ptr::write_volatile(&raw mut (*header).counters_len, written as u32);
            ptr::write_volatile(&raw mut (*header).crash_signal, signal as u32);
            ptr::write_volatile(&raw mut (*header).state, STATE_CRASHED);
        }
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}
