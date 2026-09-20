//! Coverage across the fork boundary.
//!
//! The child runs the target under the root crate's `SancovCoverage` (its inline 8-bit counters
//! / guards and cmp callbacks are process-global, so the forked copy sees exactly the target's
//! edges) and serialises the resulting `ExecutionFeedback` into a `MAP_SHARED` anonymous region
//! created before fork. The parent's `ChildCoverage` implements `CoverageCapture` by reading it
//! back. No root-crate change is needed: `CoverageId::new`, `CoverageSet` and
//! `ExecutionFeedback::new` are public.

use std::{io, ptr, sync::Arc};

use iterator_fuzz::{
    backends::SancovCoverage,
    coverage::{CoverageCapture, CoverageId, CoverageSet, ExecutionFeedback},
};

const MAGIC: u32 = 0xC0FF_EE01;
const HEADER: usize = 32;

struct Region {
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    fn new(len: usize) -> io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            ptr: ptr as *mut u8,
            len,
        })
    }

    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// The region is shared with a child process; the parent only writes while no child runs.
    #[allow(clippy::mut_from_ref)]
    fn bytes_mut(&self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

/// `CoverageCapture` backend fed by the forked child. Clone it to share one region between the
/// `Sandbox` (which writes from the child) and the dowsing engine (which reads in the parent).
#[derive(Clone)]
pub struct ChildCoverage {
    region: Arc<Region>,
}

/// What the child reports back besides coverage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChildReport {
    pub panic_message: Option<String>,
    pub feature_count: usize,
}

impl ChildCoverage {
    pub fn new() -> io::Result<Self> {
        Self::with_capacity(4 << 20)
    }

    pub fn with_capacity(bytes: usize) -> io::Result<Self> {
        Ok(Self {
            region: Arc::new(Region::new(bytes)?),
        })
    }

    pub fn reset(&self) {
        self.region.bytes_mut()[..HEADER].fill(0);
    }

    /// Child side: run `f` under sancov capture and publish its feedback (plus the panic
    /// message, if any) into the shared region. Returns `true` if `f` panicked.
    pub fn child_run(&self, f: impl FnOnce()) -> bool {
        let mut cov = SancovCoverage::new();
        let token = cov.start_capture().ok();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        let feedback = match token {
            Some(token) => cov.finish_capture(token).unwrap_or_default(),
            None => ExecutionFeedback::default(),
        };
        let panic_message = result.as_ref().err().map(|payload| {
            if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".to_string()
            }
        });
        self.publish(&feedback, panic_message.as_deref());
        result.is_err()
    }

    fn publish(&self, feedback: &ExecutionFeedback, panic_message: Option<&str>) {
        let buf = self.region.bytes_mut();
        let mut w = Writer {
            buf,
            pos: HEADER,
        };
        let mut count = 0u32;
        for id in feedback.features().iter() {
            if !w.put(&id.raw().to_ne_bytes()) {
                break;
            }
            count += 1;
        }
        let mut dict_count = 0u32;
        for entry in feedback.dictionary() {
            let len = entry.len() as u32;
            if w.remaining() < 4 + entry.len() {
                break;
            }
            w.put(&len.to_ne_bytes());
            w.put(entry);
            dict_count += 1;
        }
        let panic_bytes = panic_message.unwrap_or("").as_bytes();
        let panic_len = panic_bytes.len().min(w.remaining());
        w.put(&panic_bytes[..panic_len]);
        let used = w.pos as u32;
        let buf = self.region.bytes_mut();
        buf[4..8].copy_from_slice(&count.to_ne_bytes());
        buf[8..16].copy_from_slice(&feedback.hit_count_weight().to_ne_bytes());
        buf[16..20].copy_from_slice(&dict_count.to_ne_bytes());
        buf[20..24].copy_from_slice(&(panic_len as u32).to_ne_bytes());
        buf[24..28].copy_from_slice(&used.to_ne_bytes());
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        buf[0..4].copy_from_slice(&MAGIC.to_ne_bytes());
    }

    /// Parent side: read what the child published. Empty if the child never got to publish
    /// (killed, crashed outside `catch_unwind`).
    pub fn read(&self) -> (ExecutionFeedback, ChildReport) {
        let buf = self.region.bytes();
        let magic = u32::from_ne_bytes(buf[0..4].try_into().unwrap());
        if magic != MAGIC {
            return (ExecutionFeedback::default(), ChildReport::default());
        }
        let count = u32::from_ne_bytes(buf[4..8].try_into().unwrap()) as usize;
        let weight = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
        let dict_count = u32::from_ne_bytes(buf[16..20].try_into().unwrap()) as usize;
        let panic_len = u32::from_ne_bytes(buf[20..24].try_into().unwrap()) as usize;
        let mut pos = HEADER;
        let mut set = CoverageSet::new();
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            let raw = u64::from_ne_bytes(buf[pos..pos + 8].try_into().unwrap());
            ids.push(CoverageId::new(raw));
            pos += 8;
        }
        set.extend(ids);
        let mut dictionary = Vec::with_capacity(dict_count);
        for _ in 0..dict_count {
            let len = u32::from_ne_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            dictionary.push(buf[pos..pos + len].to_vec());
            pos += len;
        }
        let panic_message = if panic_len > 0 {
            Some(String::from_utf8_lossy(&buf[pos..pos + panic_len]).into_owned())
        } else {
            None
        };
        let report = ChildReport {
            panic_message,
            feature_count: set.len(),
        };
        (ExecutionFeedback::new(set, weight, dictionary), report)
    }
}

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn put(&mut self, bytes: &[u8]) -> bool {
        if self.remaining() < bytes.len() {
            return false;
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        true
    }
}

impl CoverageCapture for ChildCoverage {
    type Token = ();

    fn start_capture(&mut self) -> Result<(), String> {
        self.reset();
        Ok(())
    }

    fn finish_capture(&mut self, _token: ()) -> Result<ExecutionFeedback, String> {
        Ok(self.read().0)
    }
}
