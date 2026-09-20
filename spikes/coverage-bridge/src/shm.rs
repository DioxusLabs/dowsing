//! Shared-memory protocol between the supervisor and the target process.
//!
//! The region is one `memfd` created by the supervisor and mapped by both sides. Everything in
//! it is plain little-endian `#[repr(C)]` data so the child needs no serialisation code. The
//! header carries the region capacities, so the child derives the layout from the mapping alone.
//! Access is sequenced by the control/status pipes: the supervisor writes a request, the child
//! owns the region until it reports back, then the supervisor reads the response.

use std::{io, mem::size_of, os::fd::RawFd, ptr};

pub const MAGIC: u32 = 0x4442_5247; // "DBRG"
pub const VERSION: u32 = 1;

/// Case lifecycle as seen from the supervisor.
pub const STATE_IDLE: u32 = 0;
pub const STATE_STARTED: u32 = 1;
pub const STATE_DONE: u32 = 2;
pub const STATE_CRASHED: u32 = 3;

pub const VERDICT_NONE: u32 = 0;
pub const VERDICT_OK: u32 = 1;
pub const VERDICT_FAILED: u32 = 2;
pub const VERDICT_PANICKED: u32 = 3;

pub const CASE_FLAG_CMP_FEEDBACK: u32 = 1 << 0;

pub const OVERFLOW_INPUT: u32 = 1 << 0;
pub const OVERFLOW_DRAWS: u32 = 1 << 1;
pub const OVERFLOW_SEMANTICS: u32 = 1 << 2;
pub const OVERFLOW_SEQUENCES: u32 = 1 << 3;
pub const OVERFLOW_ITEMS: u32 = 1 << 4;
pub const OVERFLOW_FEATURES: u32 = 1 << 5;
pub const OVERFLOW_DICT: u32 = 1 << 6;
pub const OVERFLOW_COUNTERS: u32 = 1 << 7;

/// Hello flags reported by the child on the status pipe.
pub const HELLO_INSTRUMENTED: u32 = 1 << 0;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Header {
    pub magic: u32,
    pub version: u32,
    // Capacities, written once by the supervisor.
    pub input_cap: u32,
    pub spans_cap: u32,
    pub sequences_cap: u32,
    pub items_cap: u32,
    pub features_cap: u32,
    pub dict_cap: u32,
    pub dict_bytes_cap: u32,
    pub counters_cap: u32,
    // Request, written by the supervisor per case.
    pub seed: u64,
    pub input_len: u32,
    pub case_flags: u32,
    // Response, written by the case child.
    pub state: u32,
    pub verdict: u32,
    pub cost: u64,
    pub consumed: u32,
    pub n_draws: u32,
    pub n_semantics: u32,
    pub n_sequences: u32,
    pub n_items: u32,
    pub n_features: u32,
    pub n_dict: u32,
    pub dict_bytes: u32,
    pub counters_len: u32,
    pub overflow: u32,
    pub crash_signal: u32,
    pub _pad: u32,
    pub hit_count_weight: u64,
    /// Reserved for later spikes (second input cursor, scheduler decisions, ...).
    pub reserved: [u64; 4],
}

/// One draw or semantic span; `kind` follows `iterator_fuzz::raw::RawSpan`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpanRec {
    pub start: u32,
    pub len: u32,
    pub kind: u32,
    pub _pad: u32,
}

/// One `range()` sequence; its items live in the item table at `items_start..+items_len`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SequenceRec {
    pub length_start: u32,
    pub length_len: u32,
    pub items_start: u32,
    pub items_len: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ItemRec {
    pub start: u32,
    pub len: u32,
}

/// Region capacities chosen by the supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacities {
    pub input: usize,
    pub spans: usize,
    pub sequences: usize,
    pub items: usize,
    pub features: usize,
    pub dict: usize,
    pub dict_bytes: usize,
    pub counters: usize,
}

impl Default for Capacities {
    fn default() -> Self {
        Self {
            input: 64 * 1024,
            spans: 8192,
            sequences: 1024,
            items: 8192,
            features: 16384,
            dict: 256,
            dict_bytes: 256 * 8,
            counters: 1024 * 1024,
        }
    }
}

/// Byte offsets of every table in the region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub caps: Capacities,
    pub input: usize,
    pub draws: usize,
    pub semantics: usize,
    pub sequences: usize,
    pub items: usize,
    pub features: usize,
    pub dict_lens: usize,
    pub dict_bytes: usize,
    pub counters: usize,
    pub total: usize,
}

fn align8(value: usize) -> usize {
    (value + 7) & !7
}

impl Layout {
    pub fn new(caps: Capacities) -> Self {
        let mut cursor = align8(size_of::<Header>());
        let mut take = |bytes: usize| {
            let offset = cursor;
            cursor = align8(cursor + bytes);
            offset
        };
        let input = take(caps.input);
        let draws = take(caps.spans * size_of::<SpanRec>());
        let semantics = take(caps.spans * size_of::<SpanRec>());
        let sequences = take(caps.sequences * size_of::<SequenceRec>());
        let items = take(caps.items * size_of::<ItemRec>());
        let features = take(caps.features * size_of::<u64>());
        let dict_lens = take(caps.dict * size_of::<u32>());
        let dict_bytes = take(caps.dict_bytes);
        let counters = take(caps.counters);
        let total = page_round(cursor);
        Self {
            caps,
            input,
            draws,
            semantics,
            sequences,
            items,
            features,
            dict_lens,
            dict_bytes,
            counters,
            total,
        }
    }

    pub fn from_header(header: &Header) -> Result<Self, String> {
        if header.magic != MAGIC {
            return Err(format!("bad shm magic {:#x}", header.magic));
        }
        if header.version != VERSION {
            return Err(format!("unsupported shm version {}", header.version));
        }
        Ok(Self::new(Capacities {
            input: header.input_cap as usize,
            spans: header.spans_cap as usize,
            sequences: header.sequences_cap as usize,
            items: header.items_cap as usize,
            features: header.features_cap as usize,
            dict: header.dict_cap as usize,
            dict_bytes: header.dict_bytes_cap as usize,
            counters: header.counters_cap as usize,
        }))
    }
}

fn page_round(value: usize) -> usize {
    let page = 4096;
    (value + page - 1) & !(page - 1)
}

/// A mapped protocol region. Both processes hold one of these over the same `memfd`.
pub struct Region {
    base: *mut u8,
    len: usize,
    layout: Layout,
    fd: RawFd,
    owns_fd: bool,
}

unsafe impl Send for Region {}

impl Region {
    /// Create a fresh `memfd`-backed region and write the capacities into its header.
    pub fn create(caps: Capacities) -> io::Result<Self> {
        let layout = Layout::new(caps);
        let fd = unsafe { libc::memfd_create(c"coverage-bridge".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::ftruncate(fd, layout.total as libc::off_t) } != 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        let mut region = Self::map(fd, layout, true)?;
        let header = Header {
            magic: MAGIC,
            version: VERSION,
            input_cap: caps.input as u32,
            spans_cap: caps.spans as u32,
            sequences_cap: caps.sequences as u32,
            items_cap: caps.items as u32,
            features_cap: caps.features as u32,
            dict_cap: caps.dict as u32,
            dict_bytes_cap: caps.dict_bytes as u32,
            counters_cap: caps.counters as u32,
            ..Header::default()
        };
        region.write_header(&header);
        Ok(region)
    }

    /// Map an inherited region; the layout is recovered from the header.
    pub fn open(fd: RawFd) -> io::Result<Self> {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let len = stat.st_size as usize;
        if len < size_of::<Header>() {
            return Err(io::Error::other("shm region too small"));
        }
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { ptr::read_volatile(base as *const Header) };
        let layout = Layout::from_header(&header).map_err(io::Error::other)?;
        if layout.total > len {
            unsafe { libc::munmap(base, len) };
            return Err(io::Error::other("shm region shorter than its layout"));
        }
        Ok(Self {
            base: base as *mut u8,
            len,
            layout,
            fd,
            owns_fd: false,
        })
    }

    fn map(fd: RawFd, layout: Layout, owns_fd: bool) -> io::Result<Self> {
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                layout.total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            let err = io::Error::last_os_error();
            if owns_fd {
                unsafe { libc::close(fd) };
            }
            return Err(err);
        }
        Ok(Self {
            base: base as *mut u8,
            len: layout.total,
            layout,
            fd,
            owns_fd,
        })
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn header(&self) -> Header {
        unsafe { ptr::read_volatile(self.base as *const Header) }
    }

    pub fn write_header(&mut self, header: &Header) {
        unsafe { ptr::write_volatile(self.base as *mut Header, *header) }
    }

    /// Raw pointer to the header, for async-signal-safe writers.
    pub fn header_ptr(&self) -> *mut Header {
        self.base as *mut Header
    }

    /// Raw pointer to the counter table, for async-signal-safe writers.
    pub fn counters_ptr(&self) -> *mut u8 {
        unsafe { self.base.add(self.layout.counters) }
    }

    fn bytes(&self, offset: usize, len: usize) -> &[u8] {
        debug_assert!(offset + len <= self.len);
        unsafe { std::slice::from_raw_parts(self.base.add(offset), len) }
    }

    fn bytes_mut(&mut self, offset: usize, len: usize) -> &mut [u8] {
        debug_assert!(offset + len <= self.len);
        unsafe { std::slice::from_raw_parts_mut(self.base.add(offset), len) }
    }

    fn table<T: Copy>(&self, offset: usize, cap: usize) -> &[T] {
        debug_assert!(offset + cap * size_of::<T>() <= self.len);
        unsafe { std::slice::from_raw_parts(self.base.add(offset) as *const T, cap) }
    }

    fn table_mut<T: Copy>(&mut self, offset: usize, cap: usize) -> &mut [T] {
        debug_assert!(offset + cap * size_of::<T>() <= self.len);
        unsafe { std::slice::from_raw_parts_mut(self.base.add(offset) as *mut T, cap) }
    }

    pub fn input(&self) -> &[u8] {
        self.bytes(self.layout.input, self.layout.caps.input)
    }
    pub fn input_mut(&mut self) -> &mut [u8] {
        self.bytes_mut(self.layout.input, self.layout.caps.input)
    }
    pub fn draws(&self) -> &[SpanRec] {
        self.table(self.layout.draws, self.layout.caps.spans)
    }
    pub fn draws_mut(&mut self) -> &mut [SpanRec] {
        self.table_mut(self.layout.draws, self.layout.caps.spans)
    }
    pub fn semantics(&self) -> &[SpanRec] {
        self.table(self.layout.semantics, self.layout.caps.spans)
    }
    pub fn semantics_mut(&mut self) -> &mut [SpanRec] {
        self.table_mut(self.layout.semantics, self.layout.caps.spans)
    }
    pub fn sequences(&self) -> &[SequenceRec] {
        self.table(self.layout.sequences, self.layout.caps.sequences)
    }
    pub fn sequences_mut(&mut self) -> &mut [SequenceRec] {
        self.table_mut(self.layout.sequences, self.layout.caps.sequences)
    }
    pub fn items(&self) -> &[ItemRec] {
        self.table(self.layout.items, self.layout.caps.items)
    }
    pub fn items_mut(&mut self) -> &mut [ItemRec] {
        self.table_mut(self.layout.items, self.layout.caps.items)
    }
    pub fn features(&self) -> &[u64] {
        self.table(self.layout.features, self.layout.caps.features)
    }
    pub fn features_mut(&mut self) -> &mut [u64] {
        self.table_mut(self.layout.features, self.layout.caps.features)
    }
    pub fn dict_lens(&self) -> &[u32] {
        self.table(self.layout.dict_lens, self.layout.caps.dict)
    }
    pub fn dict_lens_mut(&mut self) -> &mut [u32] {
        self.table_mut(self.layout.dict_lens, self.layout.caps.dict)
    }
    pub fn dict_bytes(&self) -> &[u8] {
        self.bytes(self.layout.dict_bytes, self.layout.caps.dict_bytes)
    }
    pub fn dict_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes_mut(self.layout.dict_bytes, self.layout.caps.dict_bytes)
    }
    pub fn counters(&self) -> &[u8] {
        self.bytes(self.layout.counters, self.layout.caps.counters)
    }
    pub fn counters_mut(&mut self) -> &mut [u8] {
        self.bytes_mut(self.layout.counters, self.layout.caps.counters)
    }

    /// Reset the per-case response fields before issuing a new request.
    pub fn reset_response(&mut self) {
        let mut header = self.header();
        header.state = STATE_IDLE;
        header.verdict = VERDICT_NONE;
        header.cost = 0;
        header.consumed = 0;
        header.n_draws = 0;
        header.n_semantics = 0;
        header.n_sequences = 0;
        header.n_items = 0;
        header.n_features = 0;
        header.n_dict = 0;
        header.dict_bytes = 0;
        header.counters_len = 0;
        header.overflow = 0;
        header.crash_signal = 0;
        header.hit_count_weight = 0;
        self.write_header(&header);
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.len);
            if self.owns_fd {
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_pod_sized_and_aligned() {
        assert_eq!(size_of::<Header>() % 8, 0);
        assert_eq!(size_of::<SpanRec>(), 16);
        assert_eq!(size_of::<SequenceRec>(), 16);
        assert_eq!(size_of::<ItemRec>(), 8);
    }

    #[test]
    fn layout_tables_do_not_overlap_and_fit() {
        let layout = Layout::new(Capacities::default());
        let caps = layout.caps;
        let ends = [
            (layout.input, caps.input, layout.draws),
            (layout.draws, caps.spans * 16, layout.semantics),
            (layout.semantics, caps.spans * 16, layout.sequences),
            (layout.sequences, caps.sequences * 16, layout.items),
            (layout.items, caps.items * 8, layout.features),
            (layout.features, caps.features * 8, layout.dict_lens),
            (layout.dict_lens, caps.dict * 4, layout.dict_bytes),
            (layout.dict_bytes, caps.dict_bytes, layout.counters),
            (layout.counters, caps.counters, layout.total),
        ];
        for (start, len, next) in ends {
            assert_eq!(start % 8, 0);
            assert!(start + len <= next, "{start}+{len} > {next}");
        }
        assert_eq!(layout.total % 4096, 0);
    }

    #[test]
    fn region_round_trips_header_and_tables() {
        let mut region = Region::create(Capacities::default()).unwrap();
        let header = region.header();
        assert_eq!(header.magic, MAGIC);
        assert_eq!(Layout::from_header(&header).unwrap(), *region.layout());
        region.input_mut()[..4].copy_from_slice(&[1, 2, 3, 4]);
        region.draws_mut()[0] = SpanRec {
            start: 0,
            len: 4,
            kind: 1,
            _pad: 0,
        };
        region.features_mut()[0] = 0xdead_beef;
        region.counters_mut()[10] = 7;

        let peer = Region::open(region.fd()).unwrap();
        assert_eq!(&peer.input()[..4], &[1, 2, 3, 4]);
        assert_eq!(peer.draws()[0].len, 4);
        assert_eq!(peer.features()[0], 0xdead_beef);
        assert_eq!(peer.counters()[10], 7);
    }
}
