//! The virtual clock.  `vnow` is nanoseconds since the sandbox started; every clock the target
//! can read is derived from it.

pub const NANOS: u64 = 1_000_000_000;

/// Virtual monotonic clocks start here so `Instant` arithmetic in the target can never
/// underflow (Rust panics on `earlier - later` for some operations).
pub const MONOTONIC_EPOCH_NS: u64 = 1_000_000 * NANOS;

/// Virtual `CLOCK_REALTIME` base: 2026-01-01T00:00:00Z.  Fixed so replays are identical no
/// matter when they run.
pub const REALTIME_BASE_NS: u64 = 1_767_225_600 * NANOS;

#[derive(Debug, Clone)]
pub struct VirtualClock {
    vnow: u64,
    /// Added to every clock read so busy loops that spin on `Instant::now()` terminate.
    pub quantum_ns: u64,
    /// Offset applied to `CLOCK_REALTIME` (fuzzer-controlled wall-clock steps).
    pub realtime_step_ns: i64,
}

impl VirtualClock {
    pub fn new(quantum_ns: u64) -> Self {
        Self {
            vnow: 0,
            quantum_ns,
            realtime_step_ns: 0,
        }
    }

    pub fn now(&self) -> u64 {
        self.vnow
    }

    pub fn advance_to(&mut self, vnow: u64) {
        if vnow > self.vnow {
            self.vnow = vnow;
        }
    }

    /// Answer a clock read; `None` means the clock is not virtualised (CPU-time clocks, ...).
    pub fn read(&mut self, clockid: i64) -> Option<(i64, i64)> {
        let ns = match clockid as i32 {
            libc::CLOCK_MONOTONIC
            | libc::CLOCK_MONOTONIC_RAW
            | libc::CLOCK_MONOTONIC_COARSE
            | libc::CLOCK_BOOTTIME => {
                self.vnow = self.vnow.saturating_add(self.quantum_ns);
                MONOTONIC_EPOCH_NS + self.vnow
            }
            libc::CLOCK_REALTIME | libc::CLOCK_REALTIME_COARSE | libc::CLOCK_TAI => {
                self.vnow = self.vnow.saturating_add(self.quantum_ns);
                self.realtime_ns()
            }
            _ => return None,
        };
        Some(split(ns))
    }

    pub fn realtime_ns(&self) -> u64 {
        (REALTIME_BASE_NS + self.vnow).saturating_add_signed(self.realtime_step_ns)
    }

    /// Convert an absolute timespec on `clockid` into a `vnow` deadline.
    pub fn deadline_from_absolute(&self, clockid: i64, secs: i64, nanos: i64) -> Option<u64> {
        let abs = to_ns(secs, nanos);
        match clockid as i32 {
            libc::CLOCK_MONOTONIC | libc::CLOCK_MONOTONIC_RAW | libc::CLOCK_BOOTTIME => {
                Some(abs.saturating_sub(MONOTONIC_EPOCH_NS))
            }
            libc::CLOCK_REALTIME => {
                let base = REALTIME_BASE_NS.saturating_add_signed(self.realtime_step_ns);
                Some(abs.saturating_sub(base))
            }
            _ => None,
        }
    }

    /// Convert a relative timespec into a `vnow` deadline.
    pub fn deadline_from_relative(&self, secs: i64, nanos: i64) -> u64 {
        self.vnow.saturating_add(to_ns(secs, nanos))
    }
}

pub fn to_ns(secs: i64, nanos: i64) -> u64 {
    if secs < 0 {
        return 0;
    }
    (secs as u64)
        .saturating_mul(NANOS)
        .saturating_add(nanos.max(0) as u64)
}

pub fn split(ns: u64) -> (i64, i64) {
    ((ns / NANOS) as i64, (ns % NANOS) as i64)
}
