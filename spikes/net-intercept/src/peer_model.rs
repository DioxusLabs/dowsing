//! Peer behaviour drawn from dowsing. Every decision is a `variant` span on a `range` item so
//! `cautious()` can delete events and simplify each one toward index 0 (always the benign
//! choice).

use iterator_fuzz::{ChildRng, coverage::CoverageCapture};
use rand::RngCore;

/// The subset of `CaseRng`/`ChildRng` the peer model needs, so payload generators can be
/// written without naming the coverage type parameter.
pub trait ByteSource {
    fn variant(&mut self, upper: usize) -> usize;
    fn fill(&mut self, buf: &mut [u8]);
    fn byte(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.fill(&mut b);
        b[0]
    }
}

impl<C: CoverageCapture> ByteSource for ChildRng<'_, C> {
    fn variant(&mut self, upper: usize) -> usize {
        ChildRng::variant(self, upper)
    }
    fn fill(&mut self, buf: &mut [u8]) {
        self.fill_bytes(buf)
    }
}

/// Produces the bytes of one `Data` event. Called with the item RNG of that event.
pub type PayloadGen = Box<dyn FnMut(&mut dyn ByteSource) -> Vec<u8>>;

/// Default payload: `variant`-chosen length (0..=64) of random bytes.
pub fn random_payload() -> PayloadGen {
    Box::new(|rng: &mut dyn ByteSource| {
        let len = rng.variant(65);
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        buf
    })
}

/// What the remote peer does when the target waits for it on a stream socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    /// Orderly EOF (index 0: benign).
    Close,
    /// Bytes arrive.
    Data(Vec<u8>),
    /// Connection reset.
    Reset,
    /// Nothing yet (only offered to nonblocking sockets and finite-timeout waits).
    WouldBlock,
}

impl PeerEvent {
    pub const COUNT_BLOCKING: usize = 3;
    pub const COUNT_NONBLOCKING: usize = 4;

    pub fn draw(rng: &mut dyn ByteSource, may_block: bool, payload: &mut PayloadGen) -> Self {
        let upper = if may_block {
            Self::COUNT_NONBLOCKING
        } else {
            Self::COUNT_BLOCKING
        };
        match rng.variant(upper) {
            0 => PeerEvent::Close,
            1 => PeerEvent::Data(payload(rng)),
            2 => PeerEvent::Reset,
            _ => PeerEvent::WouldBlock,
        }
    }
}

/// Result of a `connect` on a stream socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    Ok,
    Refused,
    TimedOut,
    Unreachable,
}

impl ConnectOutcome {
    pub const COUNT: usize = 4;

    pub fn draw(rng: &mut dyn ByteSource) -> Self {
        match rng.variant(Self::COUNT) {
            0 => ConnectOutcome::Ok,
            1 => ConnectOutcome::Refused,
            2 => ConnectOutcome::TimedOut,
            _ => ConnectOutcome::Unreachable,
        }
    }

    pub fn errno(self) -> Option<i32> {
        match self {
            ConnectOutcome::Ok => None,
            ConnectOutcome::Refused => Some(libc::ECONNREFUSED),
            ConnectOutcome::TimedOut => Some(libc::ETIMEDOUT),
            ConnectOutcome::Unreachable => Some(libc::EHOSTUNREACH),
        }
    }
}

/// Result of an `accept` on a listening socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// A client connects (index 0: keeps servers making progress).
    Connection,
    Aborted,
    WouldBlock,
}

impl AcceptOutcome {
    pub fn draw(rng: &mut dyn ByteSource, may_block: bool) -> Self {
        match rng.variant(if may_block { 3 } else { 2 }) {
            0 => AcceptOutcome::Connection,
            1 => AcceptOutcome::Aborted,
            _ => AcceptOutcome::WouldBlock,
        }
    }
}

/// Result of a `send`/`write` on a connected stream socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    Accepted,
    Pipe,
    Reset,
}

impl SendOutcome {
    pub const COUNT: usize = 3;

    pub fn draw(rng: &mut dyn ByteSource) -> Self {
        match rng.variant(Self::COUNT) {
            0 => SendOutcome::Accepted,
            1 => SendOutcome::Pipe,
            _ => SendOutcome::Reset,
        }
    }
}

/// Result of a DNS lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOutcome {
    /// Resolves to a synthetic address (index 0).
    Resolves,
    NxDomain,
    ServFail,
}

impl DnsOutcome {
    pub const COUNT: usize = 3;

    pub fn draw(rng: &mut dyn ByteSource) -> Self {
        match rng.variant(Self::COUNT) {
            0 => DnsOutcome::Resolves,
            1 => DnsOutcome::NxDomain,
            _ => DnsOutcome::ServFail,
        }
    }
}
