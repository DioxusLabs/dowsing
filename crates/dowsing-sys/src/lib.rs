//! Raw in-process coverage runtime hooks used by `dowsing`.
//!
//! This crate owns the native symbols, process-global state, and pointer-level access needed to
//! collect LLVM coverage feedback. Higher-level crates should usually wrap these APIs in a safer
//! execution model.

pub mod llvm;
pub mod sancov;

/// Raw coverage feature key emitted by a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawFeature(u64);

impl RawFeature {
    /// Construct a raw feature key.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw feature key.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Error reported by a raw coverage backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
}

impl Error {
    /// Build an error from a displayable message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

pub(crate) type Result<T> = std::result::Result<T, Error>;
