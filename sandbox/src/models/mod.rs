//! The built-in models of the outside world (see [`crate::model`]).

pub mod entropy;
pub mod net;
pub mod time;

pub use entropy::Entropy;
pub use net::Net;
pub use time::Time;
