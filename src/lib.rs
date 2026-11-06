//! Integrated ACME and Pingora H2 / quiche H3 server runtime.
pub mod acme;
pub mod cli;
pub mod net;
pub mod runtime;
mod trust;

mod resolve;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T, E = Error> = std::result::Result<T, E>;
