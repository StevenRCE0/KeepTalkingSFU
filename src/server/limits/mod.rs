//! Resource bounds: the tunable [`config::Limits`] and the token-bucket rate
//! limiter that enforces the per-connection rates.

pub(crate) mod config;
pub(crate) mod rate_limiter;
