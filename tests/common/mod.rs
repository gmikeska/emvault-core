//! Shared test helpers. Each child module is gated by the feature it
//! requires so it doesn't pull in heavy deps on `cargo test` without
//! features.

#[cfg(feature = "node-tests")]
pub mod rpc;
