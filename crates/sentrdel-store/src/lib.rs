#![forbid(unsafe_code)]
//! Local persistence boundary. Durable schema arrives in Phase 2.

/// Marker proving the crate is intentionally bootstrapped without dependencies.
pub const STORE_BOOTSTRAPPED: bool = true;
