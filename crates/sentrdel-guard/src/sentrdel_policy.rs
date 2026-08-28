//! Minimal guard-facing preflight verdict contract for T052.
//!
//! This mirrors the canonical policy lattice semantics without adding a new
//! first-party dependency edge to the guard crate. Later composition remains
//! owned by `sentrdel-policy`; the gateway consumes only the already-bounded
//! preflight result at its enforcement seam.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Ask,
    Deny,
    Undecidable,
}
