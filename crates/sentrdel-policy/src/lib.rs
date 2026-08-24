#![forbid(unsafe_code)]
//! Monotonic policy boundary. Kernel invariants remain Rust-owned.

/// Ordered baseline verdicts used by later policy implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BootstrapVerdict {
    Allow,
    Ask,
    Deny,
}

#[cfg(test)]
mod tests {
    use super::BootstrapVerdict::{Allow, Ask, Deny};

    #[test]
    fn verdict_order_is_monotonic() {
        assert!(Allow < Ask);
        assert!(Ask < Deny);
    }
}
