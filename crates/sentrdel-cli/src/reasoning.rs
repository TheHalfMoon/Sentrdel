//! Canonical T076 review-reasoning flags.
//!
//! This module only recognizes the two binding flags. Optional reasoner
//! execution and coverage live in the CLI binary orchestration layer so model
//! output cannot replace deterministic review authority.

pub const REASON_FLAG: &str = "--reason";
pub const NO_NETWORK_FLAG: &str = "--no-network";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReviewReasoningFlags {
    pub reason: bool,
    pub no_network: bool,
}

impl ReviewReasoningFlags {
    #[must_use]
    pub const fn new(reason: bool, no_network: bool) -> Self {
        Self { reason, no_network }
    }

    #[must_use]
    pub const fn reason_enabled(self) -> bool {
        self.reason
    }

    #[must_use]
    pub const fn no_network(self) -> bool {
        self.no_network
    }

    #[must_use]
    pub const fn network_reasoning_allowed(self) -> bool {
        self.reason && !self.no_network
    }

    /// Read only the two T076 flags from already-tokenized CLI arguments.
    /// Unknown arguments remain the authority of the future command parser.
    #[must_use]
    pub fn from_args(args: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        let mut flags = Self::default();
        for arg in args {
            match arg.as_ref() {
                REASON_FLAG => flags.reason = true,
                NO_NETWORK_FLAG => flags.no_network = true,
                _ => {}
            }
        }
        flags
    }
}
