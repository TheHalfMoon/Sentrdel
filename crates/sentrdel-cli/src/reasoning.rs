//! Optional reasoner CLI wiring that cannot become a deterministic review dependency.
//!
//! `--reason` opts into advisory reasoning. `--no-network` is an absolute network
//! ceiling for this layer: when present, no network-backed reasoner callback is
//! invoked. The deterministic review result is carried separately and is never
//! replaced by model output or model failure.

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

    /// Read only the two T076 global review flags from already-tokenized CLI
    /// arguments. Unknown arguments remain the authority of the command parser.
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReasoningAttempt<E> {
    NotRequested,
    NetworkDisabled,
    Completed(Vec<E>),
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewWithOptionalReasoning<R, E> {
    deterministic_review: R,
    reasoning: ReasoningAttempt<E>,
}

impl<R, E> ReviewWithOptionalReasoning<R, E> {
    #[must_use]
    pub const fn deterministic_review(&self) -> &R {
        &self.deterministic_review
    }

    #[must_use]
    pub const fn reasoning(&self) -> &ReasoningAttempt<E> {
        &self.reasoning
    }

    #[must_use]
    pub fn into_deterministic_review(self) -> R {
        self.deterministic_review
    }
}

/// Attach optional advisory reasoner output without allowing the reasoner call
/// to determine whether the deterministic review exists or what it contains.
///
/// The callback is treated as network-backed. It is not invoked unless
/// `--reason` is present and `--no-network` is absent. In-process/offline model
/// support can be added later behind a separate non-network callback without
/// weakening this ceiling.
pub fn attach_optional_network_reasoning<R, E, F, Err>(
    deterministic_review: R,
    flags: ReviewReasoningFlags,
    reasoner_call: F,
) -> ReviewWithOptionalReasoning<R, E>
where
    F: FnOnce() -> Result<Vec<E>, Err>,
    Err: std::fmt::Display,
{
    let reasoning = if !flags.reason_enabled() {
        ReasoningAttempt::NotRequested
    } else if flags.no_network() {
        ReasoningAttempt::NetworkDisabled
    } else {
        match reasoner_call() {
            Ok(evidence) => ReasoningAttempt::Completed(evidence),
            Err(error) => ReasoningAttempt::Failed(error.to_string()),
        }
    };

    ReviewWithOptionalReasoning {
        deterministic_review,
        reasoning,
    }
}
