#![forbid(unsafe_code)]
//! Monotonic policy primitives for normalized action identity and guard verdict composition.
//!
//! T021 deliberately keeps repository policy evaluation and Rust-owned kernel invariants out of
//! this slice. It provides the canonical action digest and the explicit verdict lattice those later
//! layers compose through.

use std::{collections::BTreeMap, error::Error, fmt};

use sentrdel_schema::canonical::{CanonicalError, content_id};
pub use sentrdel_schema::policy::Verdict;

const ACTION_DIGEST_NAMESPACE: &str = "policy-action";

/// A structurally normalized action scope used to bind policy decisions.
///
/// Normalization here is structural rather than semantic: target keys are held in a `BTreeMap`,
/// field presence is explicit, and no caller-controlled path, identifier, case, whitespace, or
/// parameter value is rewritten. Action-specific semantic normalization belongs to the bounded
/// adapter that understands that action kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedAction {
    kind: String,
    target: BTreeMap<String, String>,
    params_digest: Option<String>,
}

/// Validation failures raised before an action is eligible for policy hashing.
#[derive(Debug, PartialEq, Eq)]
pub enum ActionNormalizationError {
    /// The action kind is empty or consists only of whitespace.
    EmptyKind,
    /// A target key is empty or consists only of whitespace.
    EmptyTargetKey,
    /// A supplied parameter digest is empty or consists only of whitespace.
    EmptyParamsDigest,
}

impl fmt::Display for ActionNormalizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKind => write!(formatter, "normalized action kind must not be empty"),
            Self::EmptyTargetKey => {
                write!(formatter, "normalized action target keys must not be empty")
            }
            Self::EmptyParamsDigest => {
                write!(formatter, "normalized action params digest must not be empty")
            }
        }
    }
}

impl Error for ActionNormalizationError {}

impl NormalizedAction {
    /// Construct an action scope without silently rewriting caller-controlled semantics.
    pub fn new(
        kind: impl Into<String>,
        target: BTreeMap<String, String>,
        params_digest: Option<String>,
    ) -> Result<Self, ActionNormalizationError> {
        let kind = kind.into();
        if kind.trim().is_empty() {
            return Err(ActionNormalizationError::EmptyKind);
        }
        if target.keys().any(|key| key.trim().is_empty()) {
            return Err(ActionNormalizationError::EmptyTargetKey);
        }
        if params_digest
            .as_deref()
            .is_some_and(|digest| digest.trim().is_empty())
        {
            return Err(ActionNormalizationError::EmptyParamsDigest);
        }

        Ok(Self {
            kind,
            target,
            params_digest,
        })
    }

    /// Return the exact action kind supplied by the trusted adapter.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Return the deterministic target map for the action scope.
    pub fn target(&self) -> &BTreeMap<String, String> {
        &self.target
    }

    /// Return the optional digest that binds the action's parameter payload.
    pub fn params_digest(&self) -> Option<&str> {
        self.params_digest.as_deref()
    }

    /// Compute the domain-separated canonical SHA-256 identifier for this action scope.
    ///
    /// The canonical input is a fixed tuple of `(kind, target, params_digest)`. Target insertion
    /// order therefore cannot affect the result, while changing any bound field changes the digest.
    pub fn digest(&self) -> Result<String, CanonicalError> {
        content_id(
            ACTION_DIGEST_NAMESPACE,
            &(
                self.kind.as_str(),
                &self.target,
                self.params_digest.as_deref(),
            ),
        )
    }
}

/// Fail-closed handling for a verdict that could not be decided.
///
/// There is intentionally no `Allow` variant. At an enforcement seam, uncertainty may require
/// interactive approval (`Ask`, the default) or a hard block (`Deny`), but it cannot fail open.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UndecidableResolution {
    /// Route the action to human/interactive approval when that seam supports it.
    #[default]
    Ask,
    /// Convert uncertainty into a hard denial.
    Deny,
}

/// Compose policy verdicts without assigning `UNDECIDABLE` an implicit lattice rank.
///
/// `ALLOW < ASK < DENY` is the ordered policy lattice. `DENY` is absorbing. If no `DENY` exists
/// but any producer is `UNDECIDABLE`, the combined verdict remains `UNDECIDABLE` so the caller must
/// resolve uncertainty explicitly. An empty input is also `UNDECIDABLE`; absence of policy results
/// is never treated as permission.
pub fn compose_verdicts<I>(verdicts: I) -> Verdict
where
    I: IntoIterator<Item = Verdict>,
{
    let mut saw_any = false;
    let mut saw_ask = false;
    let mut saw_undecidable = false;

    for verdict in verdicts {
        saw_any = true;
        match verdict {
            Verdict::Deny => return Verdict::Deny,
            Verdict::Undecidable => saw_undecidable = true,
            Verdict::Ask => saw_ask = true,
            Verdict::Allow => {}
        }
    }

    if !saw_any || saw_undecidable {
        Verdict::Undecidable
    } else if saw_ask {
        Verdict::Ask
    } else {
        Verdict::Allow
    }
}

/// Resolve a composed verdict at an enforcement seam.
///
/// Ordered verdicts pass through unchanged. `UNDECIDABLE` can only become `ASK` or `DENY`, which
/// structurally prevents a fail-open conversion into `ALLOW`.
pub fn resolve_for_enforcement(verdict: Verdict, resolution: UndecidableResolution) -> Verdict {
    match verdict {
        Verdict::Undecidable => match resolution {
            UndecidableResolution::Ask => Verdict::Ask,
            UndecidableResolution::Deny => Verdict::Deny,
        },
        ordered => ordered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn ordered_rank(verdict: Verdict) -> u8 {
        match verdict {
            Verdict::Allow => 0,
            Verdict::Ask => 1,
            Verdict::Deny => 2,
            Verdict::Undecidable => panic!("UNDECIDABLE has no implicit lattice rank"),
        }
    }

    #[test]
    fn action_digest_is_stable_across_target_insertion_order() {
        let mut first_target = BTreeMap::new();
        first_target.insert("tool".to_owned(), "deploy".to_owned());
        first_target.insert("server".to_owned(), "local-mcp".to_owned());

        let mut second_target = BTreeMap::new();
        second_target.insert("server".to_owned(), "local-mcp".to_owned());
        second_target.insert("tool".to_owned(), "deploy".to_owned());

        let first = NormalizedAction::new(
            "mcp.invocation",
            first_target,
            Some("sha256:params-a".to_owned()),
        )
        .expect("first action should normalize");
        let second = NormalizedAction::new(
            "mcp.invocation",
            second_target,
            Some("sha256:params-a".to_owned()),
        )
        .expect("second action should normalize");

        assert_eq!(first, second);
        assert_eq!(first.digest().expect("first digest"), second.digest().expect("second digest"));
    }

    #[test]
    fn action_digest_binds_kind_target_and_params() {
        let baseline = NormalizedAction::new(
            "mcp.invocation",
            target(&[("server", "local-mcp"), ("tool", "deploy")]),
            Some("sha256:params-a".to_owned()),
        )
        .expect("baseline action");
        let changed_kind = NormalizedAction::new(
            "git.operation",
            target(&[("server", "local-mcp"), ("tool", "deploy")]),
            Some("sha256:params-a".to_owned()),
        )
        .expect("changed kind");
        let changed_target = NormalizedAction::new(
            "mcp.invocation",
            target(&[("server", "local-mcp"), ("tool", "destroy")]),
            Some("sha256:params-a".to_owned()),
        )
        .expect("changed target");
        let changed_params = NormalizedAction::new(
            "mcp.invocation",
            target(&[("server", "local-mcp"), ("tool", "deploy")]),
            Some("sha256:params-b".to_owned()),
        )
        .expect("changed params");

        let baseline_digest = baseline.digest().expect("baseline digest");
        assert_ne!(baseline_digest, changed_kind.digest().expect("kind digest"));
        assert_ne!(baseline_digest, changed_target.digest().expect("target digest"));
        assert_ne!(baseline_digest, changed_params.digest().expect("params digest"));
        assert!(baseline_digest.starts_with("sha256:"));
        assert_eq!(baseline_digest.len(), 71);
    }

    #[test]
    fn action_normalization_rejects_blank_identity_fields_without_rewriting_values() {
        assert_eq!(
            NormalizedAction::new("   ", BTreeMap::new(), None),
            Err(ActionNormalizationError::EmptyKind)
        );
        assert_eq!(
            NormalizedAction::new("mcp.invocation", target(&[(" ", "value")]), None),
            Err(ActionNormalizationError::EmptyTargetKey)
        );
        assert_eq!(
            NormalizedAction::new(
                "mcp.invocation",
                BTreeMap::new(),
                Some(" ".to_owned())
            ),
            Err(ActionNormalizationError::EmptyParamsDigest)
        );

        let action = NormalizedAction::new(
            "mcp.invocation",
            target(&[("tool", "  exact caller value  ")]),
            None,
        )
        .expect("non-empty values should remain exact");
        assert_eq!(
            action.target().get("tool").map(String::as_str),
            Some("  exact caller value  ")
        );
    }

    #[test]
    fn ordered_pair_table_matches_allow_ask_deny_lattice() {
        let table = [
            (Verdict::Allow, Verdict::Allow, Verdict::Allow),
            (Verdict::Allow, Verdict::Ask, Verdict::Ask),
            (Verdict::Allow, Verdict::Deny, Verdict::Deny),
            (Verdict::Ask, Verdict::Allow, Verdict::Ask),
            (Verdict::Ask, Verdict::Ask, Verdict::Ask),
            (Verdict::Ask, Verdict::Deny, Verdict::Deny),
            (Verdict::Deny, Verdict::Allow, Verdict::Deny),
            (Verdict::Deny, Verdict::Ask, Verdict::Deny),
            (Verdict::Deny, Verdict::Deny, Verdict::Deny),
        ];

        for (left, right, expected) in table {
            assert_eq!(compose_verdicts([left, right]), expected);
        }
    }

    #[test]
    fn deny_is_absorbing_and_undecidable_never_weakens_it() {
        for other in [
            Verdict::Allow,
            Verdict::Ask,
            Verdict::Deny,
            Verdict::Undecidable,
        ] {
            assert_eq!(compose_verdicts([Verdict::Deny, other]), Verdict::Deny);
            assert_eq!(compose_verdicts([other, Verdict::Deny]), Verdict::Deny);
        }
    }

    #[test]
    fn undecidable_is_explicit_when_no_deny_exists() {
        assert_eq!(compose_verdicts([]), Verdict::Undecidable);
        assert_eq!(
            compose_verdicts([Verdict::Allow, Verdict::Undecidable]),
            Verdict::Undecidable
        );
        assert_eq!(
            compose_verdicts([Verdict::Ask, Verdict::Undecidable]),
            Verdict::Undecidable
        );
    }

    #[test]
    fn enforcement_resolution_cannot_fail_open() {
        assert_eq!(
            resolve_for_enforcement(Verdict::Undecidable, UndecidableResolution::default()),
            Verdict::Ask
        );
        assert_eq!(
            resolve_for_enforcement(Verdict::Undecidable, UndecidableResolution::Deny),
            Verdict::Deny
        );
        assert_eq!(
            resolve_for_enforcement(Verdict::Allow, UndecidableResolution::Deny),
            Verdict::Allow
        );
    }

    #[test]
    fn adding_ordered_restrictions_never_lowers_the_composed_verdict() {
        let ordered = [Verdict::Allow, Verdict::Ask, Verdict::Deny];

        for first in ordered {
            for second in ordered {
                let base = compose_verdicts([first, second]);
                for added in ordered {
                    let extended = compose_verdicts([first, second, added]);
                    assert!(
                        ordered_rank(extended) >= ordered_rank(base),
                        "adding {added:?} lowered {base:?} to {extended:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn composition_is_order_independent_for_all_verdict_pairs() {
        let verdicts = [
            Verdict::Allow,
            Verdict::Ask,
            Verdict::Deny,
            Verdict::Undecidable,
        ];

        for left in verdicts {
            for right in verdicts {
                assert_eq!(
                    compose_verdicts([left, right]),
                    compose_verdicts([right, left])
                );
            }
        }
    }
}
