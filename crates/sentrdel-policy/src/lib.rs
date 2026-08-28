#![forbid(unsafe_code)]
//! Monotonic policy primitives for normalized action identity, Rust-owned invariants, and verdict composition.
//!
//! T021 provides canonical action identity and the explicit verdict lattice. T022 adds compiled
//! workspace/evidence/enforcement invariants that later policy layers may only make stricter. T023
//! adds a bounded Regorus-backed repository-policy candidate evaluator without moving kernel
//! authority into Rego. T024 adds Rust-owned repository-policy narrowing validation and layered
//! monotonic composition without weakening the kernel enforcement floor.

pub mod bootstrap;
pub mod kernel;
pub mod narrowing;
pub mod rego;

use std::{collections::BTreeMap, error::Error, fmt};

use kernel::{KernelDecision, KernelIntegrityState};
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
                write!(
                    formatter,
                    "normalized action params digest must not be empty"
                )
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

/// Compose non-kernel policy verdicts without assigning `UNDECIDABLE` an implicit lattice rank.
///
/// `ALLOW < ASK < DENY` is the ordered policy lattice. `DENY` is absorbing. If no `DENY` exists
/// but any producer is `UNDECIDABLE`, the combined verdict remains `UNDECIDABLE` so the caller must
/// resolve uncertainty explicitly. An empty input is also `UNDECIDABLE`; absence of policy results
/// is never treated as permission.
///
/// This result is a policy candidate, not an authorization decision. Enforcement MUST pass the
/// candidate through [`resolve_for_enforcement`].
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

/// Result emitted by the policy-owned enforcement boundary.
///
/// The final verdict and the exact kernel decision stay coupled so later PolicyDecision/ASEL code
/// can bind the non-overridable invariant identifiers to the same enforcement result.
#[must_use = "an enforcement decision must be consumed by the controlled authorization boundary"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnforcementDecision {
    verdict: Verdict,
    kernel: KernelDecision,
}

impl EnforcementDecision {
    /// Return the final enforceable verdict after the kernel floor and uncertainty resolution.
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// Return the kernel decision that established the non-overridable floor.
    pub const fn kernel(&self) -> &KernelDecision {
        &self.kernel
    }
}

/// Evaluate the Rust kernel and resolve a policy candidate at the policy-owned enforcement boundary.
///
/// The opaque `KernelIntegrityState` is evaluated inside this function, then its DENY floor is
/// applied before any `UNDECIDABLE` resolution. Safe downstream Rust cannot construct a trusted
/// state directly, and there is no public enforcement helper in this crate that skips evaluation or
/// floor application. T036/T052 will wire the Rust-owned validators that produce the opaque state.
pub fn resolve_for_enforcement(
    kernel_state: KernelIntegrityState,
    verdict: Verdict,
    resolution: UndecidableResolution,
) -> EnforcementDecision {
    let kernel = kernel::evaluate_kernel_invariants(kernel_state);
    let verdict = kernel::enforce_kernel_floor(&kernel, verdict);
    let verdict = match verdict {
        Verdict::Undecidable => match resolution {
            UndecidableResolution::Ask => Verdict::Ask,
            UndecidableResolution::Deny => Verdict::Deny,
        },
        ordered => ordered,
    };

    EnforcementDecision { verdict, kernel }
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

    fn healthy_kernel_state() -> KernelIntegrityState {
        KernelIntegrityState::for_test(true, true, true, true)
    }

    fn denied_kernel_state() -> KernelIntegrityState {
        KernelIntegrityState::for_test(false, true, true, true)
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
        assert_eq!(
            first.digest().expect("first digest"),
            second.digest().expect("second digest")
        );
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
        assert_ne!(
            baseline_digest,
            changed_target.digest().expect("target digest")
        );
        assert_ne!(
            baseline_digest,
            changed_params.digest().expect("params digest")
        );
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
            NormalizedAction::new("mcp.invocation", BTreeMap::new(), Some(" ".to_owned())),
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
            resolve_for_enforcement(
                healthy_kernel_state(),
                Verdict::Undecidable,
                UndecidableResolution::default()
            )
            .verdict(),
            Verdict::Ask
        );
        assert_eq!(
            resolve_for_enforcement(
                healthy_kernel_state(),
                Verdict::Undecidable,
                UndecidableResolution::Deny
            )
            .verdict(),
            Verdict::Deny
        );
        assert_eq!(
            resolve_for_enforcement(
                healthy_kernel_state(),
                Verdict::Allow,
                UndecidableResolution::Deny
            )
            .verdict(),
            Verdict::Allow
        );
    }

    #[test]
    fn enforcement_boundary_evaluates_and_applies_absorbing_kernel_deny() {
        for candidate in [
            Verdict::Allow,
            Verdict::Ask,
            Verdict::Deny,
            Verdict::Undecidable,
        ] {
            let decision = resolve_for_enforcement(
                denied_kernel_state(),
                candidate,
                UndecidableResolution::default(),
            );
            assert_eq!(decision.verdict(), Verdict::Deny);
            assert_eq!(
                decision.kernel().invariant_ids().collect::<Vec<_>>(),
                vec![kernel::WORKSPACE_BOUNDARY_INVARIANT_ID]
            );
        }
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
