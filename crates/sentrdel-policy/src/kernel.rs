//! Rust-owned security invariants that repository policy and external evaluators cannot replace.
//!
//! `KernelIntegrityState` is an opaque capability-bearing snapshot. Downstream crates can carry it
//! into the policy enforcement boundary, but safe downstream Rust cannot construct a trusted-clear
//! state because all fields are private and there is no public constructor. T036/T052 will add the
//! Rust-owned validators/integration that produce this state from concrete trusted boundaries.

use crate::Verdict;

/// Stable identifier used when an action escapes the approved workspace boundary.
pub const WORKSPACE_BOUNDARY_INVARIANT_ID: &str = "SENTRDEL-KERNEL-WORKSPACE-BOUNDARY";
/// Stable identifier used when a controlled path attempts to disable required Evidence capture.
pub const EVIDENCE_CAPTURE_INVARIANT_ID: &str = "SENTRDEL-KERNEL-EVIDENCE-CAPTURE";
/// Stable identifier used when something other than the reconciler attempts to create a Finding.
pub const FINDING_AUTHORITY_INVARIANT_ID: &str = "SENTRDEL-KERNEL-FINDING-AUTHORITY";
/// Stable identifier used when missing or failed coverage is represented as an implicit clean result.
pub const COVERAGE_TRUTH_INVARIANT_ID: &str = "SENTRDEL-KERNEL-COVERAGE-TRUTH";

/// Rust-owned invariant catalogue for the T022 workspace/evidence/enforcement integrity slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelInvariant {
    /// Controlled writes/actions must remain inside the approved workspace scope.
    WorkspaceBoundary,
    /// Required Evidence capture cannot be disabled by repository-controlled policy/configuration.
    EvidenceCapture,
    /// Only the trusted reconciler may create canonical Findings from validated Evidence.
    FindingAuthority,
    /// Missing/failed analysis capability must remain an explicit coverage gap, never implicit clean.
    CoverageTruth,
}

impl KernelInvariant {
    /// Return the stable machine-readable identifier for this compiled Rust invariant.
    pub const fn id(self) -> &'static str {
        match self {
            Self::WorkspaceBoundary => WORKSPACE_BOUNDARY_INVARIANT_ID,
            Self::EvidenceCapture => EVIDENCE_CAPTURE_INVARIANT_ID,
            Self::FindingAuthority => FINDING_AUTHORITY_INVARIANT_ID,
            Self::CoverageTruth => COVERAGE_TRUTH_INVARIANT_ID,
        }
    }
}

/// Opaque trusted-core snapshot consumed by the policy enforcement boundary.
///
/// There is intentionally no public constructor, `Default`, `Deserialize`, or public field. The
/// later trusted validators that own each concrete boundary will be implemented inside this crate
/// and will be the only production source of a `KernelIntegrityState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelIntegrityState {
    workspace_within_approved: bool,
    evidence_capture_enabled: bool,
    finding_from_reconciler: bool,
    coverage_truth_explicit: bool,
}

#[cfg(test)]
impl KernelIntegrityState {
    pub(crate) const fn for_test(
        workspace_within_approved: bool,
        evidence_capture_enabled: bool,
        finding_from_reconciler: bool,
        coverage_truth_explicit: bool,
    ) -> Self {
        Self {
            workspace_within_approved,
            evidence_capture_enabled,
            finding_from_reconciler,
            coverage_truth_explicit,
        }
    }
}

/// Opaque result of the compiled Rust kernel invariant evaluation.
///
/// Fields are private, so downstream repository policy, plugins, engines, tool output, or model
/// output cannot directly mint a forged clear decision or remove violated invariant identifiers.
#[must_use = "kernel decisions must be applied before a later policy candidate can authorize an action"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelDecision {
    verdict: Verdict,
    violated_invariants: Vec<KernelInvariant>,
}

impl KernelDecision {
    /// Return `DENY` when any Rust-owned invariant failed, otherwise `ALLOW`.
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// Return the complete, deterministic set of violated compiled invariants.
    pub fn violated_invariants(&self) -> &[KernelInvariant] {
        &self.violated_invariants
    }

    /// Iterate stable invariant IDs suitable for PolicyDecision/ASEL reason binding.
    pub fn invariant_ids(&self) -> impl ExactSizeIterator<Item = &'static str> + '_ {
        self.violated_invariants
            .iter()
            .copied()
            .map(KernelInvariant::id)
    }

    /// Whether the Rust kernel has established an absorbing DENY floor.
    pub const fn is_deny(&self) -> bool {
        matches!(self.verdict, Verdict::Deny)
    }
}

/// Evaluate all compiled T022 invariants in deterministic catalogue order.
///
/// This function is crate-private so the public enforcement boundary owns evaluation and floor
/// application as one operation. Any violation yields `DENY`; all violations are retained for later
/// PolicyDecision/ASEL binding.
pub(crate) fn evaluate_kernel_invariants(state: KernelIntegrityState) -> KernelDecision {
    let mut violated = Vec::with_capacity(4);

    if !state.workspace_within_approved {
        violated.push(KernelInvariant::WorkspaceBoundary);
    }
    if !state.evidence_capture_enabled {
        violated.push(KernelInvariant::EvidenceCapture);
    }
    if !state.finding_from_reconciler {
        violated.push(KernelInvariant::FindingAuthority);
    }
    if !state.coverage_truth_explicit {
        violated.push(KernelInvariant::CoverageTruth);
    }

    let verdict = if violated.is_empty() {
        Verdict::Allow
    } else {
        Verdict::Deny
    };

    KernelDecision {
        verdict,
        violated_invariants: violated,
    }
}

/// Apply the non-overridable kernel floor to a later policy candidate.
#[must_use = "ignoring the enforced verdict can bypass an absorbing kernel DENY"]
pub(crate) fn enforce_kernel_floor(kernel: &KernelDecision, candidate: Verdict) -> Verdict {
    if kernel.is_deny() {
        Verdict::Deny
    } else {
        candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_state() -> KernelIntegrityState {
        KernelIntegrityState::for_test(true, true, true, true)
    }

    #[test]
    fn healthy_state_has_no_kernel_denial() {
        let decision = evaluate_kernel_invariants(healthy_state());
        assert_eq!(decision.verdict(), Verdict::Allow);
        assert!(!decision.is_deny());
        assert!(decision.violated_invariants().is_empty());
        assert_eq!(decision.invariant_ids().count(), 0);
    }

    #[test]
    fn outside_workspace_uses_binding_quickstart_invariant_id() {
        let decision =
            evaluate_kernel_invariants(KernelIntegrityState::for_test(false, true, true, true));

        assert_eq!(decision.verdict(), Verdict::Deny);
        assert_eq!(
            decision.invariant_ids().collect::<Vec<_>>(),
            vec![WORKSPACE_BOUNDARY_INVARIANT_ID]
        );
    }

    #[test]
    fn evidence_capture_cannot_be_disabled() {
        let decision =
            evaluate_kernel_invariants(KernelIntegrityState::for_test(true, false, true, true));

        assert_eq!(
            decision.invariant_ids().collect::<Vec<_>>(),
            vec![EVIDENCE_CAPTURE_INVARIANT_ID]
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn non_reconciler_cannot_create_canonical_finding() {
        let decision =
            evaluate_kernel_invariants(KernelIntegrityState::for_test(true, true, false, true));

        assert_eq!(
            decision.invariant_ids().collect::<Vec<_>>(),
            vec![FINDING_AUTHORITY_INVARIANT_ID]
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn coverage_gap_cannot_masquerade_as_clean() {
        let decision =
            evaluate_kernel_invariants(KernelIntegrityState::for_test(true, true, true, false));

        assert_eq!(
            decision.invariant_ids().collect::<Vec<_>>(),
            vec![COVERAGE_TRUTH_INVARIANT_ID]
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn multiple_violations_are_retained_in_stable_kernel_order() {
        let decision =
            evaluate_kernel_invariants(KernelIntegrityState::for_test(false, false, false, false));

        assert_eq!(
            decision.invariant_ids().collect::<Vec<_>>(),
            vec![
                WORKSPACE_BOUNDARY_INVARIANT_ID,
                EVIDENCE_CAPTURE_INVARIANT_ID,
                FINDING_AUTHORITY_INVARIANT_ID,
                COVERAGE_TRUTH_INVARIANT_ID,
            ]
        );
        assert_eq!(decision.verdict(), Verdict::Deny);
    }

    #[test]
    fn kernel_deny_cannot_be_downgraded_by_any_later_candidate() {
        let denied =
            evaluate_kernel_invariants(KernelIntegrityState::for_test(false, true, true, true));

        for candidate in [
            Verdict::Allow,
            Verdict::Ask,
            Verdict::Deny,
            Verdict::Undecidable,
        ] {
            assert_eq!(enforce_kernel_floor(&denied, candidate), Verdict::Deny);
        }
    }

    #[test]
    fn healthy_kernel_does_not_preempt_later_policy() {
        let healthy = evaluate_kernel_invariants(healthy_state());

        for candidate in [
            Verdict::Allow,
            Verdict::Ask,
            Verdict::Deny,
            Verdict::Undecidable,
        ] {
            assert_eq!(enforce_kernel_floor(&healthy, candidate), candidate);
        }
    }
}
