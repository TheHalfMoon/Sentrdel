//! Rust-owned security invariants that repository policy and external evaluators cannot replace.
//!
//! T022 keeps trusted classifications and state construction inside `sentrdel-policy`. Downstream
//! repository policy, plugins, engines, tool output, and model output can observe a `KernelDecision`
//! but cannot mint the trusted state that produces one. Later bootstrap/guard integration must
//! derive these crate-private classifications from Rust-owned validators before authorization.

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

/// Trusted workspace-boundary classification for the exact normalized action scope.
///
/// Crate-private by design: arbitrary downstream callers cannot assert that an action is in scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkspaceIntegrity {
    /// The action is proven to remain inside the approved workspace boundary.
    WithinApprovedWorkspace,
    /// The action reaches outside the approved workspace boundary.
    OutsideApprovedWorkspace,
}

/// Whether the controlled path preserves mandatory security Evidence capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvidenceCaptureIntegrity {
    /// Required Evidence capture remains enabled.
    Enabled,
    /// Required Evidence capture has been disabled or bypassed.
    Disabled,
}

/// Authority attempting to create a canonical Finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FindingAuthorityIntegrity {
    /// The canonical Finding is created through the trusted reconciler boundary.
    Reconciler,
    /// A producer, plugin, repository policy, model, or other non-reconciler path attempts creation.
    NonReconciler,
}

/// Truthfulness of coverage handling for unavailable, missing, failed, or timed-out capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoverageIntegrity {
    /// Coverage limitations remain explicit and are not presented as evidence of cleanliness.
    Explicit,
    /// A missing/failed capability is being coerced into an implicit clean result.
    ImplicitCleanFromGap,
}

/// Narrow trusted state consumed by the Rust kernel invariant evaluator.
///
/// Both the type and its constructor are crate-private. Repository-controlled or other downstream
/// code therefore cannot manufacture a healthy kernel state through the public Rust API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KernelIntegrityState {
    workspace: WorkspaceIntegrity,
    evidence_capture: EvidenceCaptureIntegrity,
    finding_authority: FindingAuthorityIntegrity,
    coverage: CoverageIntegrity,
}

impl KernelIntegrityState {
    /// Build a trusted-state snapshot after Rust-owned boundary validation has classified each axis.
    pub(crate) const fn new(
        workspace: WorkspaceIntegrity,
        evidence_capture: EvidenceCaptureIntegrity,
        finding_authority: FindingAuthorityIntegrity,
        coverage: CoverageIntegrity,
    ) -> Self {
        Self {
            workspace,
            evidence_capture,
            finding_authority,
            coverage,
        }
    }
}

/// Opaque result of the compiled Rust kernel invariant evaluation.
///
/// Fields are private and the evaluator is crate-private, so downstream code cannot directly mint a
/// forged clear decision. Trusted integration code may receive this type only from policy-owned
/// validation/evaluation paths.
#[must_use = "kernel decisions must be applied before a later policy candidate can authorize an action"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelDecision {
    verdict: Verdict,
    violated_invariants: Vec<KernelInvariant>,
}

impl KernelDecision {
    /// Return `DENY` when any Rust-owned invariant failed, otherwise `ALLOW`.
    ///
    /// `ALLOW` here means only "all T022 kernel classifications supplied by the trusted policy core
    /// were clear"; later user/repository policy may still make the action stricter.
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

/// Evaluate the compiled T022 kernel invariants in deterministic catalogue order.
///
/// This evaluator is crate-private because its input is authority-bearing trusted state. Any
/// violation yields `DENY`. All violations are retained so later audit/event layers can explain
/// every core boundary that failed without trusting external policy text for reason identifiers.
pub(crate) fn evaluate_kernel_invariants(state: KernelIntegrityState) -> KernelDecision {
    let mut violated = Vec::with_capacity(4);

    if state.workspace == WorkspaceIntegrity::OutsideApprovedWorkspace {
        violated.push(KernelInvariant::WorkspaceBoundary);
    }
    if state.evidence_capture == EvidenceCaptureIntegrity::Disabled {
        violated.push(KernelInvariant::EvidenceCapture);
    }
    if state.finding_authority == FindingAuthorityIntegrity::NonReconciler {
        violated.push(KernelInvariant::FindingAuthority);
    }
    if state.coverage == CoverageIntegrity::ImplicitCleanFromGap {
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
///
/// Kept crate-private so the public enforcement API in the crate root is the single policy-owned
/// path that converts a composed policy candidate into an enforceable verdict.
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
        KernelIntegrityState::new(
            WorkspaceIntegrity::WithinApprovedWorkspace,
            EvidenceCaptureIntegrity::Enabled,
            FindingAuthorityIntegrity::Reconciler,
            CoverageIntegrity::Explicit,
        )
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
        let decision = evaluate_kernel_invariants(KernelIntegrityState::new(
            WorkspaceIntegrity::OutsideApprovedWorkspace,
            EvidenceCaptureIntegrity::Enabled,
            FindingAuthorityIntegrity::Reconciler,
            CoverageIntegrity::Explicit,
        ));

        assert_eq!(decision.verdict(), Verdict::Deny);
        assert_eq!(
            decision.invariant_ids().collect::<Vec<_>>(),
            vec![WORKSPACE_BOUNDARY_INVARIANT_ID]
        );
    }

    #[test]
    fn evidence_capture_cannot_be_disabled() {
        let decision = evaluate_kernel_invariants(KernelIntegrityState::new(
            WorkspaceIntegrity::WithinApprovedWorkspace,
            EvidenceCaptureIntegrity::Disabled,
            FindingAuthorityIntegrity::Reconciler,
            CoverageIntegrity::Explicit,
        ));

        assert_eq!(
            decision.invariant_ids().collect::<Vec<_>>(),
            vec![EVIDENCE_CAPTURE_INVARIANT_ID]
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn non_reconciler_cannot_create_canonical_finding() {
        let decision = evaluate_kernel_invariants(KernelIntegrityState::new(
            WorkspaceIntegrity::WithinApprovedWorkspace,
            EvidenceCaptureIntegrity::Enabled,
            FindingAuthorityIntegrity::NonReconciler,
            CoverageIntegrity::Explicit,
        ));

        assert_eq!(
            decision.invariant_ids().collect::<Vec<_>>(),
            vec![FINDING_AUTHORITY_INVARIANT_ID]
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn coverage_gap_cannot_masquerade_as_clean() {
        let decision = evaluate_kernel_invariants(KernelIntegrityState::new(
            WorkspaceIntegrity::WithinApprovedWorkspace,
            EvidenceCaptureIntegrity::Enabled,
            FindingAuthorityIntegrity::Reconciler,
            CoverageIntegrity::ImplicitCleanFromGap,
        ));

        assert_eq!(
            decision.invariant_ids().collect::<Vec<_>>(),
            vec![COVERAGE_TRUTH_INVARIANT_ID]
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn multiple_violations_are_retained_in_stable_kernel_order() {
        let decision = evaluate_kernel_invariants(KernelIntegrityState::new(
            WorkspaceIntegrity::OutsideApprovedWorkspace,
            EvidenceCaptureIntegrity::Disabled,
            FindingAuthorityIntegrity::NonReconciler,
            CoverageIntegrity::ImplicitCleanFromGap,
        ));

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
        let denied = evaluate_kernel_invariants(KernelIntegrityState::new(
            WorkspaceIntegrity::OutsideApprovedWorkspace,
            EvidenceCaptureIntegrity::Enabled,
            FindingAuthorityIntegrity::Reconciler,
            CoverageIntegrity::Explicit,
        ));

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
