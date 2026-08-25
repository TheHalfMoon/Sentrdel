//! Rust-owned security invariants that repository policy and external evaluators cannot replace.
//!
//! The caller is responsible for deriving these narrow states from trusted boundary validation.
//! This module deliberately does not deserialize repository-controlled policy into kernel state.
//! T022 establishes the decision primitive only; later bootstrap/guard integration must derive these
//! states from trusted validators and must apply the kernel floor before an action is authorized.

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceIntegrity {
    /// The action is proven to remain inside the approved workspace boundary.
    WithinApprovedWorkspace,
    /// The action reaches outside the approved workspace boundary.
    OutsideApprovedWorkspace,
}

/// Whether the controlled path preserves mandatory security Evidence capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceCaptureIntegrity {
    /// Required Evidence capture remains enabled.
    Enabled,
    /// Required Evidence capture has been disabled or bypassed.
    Disabled,
}

/// Authority attempting to create a canonical Finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingAuthorityIntegrity {
    /// The canonical Finding is created through the trusted reconciler boundary.
    Reconciler,
    /// A producer, plugin, repository policy, model, or other non-reconciler path attempts creation.
    NonReconciler,
}

/// Truthfulness of coverage handling for unavailable, missing, failed, or timed-out capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageIntegrity {
    /// Coverage limitations remain explicit and are not presented as evidence of cleanliness.
    Explicit,
    /// A missing/failed capability is being coerced into an implicit clean result.
    ImplicitCleanFromGap,
}

/// Narrow trusted state consumed by the Rust kernel invariant evaluator.
///
/// This is authority-bearing trusted-core input, not an authorization token to derive directly from
/// repository text. It has no serde/deserialization surface; callers must construct it only after
/// the applicable Rust boundary validator has established each classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelIntegrityState {
    workspace: WorkspaceIntegrity,
    evidence_capture: EvidenceCaptureIntegrity,
    finding_authority: FindingAuthorityIntegrity,
    coverage: CoverageIntegrity,
}

impl KernelIntegrityState {
    /// Build the exact trusted-state snapshot to evaluate for one policy decision boundary.
    pub const fn new(
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
/// Fields are private so downstream repository policy, plugins, engines, tool output, or model
/// output cannot directly construct a forged "kernel allowed" object. A decision is created only by
/// `evaluate_kernel_invariants` inside this crate.
#[must_use = "kernel decisions must be applied before a later policy candidate can authorize an action"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelDecision {
    verdict: Verdict,
    violated_invariants: Vec<KernelInvariant>,
}

impl KernelDecision {
    /// Return `DENY` when any Rust-owned invariant failed, otherwise `ALLOW`.
    ///
    /// `ALLOW` here means only "no T022 kernel invariant denied this state"; later user/repository
    /// policy may still make the action stricter.
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
/// Any violation yields `DENY`. All violations are retained so audit/event layers can explain every
/// core boundary that failed without trusting external policy text for the reason identifiers.
pub fn evaluate_kernel_invariants(state: KernelIntegrityState) -> KernelDecision {
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
/// A kernel `DENY` remains `DENY` against every candidate, including `ALLOW`, `ASK`, and
/// `UNDECIDABLE`. When the kernel has no violation, this function deliberately passes the candidate
/// through unchanged; T024 owns broader user/repository policy composition and narrowing semantics.
#[must_use = "ignoring the enforced verdict can bypass an absorbing kernel DENY"]
pub fn enforce_kernel_floor(kernel: &KernelDecision, candidate: Verdict) -> Verdict {
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
            vec!["SENTRDEL-KERNEL-WORKSPACE-BOUNDARY"]
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
