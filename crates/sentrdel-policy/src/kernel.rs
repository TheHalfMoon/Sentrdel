//! Rust-owned security invariants that repository policy and external evaluators cannot replace.
//!
//! `KernelIntegrityState` is an opaque capability-bearing snapshot. Downstream crates can carry it
//! into the policy enforcement boundary, but safe downstream Rust cannot construct a trusted-clear
//! state because all fields are private and there is no public constructor. T036 establishes the
//! canonical workspace/policy-authority bootstrap boundary; T052 will combine action-specific
//! trusted validators into `KernelIntegrityState` before enforcement.

use std::{
    error::Error,
    fmt, fs,
    path::{Component, Path, PathBuf},
};

use crate::Verdict;
use sentrdel_schema::policy::TrustedPolicyAuthority;

const MAX_POLICY_AUTHORITY_ID_BYTES: usize = 4_096;

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

/// Trusted policy bootstrap state created from process-owned configuration.
///
/// Repository/model/engine content cannot manufacture this value by
/// deserialization. The approved workspace is canonicalized before the runtime
/// opens mutable state, and policy authority metadata is validated before being
/// bound through `TrustedPolicyAuthority`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyBootstrap {
    workspace_root: PathBuf,
    authority: TrustedPolicyAuthority,
}

impl PolicyBootstrap {
    pub fn new(
        workspace_root: impl AsRef<Path>,
        authority_id: impl Into<String>,
        configuration_digest: impl Into<String>,
    ) -> Result<Self, PolicyBootstrapError> {
        let workspace_root = workspace_root.as_ref();
        if !workspace_root.is_absolute() {
            return Err(PolicyBootstrapError::WorkspaceRootNotAbsolute(
                workspace_root.to_path_buf(),
            ));
        }
        if contains_parent_component(workspace_root) {
            return Err(PolicyBootstrapError::WorkspaceParentTraversal(
                workspace_root.to_path_buf(),
            ));
        }
        let canonical_workspace = fs::canonicalize(workspace_root).map_err(|_| {
            PolicyBootstrapError::WorkspaceRootUnavailable(workspace_root.to_path_buf())
        })?;
        if !canonical_workspace.is_dir() {
            return Err(PolicyBootstrapError::WorkspaceRootUnavailable(
                workspace_root.to_path_buf(),
            ));
        }

        let authority_id = authority_id.into();
        if authority_id.trim().is_empty()
            || authority_id.len() > MAX_POLICY_AUTHORITY_ID_BYTES
            || authority_id.chars().any(char::is_control)
        {
            return Err(PolicyBootstrapError::InvalidAuthorityId);
        }

        let configuration_digest = configuration_digest.into();
        if !is_canonical_sha256_id(&configuration_digest) {
            return Err(PolicyBootstrapError::InvalidConfigurationDigest);
        }

        Ok(Self {
            workspace_root: canonical_workspace,
            authority: TrustedPolicyAuthority::from_runtime(authority_id, configuration_digest),
        })
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn authority(&self) -> &TrustedPolicyAuthority {
        &self.authority
    }

    /// Validate one existing path against the canonical approved workspace.
    ///
    /// Canonicalization resolves symlinks before containment is checked. This is
    /// a T036 bootstrap primitive, not a complete write-target validator; T052
    /// owns action-specific handling for paths that may not exist yet.
    pub fn validate_workspace_path(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<ValidatedWorkspacePath, PolicyBootstrapError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(PolicyBootstrapError::CandidatePathNotAbsolute(
                path.to_path_buf(),
            ));
        }
        if contains_parent_component(path) {
            return Err(PolicyBootstrapError::CandidateParentTraversal(
                path.to_path_buf(),
            ));
        }
        let canonical = fs::canonicalize(path)
            .map_err(|_| PolicyBootstrapError::CandidatePathUnavailable(path.to_path_buf()))?;
        if !canonical.starts_with(&self.workspace_root) {
            return Err(PolicyBootstrapError::CandidateOutsideWorkspace(canonical));
        }
        Ok(ValidatedWorkspacePath { path: canonical })
    }
}

/// Opaque evidence that one existing path resolved inside the approved
/// workspace. This is intentionally not serializable or directly constructible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedWorkspacePath {
    path: PathBuf,
}

impl ValidatedWorkspacePath {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyBootstrapError {
    WorkspaceRootNotAbsolute(PathBuf),
    WorkspaceParentTraversal(PathBuf),
    WorkspaceRootUnavailable(PathBuf),
    InvalidAuthorityId,
    InvalidConfigurationDigest,
    CandidatePathNotAbsolute(PathBuf),
    CandidateParentTraversal(PathBuf),
    CandidatePathUnavailable(PathBuf),
    CandidateOutsideWorkspace(PathBuf),
}

impl fmt::Display for PolicyBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceRootNotAbsolute(path) => {
                write!(formatter, "policy workspace root must be absolute: {path:?}")
            }
            Self::WorkspaceParentTraversal(path) => write!(
                formatter,
                "policy workspace root must not contain parent traversal: {path:?}"
            ),
            Self::WorkspaceRootUnavailable(path) => write!(
                formatter,
                "policy workspace root must exist as a canonical directory: {path:?}"
            ),
            Self::InvalidAuthorityId => formatter.write_str(
                "policy authority id must be bounded, non-blank text without control characters",
            ),
            Self::InvalidConfigurationDigest => formatter.write_str(
                "policy configuration digest must use sha256:<64 lowercase hex> form",
            ),
            Self::CandidatePathNotAbsolute(path) => {
                write!(formatter, "policy candidate path must be absolute: {path:?}")
            }
            Self::CandidateParentTraversal(path) => write!(
                formatter,
                "policy candidate path must not contain parent traversal: {path:?}"
            ),
            Self::CandidatePathUnavailable(path) => write!(
                formatter,
                "policy candidate path must exist for bootstrap validation: {path:?}"
            ),
            Self::CandidateOutsideWorkspace(path) => write!(
                formatter,
                "policy candidate path resolves outside the approved workspace: {path:?}"
            ),
        }
    }
}

impl Error for PolicyBootstrapError {}

fn contains_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn is_canonical_sha256_id(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Opaque trusted-core snapshot consumed by the policy enforcement boundary.
///
/// There is intentionally no public constructor, `Default`, `Deserialize`, or public field. T036
/// establishes the trusted workspace/authority bootstrap; T052 will produce this complete state
/// from concrete action-specific validators for all four invariants.
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
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_WORKSPACE_ID: AtomicU64 = AtomicU64::new(0);

    struct TestWorkspace {
        root: PathBuf,
    }

    impl TestWorkspace {
        fn new(label: &str) -> Self {
            let id = NEXT_WORKSPACE_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "sentrdel-policy-bootstrap-{label}-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("inside")).expect("create policy test workspace");
            Self { root }
        }

        fn bootstrap(&self) -> PolicyBootstrap {
            PolicyBootstrap::new(
                &self.root,
                "sentrdel-test-authority",
                format!("sha256:{}", "a".repeat(64)),
            )
            .expect("policy bootstrap")
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn healthy_state() -> KernelIntegrityState {
        KernelIntegrityState::for_test(true, true, true, true)
    }

    #[test]
    fn bootstrap_binds_canonical_workspace_and_policy_authority() {
        let workspace = TestWorkspace::new("canonical");
        let bootstrap = workspace.bootstrap();

        assert_eq!(bootstrap.workspace_root(), workspace.root.canonicalize().unwrap());
        assert_eq!(bootstrap.authority().id(), "sentrdel-test-authority");
        assert_eq!(
            bootstrap.authority().configuration_digest(),
            format!("sha256:{}", "a".repeat(64))
        );
        let inside = bootstrap
            .validate_workspace_path(workspace.root.join("inside"))
            .expect("inside path");
        assert!(inside.path().starts_with(bootstrap.workspace_root()));
    }

    #[test]
    fn bootstrap_rejects_untrusted_authority_and_digest_shapes() {
        let workspace = TestWorkspace::new("authority");
        assert!(matches!(
            PolicyBootstrap::new(
                &workspace.root,
                "   ",
                format!("sha256:{}", "a".repeat(64))
            ),
            Err(PolicyBootstrapError::InvalidAuthorityId)
        ));
        assert!(matches!(
            PolicyBootstrap::new(&workspace.root, "authority", "sha256:not-valid"),
            Err(PolicyBootstrapError::InvalidConfigurationDigest)
        ));
    }

    #[test]
    fn bootstrap_workspace_validation_fails_closed_outside_root() {
        let workspace = TestWorkspace::new("outside");
        let outside = TestWorkspace::new("other");
        let bootstrap = workspace.bootstrap();

        assert!(matches!(
            bootstrap.validate_workspace_path(outside.root.join("inside")),
            Err(PolicyBootstrapError::CandidateOutsideWorkspace(_))
        ));
        assert!(matches!(
            bootstrap.validate_workspace_path("relative/path"),
            Err(PolicyBootstrapError::CandidatePathNotAbsolute(_))
        ));
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
