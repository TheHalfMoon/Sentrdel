//! R1 `sentrdel guard install-git-hooks` output contract.
//!
//! Git hooks are explicitly PARTIAL enforcement because users and tools can
//! bypass local hooks. This layer renders an already-validated T056 install
//! plan and ownership record; it does not claim universal interception or
//! execute target repository code.

use std::{error::Error, fmt};

use sentrdel_guard::git_hooks::{
    HookInstallAction, HookInstallPlan, HookOwnershipMetadata,
};
use sentrdel_schema::policy::EnforcementFidelity;
use serde::Serialize;

use crate::{
    CliCommand, CliContractError, CliDecision, CliDiagnostic, CliDiagnosticLevel, CliEnvelope,
    CliRepository, CliTiming,
};

const PARTIAL_WARNING_CODE: &str = "GIT_HOOKS_PARTIAL_FIDELITY";
const PARTIAL_WARNING: &str =
    "Local Git hooks are bypassable and provide PARTIAL enforcement only; they are not universal agent or merge interception.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardGitHookInstallAction {
    CreateManagedHook,
    RefreshOwnedHook,
    ComposePreservingExisting,
}

impl From<&HookInstallAction> for GuardGitHookInstallAction {
    fn from(value: &HookInstallAction) -> Self {
        match value {
            HookInstallAction::CreateManagedHook => Self::CreateManagedHook,
            HookInstallAction::RefreshOwnedHook => Self::RefreshOwnedHook,
            HookInstallAction::ComposePreservingExisting { .. } => Self::ComposePreservingExisting,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GuardGitHookSummary {
    pub hook_name: String,
    pub action: GuardGitHookInstallAction,
    pub installed_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preserved_original_path: Option<String>,
    pub uninstall_restores_preserved_original: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GuardGitHooksSummary {
    pub enforcement_fidelity: EnforcementFidelity,
    pub hooks: Vec<GuardGitHookSummary>,
    pub warning: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GuardGitHooksOutput {
    #[serde(flatten)]
    envelope: CliEnvelope,
    pub guard: GuardGitHooksSummary,
}

impl GuardGitHooksOutput {
    pub fn new(
        repository: CliRepository,
        plans: &[(HookInstallPlan, HookOwnershipMetadata)],
        timing: CliTiming,
    ) -> Result<Self, GuardGitHooksOutputError> {
        if plans.is_empty() {
            return Err(GuardGitHooksOutputError::EmptyPlan);
        }

        let mut hooks = Vec::with_capacity(plans.len());
        for (plan, metadata) in plans {
            metadata.validate()?;
            if plan.hook_name != metadata.hook_name {
                return Err(GuardGitHooksOutputError::HookNameMismatch);
            }
            if plan.installed_digest != metadata.installed_digest {
                return Err(GuardGitHooksOutputError::InstalledDigestMismatch);
            }

            match &plan.action {
                HookInstallAction::ComposePreservingExisting { preserve_as } => {
                    if metadata.preserved_original_path.as_deref() != Some(preserve_as.as_str())
                        || metadata.preserved_original_digest.is_none()
                    {
                        return Err(GuardGitHooksOutputError::MissingCompositionMetadata);
                    }
                }
                HookInstallAction::CreateManagedHook | HookInstallAction::RefreshOwnedHook => {}
            }

            hooks.push(GuardGitHookSummary {
                hook_name: plan.hook_name.clone(),
                action: GuardGitHookInstallAction::from(&plan.action),
                installed_digest: plan.installed_digest.clone(),
                preserved_original_path: metadata.preserved_original_path.clone(),
                uninstall_restores_preserved_original: metadata.preserved_original_path.is_some(),
            });
        }
        hooks.sort_by(|left, right| left.hook_name.cmp(&right.hook_name));
        for pair in hooks.windows(2) {
            if pair[0].hook_name == pair[1].hook_name {
                return Err(GuardGitHooksOutputError::DuplicateHook(pair[0].hook_name.clone()));
            }
        }

        let diagnostic = CliDiagnostic::new(
            PARTIAL_WARNING_CODE,
            CliDiagnosticLevel::Warning,
            PARTIAL_WARNING,
        )?;
        let envelope = CliEnvelope::new(
            CliCommand::GuardInstallGitHooks,
            repository,
            CliDecision::Allow,
            Vec::new(),
            Vec::new(),
            vec![diagnostic],
            timing,
            None,
        )?;

        Ok(Self {
            envelope,
            guard: GuardGitHooksSummary {
                enforcement_fidelity: EnforcementFidelity::Partial,
                hooks,
                warning: PARTIAL_WARNING,
            },
        })
    }

    #[must_use]
    pub const fn envelope(&self) -> &CliEnvelope {
        &self.envelope
    }

    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        let mut output = serde_json::to_string(self)?;
        output.push('\n');
        Ok(output)
    }

    #[must_use]
    pub fn render_human(&self) -> String {
        let mut output = String::from("Git hook integration: PARTIAL\n");
        for hook in &self.guard.hooks {
            output.push_str("- ");
            output.push_str(&hook.hook_name);
            output.push_str(": ");
            output.push_str(action_name(hook.action));
            if let Some(path) = &hook.preserved_original_path {
                output.push_str("; original preserved at ");
                output.push_str(path);
                output.push_str(" for uninstall/restore");
            }
            output.push('\n');
        }
        output.push_str("Warning: ");
        output.push_str(PARTIAL_WARNING);
        output.push('\n');
        output
    }
}

#[derive(Debug)]
pub enum GuardGitHooksOutputError {
    Cli(CliContractError),
    Plan(sentrdel_guard::git_hooks::HookPlanError),
    EmptyPlan,
    HookNameMismatch,
    InstalledDigestMismatch,
    MissingCompositionMetadata,
    DuplicateHook(String),
}

impl fmt::Display for GuardGitHooksOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cli(error) => write!(formatter, "Git-hook CLI contract rejected output: {error}"),
            Self::Plan(error) => write!(formatter, "Git-hook ownership metadata is invalid: {error}"),
            Self::EmptyPlan => formatter.write_str("Git-hook install output requires at least one planned hook"),
            Self::HookNameMismatch => formatter.write_str("Git-hook plan and ownership metadata names differ"),
            Self::InstalledDigestMismatch => formatter.write_str("Git-hook plan and ownership metadata installed digests differ"),
            Self::MissingCompositionMetadata => formatter.write_str("composed Git-hook installation must retain exact restore metadata"),
            Self::DuplicateHook(name) => write!(formatter, "Git-hook install output contains duplicate hook {name:?}"),
        }
    }
}

impl Error for GuardGitHooksOutputError {}

impl From<CliContractError> for GuardGitHooksOutputError {
    fn from(value: CliContractError) -> Self {
        Self::Cli(value)
    }
}

impl From<sentrdel_guard::git_hooks::HookPlanError> for GuardGitHooksOutputError {
    fn from(value: sentrdel_guard::git_hooks::HookPlanError) -> Self {
        Self::Plan(value)
    }
}

const fn action_name(action: GuardGitHookInstallAction) -> &'static str {
    match action {
        GuardGitHookInstallAction::CreateManagedHook => "CREATE_MANAGED_HOOK",
        GuardGitHookInstallAction::RefreshOwnedHook => "REFRESH_OWNED_HOOK",
        GuardGitHookInstallAction::ComposePreservingExisting => "COMPOSE_PRESERVING_EXISTING",
    }
}

#[cfg(test)]
mod tests {
    use sentrdel_guard::git_hooks::{ObservedHook, plan_install};
    use serde_json::Value;

    use super::*;

    const MANAGED: &[u8] = b"#!/bin/sh\n# sentrdel managed hook\n";
    const EXISTING: &[u8] = b"#!/bin/sh\necho existing\n";

    fn repository() -> CliRepository {
        CliRepository::new("sha256:repo", ".").expect("repo")
    }

    #[test]
    fn missing_hook_reports_partial_fidelity_and_no_restore_path() {
        let plan = plan_install("pre-commit", &ObservedHook::Missing, MANAGED, None).unwrap();
        let metadata = HookOwnershipMetadata::new("pre-commit", MANAGED, None).unwrap();
        let output = GuardGitHooksOutput::new(
            repository(),
            &[(plan, metadata)],
            CliTiming::default(),
        )
        .unwrap();

        assert_eq!(
            output.guard.enforcement_fidelity,
            EnforcementFidelity::Partial
        );
        assert!(!output.guard.hooks[0].uninstall_restores_preserved_original);
        assert_eq!(output.envelope().exit_code().as_u8(), 0);
    }

    #[test]
    fn composition_exposes_restore_metadata_without_existing_hook_content() {
        let observed = ObservedHook::from_bytes(EXISTING);
        let plan = plan_install("pre-push", &observed, MANAGED, None).unwrap();
        let metadata = HookOwnershipMetadata::new(
            "pre-push",
            MANAGED,
            Some((".sentrdel/pre-push.original", EXISTING)),
        )
        .unwrap();
        let output = GuardGitHooksOutput::new(
            repository(),
            &[(plan, metadata)],
            CliTiming::default(),
        )
        .unwrap();

        assert_eq!(
            output.guard.hooks[0].preserved_original_path.as_deref(),
            Some(".sentrdel/pre-push.original")
        );
        assert!(output.guard.hooks[0].uninstall_restores_preserved_original);
        assert!(!output.render_json().unwrap().contains("echo existing"));
    }

    #[test]
    fn human_and_json_outputs_cannot_overclaim_enforcement() {
        let plan = plan_install("pre-commit", &ObservedHook::Missing, MANAGED, None).unwrap();
        let metadata = HookOwnershipMetadata::new("pre-commit", MANAGED, None).unwrap();
        let output = GuardGitHooksOutput::new(
            repository(),
            &[(plan, metadata)],
            CliTiming::default(),
        )
        .unwrap();

        let human = output.render_human();
        assert!(human.contains("Git hook integration: PARTIAL"));
        assert!(human.contains("bypassable"));
        assert!(!human.contains("ENFORCED"));

        let json = output.render_json().unwrap();
        let value: Value = serde_json::from_str(json.trim()).unwrap();
        assert_eq!(value["command"], "guard install-git-hooks");
        assert_eq!(value["guard"]["enforcement_fidelity"], "PARTIAL");
        assert_eq!(value["diagnostics"][0]["code"], PARTIAL_WARNING_CODE);
    }

    #[test]
    fn composition_fails_closed_without_matching_restore_metadata() {
        let plan = plan_install(
            "pre-push",
            &ObservedHook::from_bytes(EXISTING),
            MANAGED,
            None,
        )
        .unwrap();
        let metadata = HookOwnershipMetadata::new("pre-push", MANAGED, None).unwrap();
        assert!(matches!(
            GuardGitHooksOutput::new(repository(), &[(plan, metadata)], CliTiming::default()),
            Err(GuardGitHooksOutputError::MissingCompositionMetadata)
        ));
    }
}