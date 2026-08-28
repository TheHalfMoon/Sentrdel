//! Fail-closed planning metadata for safe Git-hook installation and removal.
//!
//! T056 deliberately separates mutation planning from the later CLI executor.
//! Existing unrelated hooks are never classified as replaceable. Composition
//! requires preserving the exact observed hook under a Sentrdel-owned path, and
//! uninstall may restore it only when both the managed hook and preserved copy
//! still match the recorded digests.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

const METADATA_VERSION: &str = "sentrdel.git-hooks.v1";
const MAX_HOOK_NAME_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedHook {
    Missing,
    Present { digest: String },
}

impl ObservedHook {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::Present {
            digest: digest(bytes),
        }
    }

    #[must_use]
    pub fn digest(&self) -> Option<&str> {
        match self {
            Self::Missing => None,
            Self::Present { digest } => Some(digest),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookOwnershipMetadata {
    pub metadata_version: String,
    pub hook_name: String,
    pub installed_digest: String,
    pub preserved_original_digest: Option<String>,
    pub preserved_original_path: Option<String>,
}

impl HookOwnershipMetadata {
    pub fn new(
        hook_name: impl Into<String>,
        installed_bytes: &[u8],
        preserved_original: Option<(&str, &[u8])>,
    ) -> Result<Self, HookPlanError> {
        let hook_name = hook_name.into();
        validate_hook_name(&hook_name)?;

        let (preserved_original_path, preserved_original_digest) =
            if let Some((path, bytes)) = preserved_original {
                validate_preserved_path(&hook_name, path)?;
                (Some(path.to_owned()), Some(digest(bytes)))
            } else {
                (None, None)
            };

        Ok(Self {
            metadata_version: METADATA_VERSION.to_owned(),
            hook_name,
            installed_digest: digest(installed_bytes),
            preserved_original_digest,
            preserved_original_path,
        })
    }

    pub fn validate(&self) -> Result<(), HookPlanError> {
        if self.metadata_version != METADATA_VERSION {
            return Err(HookPlanError::UnsupportedMetadataVersion(
                self.metadata_version.clone(),
            ));
        }
        validate_hook_name(&self.hook_name)?;
        validate_digest(&self.installed_digest)?;
        match (
            self.preserved_original_path.as_deref(),
            self.preserved_original_digest.as_deref(),
        ) {
            (None, None) => Ok(()),
            (Some(path), Some(digest_value)) => {
                validate_preserved_path(&self.hook_name, path)?;
                validate_digest(digest_value)
            }
            _ => Err(HookPlanError::IncompletePreservedOriginalMetadata),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookInstallAction {
    CreateManagedHook,
    RefreshOwnedHook,
    ComposePreservingExisting { preserve_as: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookInstallPlan {
    pub hook_name: String,
    pub action: HookInstallAction,
    pub expected_current_digest: Option<String>,
    pub installed_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookUninstallAction {
    RemoveManagedHook,
    RestorePreservedOriginal { preserved_path: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookUninstallPlan {
    pub hook_name: String,
    pub action: HookUninstallAction,
    pub expected_current_digest: String,
    pub expected_preserved_digest: Option<String>,
}

pub fn plan_install(
    hook_name: &str,
    observed: &ObservedHook,
    installed_bytes: &[u8],
    ownership: Option<&HookOwnershipMetadata>,
) -> Result<HookInstallPlan, HookPlanError> {
    validate_hook_name(hook_name)?;
    let installed_digest = digest(installed_bytes);

    match (observed, ownership) {
        (ObservedHook::Missing, None) => Ok(HookInstallPlan {
            hook_name: hook_name.to_owned(),
            action: HookInstallAction::CreateManagedHook,
            expected_current_digest: None,
            installed_digest,
        }),
        (ObservedHook::Missing, Some(_)) => Err(HookPlanError::OwnedHookMissing),
        (ObservedHook::Present { digest: current }, None) => {
            let preserve_as = preserved_path(hook_name);
            Ok(HookInstallPlan {
                hook_name: hook_name.to_owned(),
                action: HookInstallAction::ComposePreservingExisting { preserve_as },
                expected_current_digest: Some(current.clone()),
                installed_digest,
            })
        }
        (ObservedHook::Present { digest: current }, Some(metadata)) => {
            metadata.validate()?;
            if metadata.hook_name != hook_name {
                return Err(HookPlanError::HookNameMismatch);
            }
            if current != &metadata.installed_digest {
                return Err(HookPlanError::ManagedHookDrift {
                    expected: metadata.installed_digest.clone(),
                    observed: current.clone(),
                });
            }
            Ok(HookInstallPlan {
                hook_name: hook_name.to_owned(),
                action: HookInstallAction::RefreshOwnedHook,
                expected_current_digest: Some(current.clone()),
                installed_digest,
            })
        }
    }
}

pub fn plan_uninstall(
    hook_name: &str,
    observed_managed: &ObservedHook,
    observed_preserved: &ObservedHook,
    ownership: &HookOwnershipMetadata,
) -> Result<HookUninstallPlan, HookPlanError> {
    validate_hook_name(hook_name)?;
    ownership.validate()?;
    if ownership.hook_name != hook_name {
        return Err(HookPlanError::HookNameMismatch);
    }

    let current = observed_managed
        .digest()
        .ok_or(HookPlanError::OwnedHookMissing)?;
    if current != ownership.installed_digest {
        return Err(HookPlanError::ManagedHookDrift {
            expected: ownership.installed_digest.clone(),
            observed: current.to_owned(),
        });
    }

    match (
        ownership.preserved_original_path.as_deref(),
        ownership.preserved_original_digest.as_deref(),
    ) {
        (None, None) => {
            if !matches!(observed_preserved, ObservedHook::Missing) {
                return Err(HookPlanError::UnexpectedPreservedHook);
            }
            Ok(HookUninstallPlan {
                hook_name: hook_name.to_owned(),
                action: HookUninstallAction::RemoveManagedHook,
                expected_current_digest: current.to_owned(),
                expected_preserved_digest: None,
            })
        }
        (Some(path), Some(expected_preserved)) => {
            let observed = observed_preserved
                .digest()
                .ok_or(HookPlanError::PreservedHookMissing)?;
            if observed != expected_preserved {
                return Err(HookPlanError::PreservedHookDrift {
                    expected: expected_preserved.to_owned(),
                    observed: observed.to_owned(),
                });
            }
            Ok(HookUninstallPlan {
                hook_name: hook_name.to_owned(),
                action: HookUninstallAction::RestorePreservedOriginal {
                    preserved_path: path.to_owned(),
                },
                expected_current_digest: current.to_owned(),
                expected_preserved_digest: Some(expected_preserved.to_owned()),
            })
        }
        _ => Err(HookPlanError::IncompletePreservedOriginalMetadata),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookPlanError {
    InvalidHookName,
    InvalidPreservedPath,
    InvalidDigest,
    UnsupportedMetadataVersion(String),
    IncompletePreservedOriginalMetadata,
    HookNameMismatch,
    OwnedHookMissing,
    PreservedHookMissing,
    UnexpectedPreservedHook,
    ManagedHookDrift { expected: String, observed: String },
    PreservedHookDrift { expected: String, observed: String },
}

impl fmt::Display for HookPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHookName => formatter.write_str("Git hook name is not canonical"),
            Self::InvalidPreservedPath => {
                formatter.write_str("preserved Git-hook path is outside the Sentrdel-owned namespace")
            }
            Self::InvalidDigest => formatter.write_str("Git-hook digest is not canonical SHA-256"),
            Self::UnsupportedMetadataVersion(version) => {
                write!(formatter, "unsupported Git-hook metadata version {version:?}")
            }
            Self::IncompletePreservedOriginalMetadata => formatter.write_str(
                "preserved Git-hook metadata must contain both path and digest or neither",
            ),
            Self::HookNameMismatch => {
                formatter.write_str("Git-hook ownership metadata belongs to another hook")
            }
            Self::OwnedHookMissing => formatter.write_str(
                "Sentrdel ownership metadata exists but the managed Git hook is missing",
            ),
            Self::PreservedHookMissing => formatter.write_str(
                "Sentrdel recorded a preserved Git hook but the preserved copy is missing",
            ),
            Self::UnexpectedPreservedHook => formatter.write_str(
                "unexpected preserved Git hook exists without ownership metadata; refusing removal",
            ),
            Self::ManagedHookDrift { expected, observed } => write!(
                formatter,
                "managed Git hook changed since installation: expected {expected}, observed {observed}"
            ),
            Self::PreservedHookDrift { expected, observed } => write!(
                formatter,
                "preserved Git hook changed since installation: expected {expected}, observed {observed}"
            ),
        }
    }
}

impl Error for HookPlanError {}

fn validate_hook_name(name: &str) -> Result<(), HookPlanError> {
    if name.is_empty()
        || name.len() > MAX_HOOK_NAME_BYTES
        || name.starts_with('.')
        || name.contains('/')
        || name.contains('\\')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(HookPlanError::InvalidHookName);
    }
    Ok(())
}

fn preserved_path(hook_name: &str) -> String {
    format!(".sentrdel/{hook_name}.original")
}

fn validate_preserved_path(hook_name: &str, path: &str) -> Result<(), HookPlanError> {
    if path != preserved_path(hook_name) {
        return Err(HookPlanError::InvalidPreservedPath);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), HookPlanError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(HookPlanError::InvalidDigest);
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HookPlanError::InvalidDigest);
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANAGED: &[u8] = b"#!/bin/sh\n# sentrdel managed hook\n";
    const EXISTING: &[u8] = b"#!/bin/sh\necho existing\n";

    #[test]
    fn missing_hook_can_be_created_without_preservation() {
        let plan = plan_install("pre-commit", &ObservedHook::Missing, MANAGED, None).unwrap();
        assert_eq!(plan.action, HookInstallAction::CreateManagedHook);
        assert_eq!(plan.expected_current_digest, None);
    }

    #[test]
    fn unrelated_hook_is_never_planned_for_overwrite() {
        let observed = ObservedHook::from_bytes(EXISTING);
        let plan = plan_install("pre-commit", &observed, MANAGED, None).unwrap();
        assert_eq!(
            plan.action,
            HookInstallAction::ComposePreservingExisting {
                preserve_as: ".sentrdel/pre-commit.original".to_owned()
            }
        );
        assert_eq!(plan.expected_current_digest, observed.digest().map(str::to_owned));
    }

    #[test]
    fn owned_hook_may_refresh_only_when_current_digest_matches_metadata() {
        let metadata = HookOwnershipMetadata::new("pre-commit", MANAGED, None).unwrap();
        let observed = ObservedHook::from_bytes(MANAGED);
        assert_eq!(
            plan_install("pre-commit", &observed, b"new managed", Some(&metadata))
                .unwrap()
                .action,
            HookInstallAction::RefreshOwnedHook
        );

        let drifted = ObservedHook::from_bytes(b"user changed this hook");
        assert!(matches!(
            plan_install("pre-commit", &drifted, MANAGED, Some(&metadata)),
            Err(HookPlanError::ManagedHookDrift { .. })
        ));
    }

    #[test]
    fn composed_uninstall_restores_only_the_exact_preserved_original() {
        let metadata = HookOwnershipMetadata::new(
            "pre-push",
            MANAGED,
            Some((".sentrdel/pre-push.original", EXISTING)),
        )
        .unwrap();
        let plan = plan_uninstall(
            "pre-push",
            &ObservedHook::from_bytes(MANAGED),
            &ObservedHook::from_bytes(EXISTING),
            &metadata,
        )
        .unwrap();

        assert_eq!(
            plan.action,
            HookUninstallAction::RestorePreservedOriginal {
                preserved_path: ".sentrdel/pre-push.original".to_owned()
            }
        );
    }

    #[test]
    fn uninstall_refuses_managed_or_preserved_drift() {
        let metadata = HookOwnershipMetadata::new(
            "pre-commit",
            MANAGED,
            Some((".sentrdel/pre-commit.original", EXISTING)),
        )
        .unwrap();

        assert!(matches!(
            plan_uninstall(
                "pre-commit",
                &ObservedHook::from_bytes(b"managed changed"),
                &ObservedHook::from_bytes(EXISTING),
                &metadata,
            ),
            Err(HookPlanError::ManagedHookDrift { .. })
        ));
        assert!(matches!(
            plan_uninstall(
                "pre-commit",
                &ObservedHook::from_bytes(MANAGED),
                &ObservedHook::from_bytes(b"preserved changed"),
                &metadata,
            ),
            Err(HookPlanError::PreservedHookDrift { .. })
        ));
    }

    #[test]
    fn ownership_metadata_is_versioned_and_namespace_bounded() {
        let metadata = HookOwnershipMetadata::new(
            "pre-commit",
            MANAGED,
            Some((".sentrdel/pre-commit.original", EXISTING)),
        )
        .unwrap();
        assert_eq!(metadata.metadata_version, "sentrdel.git-hooks.v1");
        assert!(metadata.validate().is_ok());

        assert!(matches!(
            HookOwnershipMetadata::new(
                "pre-commit",
                MANAGED,
                Some(("../pre-commit", EXISTING)),
            ),
            Err(HookPlanError::InvalidPreservedPath)
        ));
        assert!(matches!(
            plan_install("../pre-commit", &ObservedHook::Missing, MANAGED, None),
            Err(HookPlanError::InvalidHookName)
        ));
    }
}
