//! Tightening-only R3 invariant contract.
//!
//! Repository declarations are untrusted data. This module freezes the bounded
//! key/identifier/authority ceiling for a later loader; it does not parse TOML,
//! execute repository content, suppress Evidence, waive Findings, or grant
//! provider/runtime authority.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use super::model::InvariantEvaluationState;

pub const PROJECT_INVARIANT_EXECUTION_ALLOWED: bool = false;
pub const PROJECT_INVARIANT_FINDING_SUPPRESSION_ALLOWED: bool = false;
pub const PROJECT_INVARIANT_AUTHORITY_WIDENING_ALLOWED: bool = false;
pub const PROJECT_INVARIANT_SEVERITY_OVERRIDE_ALLOWED: bool = false;
pub const PROJECT_INVARIANT_ACCEPTED_RISK_ALLOWED: bool = false;

pub const DEFAULT_MAX_PROJECT_INVARIANT_FILE_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_PROJECT_INVARIANTS: usize = 128;
pub const DEFAULT_MAX_PROJECT_INVARIANT_ID_BYTES: usize = 96;
pub const DEFAULT_MAX_PROJECT_INVARIANT_KEYS: usize = 32;
pub const DEFAULT_MAX_PROJECT_INVARIANT_VALUE_BYTES: usize = 4 * 1024;

pub const PROJECT_INVARIANT_ALLOWED_KEYS: &[&str] = &[
    "id",
    "type",
    "resource",
    "route",
    "methods",
    "tenant_field",
    "actor",
    "roles",
    "operations",
    "properties",
    "required_guards",
    "allowed_contexts",
];

pub const PROJECT_INVARIANT_FORBIDDEN_AUTHORITY_KEYS: &[&str] = &[
    "suppress",
    "suppression",
    "waive",
    "waiver",
    "ignore",
    "severity",
    "confidence",
    "epistemic_class",
    "accepted_risk",
    "risk_acceptance",
    "network",
    "provider_credentials",
    "credential",
    "command",
    "plugin",
    "script",
    "template",
    "fact",
    "verified",
    "fix_verified",
    "policy_override",
    "kernel_override",
    "finding",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectInvariantLimits {
    pub max_file_bytes: usize,
    pub max_invariants: usize,
    pub max_id_bytes: usize,
    pub max_keys: usize,
    pub max_value_bytes: usize,
}

impl Default for ProjectInvariantLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_PROJECT_INVARIANT_FILE_BYTES,
            max_invariants: DEFAULT_MAX_PROJECT_INVARIANTS,
            max_id_bytes: DEFAULT_MAX_PROJECT_INVARIANT_ID_BYTES,
            max_keys: DEFAULT_MAX_PROJECT_INVARIANT_KEYS,
            max_value_bytes: DEFAULT_MAX_PROJECT_INVARIANT_VALUE_BYTES,
        }
    }
}

impl ProjectInvariantLimits {
    pub fn validate(self) -> Result<Self, ProjectInvariantContractError> {
        if self.max_file_bytes == 0
            || self.max_invariants == 0
            || self.max_id_bytes == 0
            || self.max_keys == 0
            || self.max_value_bytes == 0
        {
            return Err(ProjectInvariantContractError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectInvariantContractError {
    InvalidLimits,
    EmptyIdentifier,
    IdentifierTooLarge { bytes: usize, max: usize },
    InvalidIdentifierCharacter { index: usize },
    TooManyKeys { count: usize, max: usize },
    DuplicateKey(String),
    ForbiddenAuthorityKey(String),
    UnsupportedKey(String),
}

impl fmt::Display for ProjectInvariantContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("project invariant limits must be non-zero"),
            Self::EmptyIdentifier => formatter.write_str("project invariant id must not be empty"),
            Self::IdentifierTooLarge { bytes, max } => write!(
                formatter,
                "project invariant id size {bytes} exceeds cap {max}"
            ),
            Self::InvalidIdentifierCharacter { index } => write!(
                formatter,
                "project invariant id contains an unsupported character at byte {index}"
            ),
            Self::TooManyKeys { count, max } => write!(
                formatter,
                "project invariant key count {count} exceeds cap {max}"
            ),
            Self::DuplicateKey(key) => write!(formatter, "project invariant key is duplicated: {key}"),
            Self::ForbiddenAuthorityKey(key) => write!(
                formatter,
                "project invariant authority-bearing key is forbidden: {key}"
            ),
            Self::UnsupportedKey(key) => {
                write!(formatter, "project invariant key is unsupported: {key}")
            }
        }
    }
}

impl Error for ProjectInvariantContractError {}

pub fn validate_project_invariant_id(
    id: &str,
    limits: ProjectInvariantLimits,
) -> Result<(), ProjectInvariantContractError> {
    let limits = limits.validate()?;
    if id.is_empty() {
        return Err(ProjectInvariantContractError::EmptyIdentifier);
    }
    if id.len() > limits.max_id_bytes {
        return Err(ProjectInvariantContractError::IdentifierTooLarge {
            bytes: id.len(),
            max: limits.max_id_bytes,
        });
    }

    for (index, byte) in id.bytes().enumerate() {
        let supported = byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || (index > 0 && matches!(byte, b'-' | b'_'));
        if !supported {
            return Err(ProjectInvariantContractError::InvalidIdentifierCharacter { index });
        }
    }
    Ok(())
}

pub fn validate_project_invariant_keys(
    keys: &[&str],
    limits: ProjectInvariantLimits,
) -> Result<(), ProjectInvariantContractError> {
    let limits = limits.validate()?;
    if keys.len() > limits.max_keys {
        return Err(ProjectInvariantContractError::TooManyKeys {
            count: keys.len(),
            max: limits.max_keys,
        });
    }

    let allowed = PROJECT_INVARIANT_ALLOWED_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let forbidden = PROJECT_INVARIANT_FORBIDDEN_AUTHORITY_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();

    for key in keys {
        if !seen.insert(*key) {
            return Err(ProjectInvariantContractError::DuplicateKey((*key).to_owned()));
        }
        if forbidden.contains(key) {
            return Err(ProjectInvariantContractError::ForbiddenAuthorityKey(
                (*key).to_owned(),
            ));
        }
        if !allowed.contains(key) {
            return Err(ProjectInvariantContractError::UnsupportedKey(
                (*key).to_owned(),
            ));
        }
    }
    Ok(())
}

#[must_use]
pub const fn combine_tightening_requirement_states(
    built_in: InvariantEvaluationState,
    project: InvariantEvaluationState,
) -> InvariantEvaluationState {
    use InvariantEvaluationState::{NotApplicable, Satisfied, Unknown, Violated};

    match (built_in, project) {
        (Violated, _) | (_, Violated) => Violated,
        (Unknown, _) | (_, Unknown) => Unknown,
        (NotApplicable, NotApplicable) => NotApplicable,
        (Satisfied, Satisfied | NotApplicable) | (NotApplicable, Satisfied) => Satisfied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::business_logic::model::{BusinessLogicLimits, StableSemanticId};

    #[test]
    fn supported_project_ids_are_bounded_lowercase_ascii() {
        let limits = ProjectInvariantLimits::default();
        validate_project_invariant_id("accounts-tenant-binding", limits).unwrap();
        validate_project_invariant_id("admin_delete_2", limits).unwrap();
        for invalid in ["", "Sentrdel", "sentrdel.builtin", "../../escape", "tenant binding"] {
            assert!(validate_project_invariant_id(invalid, limits).is_err());
        }
    }

    #[test]
    fn authority_bearing_and_unknown_keys_fail_closed() {
        let limits = ProjectInvariantLimits::default();
        validate_project_invariant_keys(
            &["id", "type", "resource", "route", "methods", "roles"],
            limits,
        )
        .unwrap();

        for forbidden in PROJECT_INVARIANT_FORBIDDEN_AUTHORITY_KEYS {
            assert!(matches!(
                validate_project_invariant_keys(&["id", "type", forbidden], limits),
                Err(ProjectInvariantContractError::ForbiddenAuthorityKey(ref value)) if value == forbidden
            ));
        }
        assert!(matches!(
            validate_project_invariant_keys(&["id", "type", "future_magic"], limits),
            Err(ProjectInvariantContractError::UnsupportedKey(value)) if value == "future_magic"
        ));
    }

    #[test]
    fn project_requirement_can_never_relax_builtin_violation_or_unknown() {
        for project in [
            InvariantEvaluationState::Satisfied,
            InvariantEvaluationState::Violated,
            InvariantEvaluationState::Unknown,
            InvariantEvaluationState::NotApplicable,
        ] {
            assert_eq!(
                combine_tightening_requirement_states(InvariantEvaluationState::Violated, project),
                InvariantEvaluationState::Violated
            );
        }
        assert_eq!(
            combine_tightening_requirement_states(
                InvariantEvaluationState::Unknown,
                InvariantEvaluationState::Satisfied
            ),
            InvariantEvaluationState::Unknown
        );
    }

    #[test]
    fn builtin_and_project_identity_namespaces_cannot_collide() {
        let limits = BusinessLogicLimits::default();
        let builtin = StableSemanticId::from_parts(
            "sentrdel.r3.builtin-invariant",
            &["tenant-binding"],
            limits,
        )
        .unwrap();
        let project = StableSemanticId::from_parts(
            "sentrdel.r3.project-invariant",
            &["tenant-binding"],
            limits,
        )
        .unwrap();
        assert_ne!(builtin, project);
    }

    #[test]
    fn project_declarations_grant_no_suppression_execution_or_authority() {
        const { assert!(!PROJECT_INVARIANT_EXECUTION_ALLOWED) };
        const { assert!(!PROJECT_INVARIANT_FINDING_SUPPRESSION_ALLOWED) };
        const { assert!(!PROJECT_INVARIANT_AUTHORITY_WIDENING_ALLOWED) };
        const { assert!(!PROJECT_INVARIANT_SEVERITY_OVERRIDE_ALLOWED) };
        const { assert!(!PROJECT_INVARIANT_ACCEPTED_RISK_ALLOWED) };
    }
}
