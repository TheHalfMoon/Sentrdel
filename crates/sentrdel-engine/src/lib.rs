#![forbid(unsafe_code)]
//! Trusted external-engine boundary and bounded process runner.
//!
//! T026 owns the normalized adapter boundary and registry. T027 adds the only
//! R1 process-spawning implementation: trusted executable resolution,
//! argv-only invocation, canonical cwd, wall-clock/output bounds, and a
//! deny-by-default explicit child environment.

#[path = "boundary.rs"]
mod boundary;
mod runner;

use std::{error::Error, fmt};

use sentrdel_schema::engine::EngineManifest;

pub use boundary::{
    Engine, EngineDiagnostic, EngineInputRef, EngineLimits, EngineLimitsError, EngineRegistry,
    EngineRegistryError, EngineRequest, EngineRequestError, EngineRunError, EngineRunErrorKind,
    EngineRunFuture, EngineRunResult, EngineScope, NetworkAccessPolicy,
};
pub use runner::{
    EngineOutputStream, EngineProcessError, EngineProcessOutcome, EngineProcessSpec,
    EngineProcessSpecError, MAX_ENGINE_ARGUMENT_BYTES, MAX_ENGINE_ARGUMENTS,
    MAX_ENGINE_ENVIRONMENT_BYTES, MAX_ENGINE_ENVIRONMENT_ENTRIES, TrustedExecutable,
    TrustedExecutableError,
};

const _: () = {
    assert!(!boundary::EXTERNAL_ENGINE_EXECUTION_IMPLEMENTED);
};

/// T027 has installed the bounded external-engine process runner.
///
/// This does not authorize T028 raw-result adaptation, T030 coverage mapping,
/// T036 bootstrap/DI wiring, target build execution, or shell evaluation.
pub const EXTERNAL_ENGINE_EXECUTION_IMPLEMENTED: bool = true;

/// Public invocation failures at the T027 authority boundary.
///
/// Digest/version constraints are deliberately fail-closed until a qualified
/// adapter can provide a verified identity binding. The generic runner never
/// treats a declared constraint as satisfied merely because a path resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineInvocationError {
    ExecutableDigestRequiresVerifiedBinding,
    VersionConstraintRequiresVerifiedBinding,
    Process(EngineProcessError),
}

impl fmt::Display for EngineInvocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExecutableDigestRequiresVerifiedBinding => formatter.write_str(
                "engine executable digest is declared but no verified digest binding was supplied",
            ),
            Self::VersionConstraintRequiresVerifiedBinding => formatter.write_str(
                "engine version constraint is declared but no verified version binding was supplied",
            ),
            Self::Process(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for EngineInvocationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Process(error) => Some(error),
            Self::ExecutableDigestRequiresVerifiedBinding
            | Self::VersionConstraintRequiresVerifiedBinding => None,
        }
    }
}

impl From<EngineProcessError> for EngineInvocationError {
    fn from(value: EngineProcessError) -> Self {
        Self::Process(value)
    }
}

/// Run one qualified external engine through the sole T027 process authority.
///
/// The generic R1 runner accepts canonical trusted paths but cannot itself
/// prove engine-specific version semantics. When the manifest asserts an
/// executable digest or version constraint, invocation therefore fails closed
/// until a later qualified adapter supplies a verified binding rather than
/// silently weakening the manifest claim.
pub fn run_engine_process(
    manifest: &EngineManifest,
    spec: &EngineProcessSpec,
    limits: &EngineLimits,
) -> Result<EngineProcessOutcome, EngineInvocationError> {
    require_verified_identity_binding(manifest)?;
    runner::run_engine_process(manifest, spec, limits).map_err(EngineInvocationError::from)
}

fn require_verified_identity_binding(manifest: &EngineManifest) -> Result<(), EngineInvocationError> {
    if manifest.executable_digest.is_some() {
        return Err(EngineInvocationError::ExecutableDigestRequiresVerifiedBinding);
    }
    if manifest.expected_version_constraint.is_some() {
        return Err(EngineInvocationError::VersionConstraintRequiresVerifiedBinding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::engine::NetworkRequirement;

    fn manifest() -> EngineManifest {
        EngineManifest {
            schema_version: "1".to_owned(),
            engine_id: "fixture".to_owned(),
            adapter_version: "1".to_owned(),
            executable_source: "trusted-fixture".to_owned(),
            executable_digest: None,
            expected_version_constraint: None,
            input_dialects: vec!["fixture".to_owned()],
            output_dialects: vec!["raw".to_owned()],
            capabilities: vec!["fixture".to_owned()],
            timeout_ms: 1_000,
            max_stdout_bytes: 1_024,
            max_stderr_bytes: 1_024,
            allowed_environment_names: Vec::new(),
            network_requirement: NetworkRequirement::None,
        }
    }

    #[test]
    fn t027_enables_the_bounded_process_runner_surface() {
        const { assert!(EXTERNAL_ENGINE_EXECUTION_IMPLEMENTED) };
    }

    #[test]
    fn generic_runner_does_not_silently_accept_unverified_identity_constraints() {
        let mut fixture = manifest();
        fixture.executable_digest = Some("sha256:unverified".to_owned());
        assert_eq!(
            require_verified_identity_binding(&fixture),
            Err(EngineInvocationError::ExecutableDigestRequiresVerifiedBinding)
        );

        fixture.executable_digest = None;
        fixture.expected_version_constraint = Some("1.x".to_owned());
        assert_eq!(
            require_verified_identity_binding(&fixture),
            Err(EngineInvocationError::VersionConstraintRequiresVerifiedBinding)
        );
    }
}
