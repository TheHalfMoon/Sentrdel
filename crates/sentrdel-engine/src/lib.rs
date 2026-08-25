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

pub use boundary::{
    Engine, EngineDiagnostic, EngineInputRef, EngineLimits, EngineLimitsError, EngineRegistry,
    EngineRegistryError, EngineRequest, EngineRequestError, EngineRunError, EngineRunErrorKind,
    EngineRunFuture, EngineRunResult, EngineScope, NetworkAccessPolicy,
};
pub use runner::{
    EngineOutputStream, EngineProcessError, EngineProcessOutcome, EngineProcessSpec,
    EngineProcessSpecError, MAX_ENGINE_ARGUMENT_BYTES, MAX_ENGINE_ARGUMENTS,
    MAX_ENGINE_ENVIRONMENT_BYTES, MAX_ENGINE_ENVIRONMENT_ENTRIES, TrustedExecutable,
    TrustedExecutableError, run_engine_process,
};

const _: () = {
    assert!(!boundary::EXTERNAL_ENGINE_EXECUTION_IMPLEMENTED);
};

/// T027 has installed the bounded external-engine process runner.
///
/// This does not authorize T028 raw-result adaptation, T030 coverage mapping,
/// T036 bootstrap/DI wiring, target build execution, or shell evaluation.
pub const EXTERNAL_ENGINE_EXECUTION_IMPLEMENTED: bool = true;

#[cfg(test)]
mod tests {
    use super::EXTERNAL_ENGINE_EXECUTION_IMPLEMENTED;

    #[test]
    fn t027_enables_the_bounded_process_runner_surface() {
        const { assert!(EXTERNAL_ENGINE_EXECUTION_IMPLEMENTED) };
    }
}
