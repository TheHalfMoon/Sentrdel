#[cfg(test)]
mod t029_fixture_tests {
    use super::*;
    use sentrdel_schema::engine::NetworkRequirement;
    use std::{
        env, fs,
        path::PathBuf,
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    const VALID_MINIMAL: &[u8] =
        include_bytes!("../../../fixtures/engines/native-valid-minimal.json");
    const VALID_MULTIPLE: &[u8] =
        include_bytes!("../../../fixtures/engines/native-valid-multiple.json");
    const VALID_EMPTY: &[u8] = include_bytes!("../../../fixtures/engines/native-empty.json");
    const MALFORMED: &[u8] = include_bytes!("../../../fixtures/engines/native-malformed.json");
    const OUT_OF_ROOT: &[u8] =
        include_bytes!("../../../fixtures/engines/native-out-of-root.json");
    const UNSUPPORTED_SCHEMA: &[u8] =
        include_bytes!("../../../fixtures/engines/native-unsupported-schema.json");

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn workspace(label: &str) -> (PathBuf, PathBuf) {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!(
            "sentrdel-t029-adapter-{label}-{}-{id}",
            process::id()
        ));
        let cwd = root.join("cwd");
        fs::create_dir_all(&cwd).expect("create T029 adapter fixture workspace");
        (root, cwd)
    }

    fn manifest() -> EngineManifest {
        EngineManifest {
            schema_version: SCHEMA_V1.to_owned(),
            engine_id: "t029-fixture-engine".to_owned(),
            adapter_version: "1".to_owned(),
            executable_source: "trusted-t029-test-binary".to_owned(),
            executable_digest: None,
            expected_version_constraint: None,
            input_dialects: vec!["fixture".to_owned()],
            output_dialects: vec![SENTRDEL_JSON_V1_DIALECT.to_owned()],
            capabilities: vec!["t029-adversarial-fixture".to_owned()],
            timeout_ms: 1_000,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 64 * 1024,
            allowed_environment_names: Vec::new(),
            network_requirement: NetworkRequirement::None,
        }
    }

    fn limits(manifest: &EngineManifest, label: &str) -> EngineLimits {
        let (root, cwd) = workspace(label);
        EngineLimits::from_manifest(manifest, root, cwd, crate::NetworkAccessPolicy::Deny)
            .expect("valid T029 adapter limits")
    }

    fn authority() -> EvidenceAuthority {
        EvidenceAuthority::from_runtime(
            "t029-fixture-engine",
            "1",
            ProducerKind::ExternalEngine,
        )
        .expect("external engine authority")
    }

    fn adapt_fixture(
        bytes: &[u8],
        label: &str,
    ) -> Result<Vec<Evidence>, EngineAdapterError> {
        let manifest = manifest();
        let limits = limits(&manifest, label);
        adapt_completed_output(
            &manifest,
            EngineOutputDialect::SentrdelJsonV1,
            bytes,
            &authority(),
            &limits,
            &[],
            "2026-08-26T00:00:00Z",
        )
    }

    #[test]
    fn valid_native_fixtures_are_accepted_by_the_canonical_adapter() {
        assert_eq!(
            adapt_fixture(VALID_MINIMAL, "valid-minimal")
                .expect("valid minimal fixture must adapt")
                .len(),
            1
        );
        assert_eq!(
            adapt_fixture(VALID_MULTIPLE, "valid-multiple")
                .expect("valid multiple fixture must adapt")
                .len(),
            2
        );
        assert!(
            adapt_fixture(VALID_EMPTY, "valid-empty")
                .expect("empty covered fixture must adapt")
                .is_empty()
        );
    }

    #[test]
    fn invalid_native_fixtures_are_rejected_by_the_canonical_adapter() {
        assert_eq!(
            adapt_fixture(MALFORMED, "malformed"),
            Err(EngineAdapterError::MalformedJson)
        );
        assert_eq!(
            adapt_fixture(UNSUPPORTED_SCHEMA, "unsupported-schema"),
            Err(EngineAdapterError::UnsupportedNativeSchemaVersion(
                "2".to_owned()
            ))
        );
        assert_eq!(
            adapt_fixture(OUT_OF_ROOT, "out-of-root"),
            Err(EngineAdapterError::Location(
                RepoLocationError::ParentTraversal
            ))
        );
    }
}
