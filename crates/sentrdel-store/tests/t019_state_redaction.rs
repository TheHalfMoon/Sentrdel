use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sentrdel_schema::{
    SCHEMA_V1,
    coverage::{CoverageRecord, CoverageState},
    engine::{EngineManifest, EngineRun, NetworkRequirement, TerminationReason},
    finding::{EpistemicState, Finding, ReconciledFindingDraft, ReconcilerAuthority, Severity},
    pack::{SecurityPackManifest, SourceProvenance},
    project::ProjectProfile,
};
use sentrdel_store::{StateStoreError, Store};

static NEXT_TEMP_DB: AtomicU64 = AtomicU64::new(0);

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sentrdel-t019-state-{label}-{}-{sequence}.sqlite3",
            std::process::id()
        ));
        cleanup_database_files(&path);
        Self { path }
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        cleanup_database_files(&self.path);
    }
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn cleanup_database_files(path: &Path) {
    for candidate in [
        path.to_path_buf(),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
    ] {
        match fs::remove_file(candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("failed to remove temporary SQLite file: {error}"),
        }
    }
}

fn finding(secret: &str) -> Finding {
    let reconciler = ReconcilerAuthority::from_runtime("sentrdel-reconciler", "sha256:t019-config")
        .expect("fixture reconciler");
    Finding::new_reconciled(
        ReconciledFindingDraft {
            schema_version: SCHEMA_V1.to_owned(),
            fingerprint: "t019-fingerprint".to_owned(),
            title: secret.to_owned(),
            impact_statement: "fixture impact".to_owned(),
            category: "fixture".to_owned(),
            severity: Severity::High,
            epistemic_state: EpistemicState::Detected,
            evidence_ids: vec!["sha256:evidence".to_owned()],
            contradiction_ids: Vec::new(),
            primary_location: None,
            affected_subjects: Vec::new(),
            first_seen_commit: None,
            last_seen_commit: None,
            remediation: None,
            updated_at: "2026-08-24T00:00:00Z".to_owned(),
        },
        &reconciler,
    )
    .expect("fixture finding")
}

fn coverage(secret: &str) -> CoverageRecord {
    CoverageRecord {
        schema_version: SCHEMA_V1.to_owned(),
        coverage_id: "coverage:t019-state".to_owned(),
        capability: "fixture".to_owned(),
        scope: ".".to_owned(),
        producer: Some("native".to_owned()),
        provider_dimension: None,
        state: CoverageState::Covered,
        reason_code: None,
        details: Some(secret.to_owned()),
        input_digests: vec!["sha256:fixture-input".to_owned()],
        observed_at: "2026-08-24T00:00:00Z".to_owned(),
    }
}

fn profile(secret: &str) -> ProjectProfile {
    ProjectProfile {
        schema_version: SCHEMA_V1.to_owned(),
        repository_id: "repo:t019-state".to_owned(),
        repository_root_digest: "sha256:root".to_owned(),
        languages: vec![secret.to_owned()],
        package_ecosystems: Vec::new(),
        ci_systems: Vec::new(),
        mcp_configurations: Vec::new(),
        detected_providers: Vec::new(),
        detected_frameworks: Vec::new(),
        security_packs: Vec::new(),
        created_at: "2026-08-24T00:00:00Z".to_owned(),
        refreshed_at: "2026-08-24T00:00:00Z".to_owned(),
    }
}

fn engine_run(secret: &str) -> EngineRun {
    EngineRun {
        schema_version: SCHEMA_V1.to_owned(),
        run_id: "run:t019-state".to_owned(),
        engine_manifest_digest: "sha256:manifest".to_owned(),
        input_digests: vec!["sha256:input".to_owned()],
        started_at: "2026-08-24T00:00:00Z".to_owned(),
        finished_at: "2026-08-24T00:00:01Z".to_owned(),
        exit_status: Some(0),
        termination_reason: TerminationReason::Completed,
        stdout_digest: Some(secret.to_owned()),
        stderr_digest: None,
        produced_evidence_ids: Vec::new(),
        coverage_ids: Vec::new(),
    }
}

fn engine_manifest(secret: &str) -> EngineManifest {
    EngineManifest {
        schema_version: SCHEMA_V1.to_owned(),
        engine_id: "engine:t019-state".to_owned(),
        adapter_version: "1".to_owned(),
        executable_source: secret.to_owned(),
        executable_digest: None,
        expected_version_constraint: None,
        input_dialects: vec!["repo".to_owned()],
        output_dialects: vec!["json".to_owned()],
        capabilities: vec!["fixture".to_owned()],
        timeout_ms: 1_000,
        max_stdout_bytes: 4_096,
        max_stderr_bytes: 4_096,
        allowed_environment_names: Vec::new(),
        network_requirement: NetworkRequirement::None,
    }
}

fn security_pack_manifest(secret: &str) -> SecurityPackManifest {
    SecurityPackManifest {
        schema_version: SCHEMA_V1.to_owned(),
        pack_id: "pack:t019-state".to_owned(),
        version: "1".to_owned(),
        provider_or_framework: secret.to_owned(),
        source_provenance: SourceProvenance {
            source_id: "native".to_owned(),
            exact_ref: "builtin".to_owned(),
            license_expression: "Apache-2.0".to_owned(),
            integrity_digest: None,
        },
        detection_capabilities: vec!["detect".to_owned()],
        evidence_capabilities: vec!["fixture".to_owned()],
        required_engines: Vec::new(),
        required_features: Vec::new(),
        coverage_dimensions: vec!["DETECTION".to_owned()],
    }
}

#[test]
fn every_current_state_write_path_rejects_registered_secret_material() {
    let temp = TempDb::new("all-write-paths");
    let mut store = Store::open(&temp.path).expect("store opens");
    let secret = "t019-state-secret-Z8p4L2";
    store
        .register_discovered_secret(secret)
        .expect("register secret");

    assert!(matches!(
        store.put_finding(&finding(secret)),
        Err(StateStoreError::Redaction(_))
    ));
    assert!(matches!(
        store.put_coverage_record(&coverage(secret)),
        Err(StateStoreError::Redaction(_))
    ));
    assert!(matches!(
        store.put_project_profile(&profile(secret)),
        Err(StateStoreError::Redaction(_))
    ));
    assert!(matches!(
        store.put_engine_run(&engine_run(secret)),
        Err(StateStoreError::Redaction(_))
    ));
    assert!(matches!(
        store.put_engine_manifest(&engine_manifest(secret)),
        Err(StateStoreError::Redaction(_))
    ));
    assert!(matches!(
        store.put_security_pack_manifest(&security_pack_manifest(secret)),
        Err(StateStoreError::Redaction(_))
    ));
}
