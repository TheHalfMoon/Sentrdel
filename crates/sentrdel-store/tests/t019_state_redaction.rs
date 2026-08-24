use sentrdel_schema::{
    SCHEMA_V1,
    coverage::{CoverageRecord, CoverageState},
    project::ProjectProfile,
};
use sentrdel_store::{StateStoreError, Store};

#[test]
fn current_state_write_paths_reject_registered_secret_material() {
    let path = std::env::temp_dir().join(format!(
        "sentrdel-t019-state-{}.sqlite3",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));

    let mut store = Store::open(&path).expect("store opens");
    let secret = "t019-state-secret-Z8p4L2";
    store
        .register_discovered_secret(secret)
        .expect("register secret");

    let coverage = CoverageRecord {
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
    };
    assert!(matches!(
        store.put_coverage_record(&coverage),
        Err(StateStoreError::Redaction(_))
    ));

    let profile = ProjectProfile {
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
    };
    assert!(matches!(
        store.put_project_profile(&profile),
        Err(StateStoreError::Redaction(_))
    ));

    drop(store);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}
