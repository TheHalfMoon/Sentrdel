use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sentrdel_schema::{
    SCHEMA_V1,
    coverage::{CoverageRecord, CoverageState},
    evidence::{EpistemicClass, EvidenceAuthority, EvidenceClaim, ProducerKind},
    project::ProjectProfile,
};
use sentrdel_store::{EvidenceStoreError, PersistentSink, StateStoreError, Store};
use sha2::{Digest, Sha256};

static NEXT_TEMP_DB: AtomicU64 = AtomicU64::new(0);
const SECRET: &str = "t019-canary-\"line\nvalue-Q7m3k9P2";

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sentrdel-t019-{label}-{}-{sequence}.sqlite3",
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

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn authority() -> EvidenceAuthority {
    EvidenceAuthority::from_runtime("t019-fixture", "1", ProducerKind::NativeRule)
        .expect("fixture authority")
}

fn claim(observation: String) -> EvidenceClaim {
    EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: vec!["sha256:fixture-input".to_owned()],
        observation,
        security_interpretation: None,
        category: "secret".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: Vec::new(),
        locations: Vec::new(),
        attributes: BTreeMap::new(),
        reproduction: None,
        captured_at: "2026-08-24T00:00:00Z".to_owned(),
    }
}

fn coverage(details: Option<String>) -> CoverageRecord {
    CoverageRecord {
        schema_version: SCHEMA_V1.to_owned(),
        coverage_id: "coverage:t019".to_owned(),
        capability: "secret-redaction".to_owned(),
        scope: ".".to_owned(),
        producer: Some("native".to_owned()),
        provider_dimension: None,
        state: CoverageState::Covered,
        reason_code: None,
        details,
        input_digests: vec!["sha256:fixture-input".to_owned()],
        observed_at: "2026-08-24T00:00:00Z".to_owned(),
    }
}

fn profile(language: String) -> ProjectProfile {
    ProjectProfile {
        schema_version: SCHEMA_V1.to_owned(),
        repository_id: "repo:t019".to_owned(),
        repository_root_digest: "sha256:fixture-root".to_owned(),
        languages: vec![language],
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

fn assert_bytes_do_not_contain(bytes: &[u8], needle: &[u8], label: &str) {
    assert!(
        !bytes.windows(needle.len()).any(|window| window == needle),
        "{label} contained forbidden canary bytes"
    );
}

#[test]
fn registered_secret_fails_closed_before_any_current_sqlite_write_path() {
    let temp = TempDb::new("sqlite-guard");
    let mut store = Store::open(&temp.path).expect("store opens");
    store
        .register_discovered_secret(SECRET)
        .expect("register secret");

    let unsafe_evidence = authority()
        .seal(claim(format!("literal matched: {SECRET}")))
        .expect("unsafe fixture can be sealed transiently");
    assert!(matches!(
        store.put_evidence(&unsafe_evidence),
        Err(EvidenceStoreError::Redaction(_))
    ));

    let digest = sha256_hex(SECRET);
    assert!(matches!(
        store.put_coverage_record(&coverage(Some(format!("sha256:{digest}")))),
        Err(StateStoreError::Redaction(_))
    ));
    assert!(matches!(
        store.put_project_profile(&profile(SECRET.to_owned())),
        Err(StateStoreError::Redaction(_))
    ));

    let safe_observation = store
        .redaction_boundary()
        .redact_text(&format!("literal matched: {SECRET}"));
    let safe_evidence = authority()
        .seal(claim(safe_observation))
        .expect("redacted fixture evidence");
    assert!(store.put_evidence(&safe_evidence).expect("safe insert"));

    let forbidden = [
        SECRET.as_bytes().to_vec(),
        serde_json::to_string(SECRET)
            .expect("fixture JSON")
            .as_bytes()[1..serde_json::to_string(SECRET).expect("fixture JSON").len() - 1]
            .to_vec(),
        digest.as_bytes().to_vec(),
        format!("sha256:{digest}").into_bytes(),
    ];

    for path in [
        temp.path.clone(),
        sidecar_path(&temp.path, "-wal"),
        sidecar_path(&temp.path, "-shm"),
    ] {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        for needle in &forbidden {
            assert_bytes_do_not_contain(&bytes, needle, &path.display().to_string());
        }
    }
}

#[test]
fn export_log_and_snapshot_fixtures_use_the_same_redaction_boundary() {
    let temp = TempDb::new("other-sinks");
    let mut store = Store::open(&temp.path).expect("store opens");
    store
        .register_discovered_secret(SECRET)
        .expect("register secret");

    let digest = sha256_hex(SECRET);
    let raw = format!("secret={SECRET}; digest=sha256:{digest}");

    for sink in [PersistentSink::Export, PersistentSink::Log, PersistentSink::Snapshot] {
        let redacted = store.redaction_boundary().redact_bytes(raw.as_bytes());
        store
            .redaction_boundary()
            .ensure_safe(sink, &redacted)
            .expect("redacted sink fixture is safe");
        assert_bytes_do_not_contain(&redacted, SECRET.as_bytes(), "sink fixture");
        assert_bytes_do_not_contain(&redacted, digest.as_bytes(), "sink fixture");
    }

    let error = store
        .redaction_boundary()
        .ensure_safe(PersistentSink::Log, raw.as_bytes())
        .expect_err("unsafe log fixture must fail");
    let rendered = error.to_string();
    assert!(!rendered.contains(SECRET));
    assert!(!rendered.contains(&digest));
}
