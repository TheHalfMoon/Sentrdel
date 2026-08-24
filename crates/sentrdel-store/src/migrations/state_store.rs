use std::{error::Error, fmt};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sentrdel_schema::{
    SCHEMA_V1,
    canonical::{CanonicalError, canonical_json_bytes},
    coverage::CoverageRecord,
    engine::{EngineManifest, EngineRun},
    finding::{Finding, FindingError, FindingRecord, ReconcilerAuthority, WorkflowAuthorization},
    pack::SecurityPackManifest,
    project::ProjectProfile,
};

use crate::Store;

const COVERAGE_KIND: &str = "coverage";
const ENGINE_RUN_KIND: &str = "engine_run";
const ENGINE_MANIFEST_KIND: &str = "engine_manifest";
const SECURITY_PACK_MANIFEST_KIND: &str = "security_pack_manifest";

type FindingProjectionRow = (i64, Vec<u8>, Option<Vec<u8>>);

pub type StateStoreResult<T> = Result<T, StateStoreError>;

#[derive(Debug)]
pub enum StateStoreError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    Canonical(CanonicalError),
    FindingValidation(FindingError),
    UnsupportedSchemaVersion {
        object_kind: &'static str,
        found: String,
    },
    EmptyIdentity {
        object_kind: &'static str,
    },
    ImmutableConflict {
        object_kind: &'static str,
        object_id: String,
    },
    CorruptStoredObject {
        object_kind: &'static str,
        object_id: String,
        detail: &'static str,
    },
    RevisionOverflow {
        finding_id: String,
    },
}

impl fmt::Display for StateStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite state-store error: {error}"),
            Self::Json(error) => write!(formatter, "stored state JSON is invalid: {error}"),
            Self::Canonical(error) => write!(formatter, "state canonicalization failed: {error}"),
            Self::FindingValidation(error) => {
                write!(
                    formatter,
                    "stored Finding failed authority validation: {error}"
                )
            }
            Self::UnsupportedSchemaVersion { object_kind, found } => write!(
                formatter,
                "unsupported {object_kind} schema version {found:?}; R1 requires {SCHEMA_V1:?}"
            ),
            Self::EmptyIdentity { object_kind } => {
                write!(formatter, "{object_kind} identity must not be empty")
            }
            Self::ImmutableConflict {
                object_kind,
                object_id,
            } => write!(
                formatter,
                "immutable {object_kind} object {object_id:?} already exists with different canonical bytes"
            ),
            Self::CorruptStoredObject {
                object_kind,
                object_id,
                detail,
            } => write!(
                formatter,
                "stored {object_kind} object {object_id:?} failed integrity validation: {detail}"
            ),
            Self::RevisionOverflow { finding_id } => write!(
                formatter,
                "Finding {finding_id:?} cannot advance beyond the maximum SQLite revision"
            ),
        }
    }
}

impl Error for StateStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Canonical(error) => Some(error),
            Self::FindingValidation(error) => Some(error),
            Self::UnsupportedSchemaVersion { .. }
            | Self::EmptyIdentity { .. }
            | Self::ImmutableConflict { .. }
            | Self::CorruptStoredObject { .. }
            | Self::RevisionOverflow { .. } => None,
        }
    }
}

impl From<rusqlite::Error> for StateStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<serde_json::Error> for StateStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<CanonicalError> for StateStoreError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

impl From<FindingError> for StateStoreError {
    fn from(error: FindingError) -> Self {
        Self::FindingValidation(error)
    }
}

impl Store {
    /// Persist the current reconciled Finding projection and append an immutable
    /// history revision atomically. Byte-identical replay is a no-op.
    pub fn put_finding(&mut self, finding: &Finding) -> StateStoreResult<bool> {
        let record = finding.to_record();
        require_schema("Finding", &record.draft.schema_version)?;
        require_identity("Finding", &record.finding_id)?;
        let finding_id = record.finding_id.clone();
        let canonical = canonical_json_bytes(&record)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = current_finding_row(&transaction, &finding_id)?;

        match current {
            None => {
                transaction.execute(
                    "INSERT INTO sentrdel_finding_projection(finding_id, revision, canonical_json) VALUES (?1, 1, ?2)",
                    params![finding_id, canonical],
                )?;
                let inserted = transaction.execute(
                    "INSERT INTO sentrdel_finding_history(finding_id, revision, canonical_json) VALUES (?1, 1, ?2)",
                    params![finding_id, canonical],
                )?;
                if inserted != 1 {
                    return Err(StateStoreError::CorruptStoredObject {
                        object_kind: "Finding history",
                        object_id: finding_id,
                        detail: "initial history revision already exists",
                    });
                }
            }
            Some((revision, stored, history)) => {
                let Some(history) = history else {
                    return Err(StateStoreError::CorruptStoredObject {
                        object_kind: "Finding projection",
                        object_id: finding_id,
                        detail: "current projection has no matching history revision",
                    });
                };
                if history != stored {
                    return Err(StateStoreError::CorruptStoredObject {
                        object_kind: "Finding projection",
                        object_id: finding_id,
                        detail: "current projection bytes differ from its history revision",
                    });
                }
                if stored == canonical {
                    transaction.commit()?;
                    return Ok(false);
                }

                let next_revision =
                    revision
                        .checked_add(1)
                        .ok_or_else(|| StateStoreError::RevisionOverflow {
                            finding_id: finding_id.clone(),
                        })?;
                let inserted = transaction.execute(
                    "INSERT INTO sentrdel_finding_history(finding_id, revision, canonical_json) VALUES (?1, ?2, ?3)",
                    params![finding_id, next_revision, canonical],
                )?;
                if inserted != 1 {
                    return Err(StateStoreError::CorruptStoredObject {
                        object_kind: "Finding history",
                        object_id: finding_id,
                        detail: "next history revision already exists",
                    });
                }
                let updated = transaction.execute(
                    "UPDATE sentrdel_finding_projection SET revision = ?1, canonical_json = ?2 WHERE finding_id = ?3 AND revision = ?4",
                    params![next_revision, canonical, finding_id, revision],
                )?;
                if updated != 1 {
                    return Err(StateStoreError::CorruptStoredObject {
                        object_kind: "Finding projection",
                        object_id: finding_id,
                        detail: "current projection revision changed during atomic update",
                    });
                }
            }
        }

        transaction.commit()?;
        Ok(true)
    }

    /// Load the current Finding projection only after its bytes match the
    /// immutable history revision and runtime authorities accept the record.
    pub fn get_finding(
        &self,
        finding_id: &str,
        reconciler: &ReconcilerAuthority,
        authorization: Option<&WorkflowAuthorization>,
        now_unix_seconds: i64,
    ) -> StateStoreResult<Option<(i64, Finding)>> {
        let Some((revision, stored, history)) = current_finding_row(&self.connection, finding_id)?
        else {
            return Ok(None);
        };
        let Some(history) = history else {
            return Err(StateStoreError::CorruptStoredObject {
                object_kind: "Finding projection",
                object_id: finding_id.to_owned(),
                detail: "current projection has no matching history revision",
            });
        };
        if history != stored {
            return Err(StateStoreError::CorruptStoredObject {
                object_kind: "Finding projection",
                object_id: finding_id.to_owned(),
                detail: "current projection bytes differ from its history revision",
            });
        }

        let finding = decode_finding(
            &stored,
            finding_id,
            reconciler,
            authorization,
            now_unix_seconds,
        )?;
        Ok(Some((revision, finding)))
    }

    /// Load one immutable Finding history revision with explicit runtime
    /// authority. Old workflow revisions may require their original authority.
    pub fn get_finding_revision(
        &self,
        finding_id: &str,
        revision: i64,
        reconciler: &ReconcilerAuthority,
        authorization: Option<&WorkflowAuthorization>,
        now_unix_seconds: i64,
    ) -> StateStoreResult<Option<Finding>> {
        let stored: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT canonical_json FROM sentrdel_finding_history WHERE finding_id = ?1 AND revision = ?2",
                params![finding_id, revision],
                |row| row.get(0),
            )
            .optional()?;
        stored
            .map(|bytes| {
                decode_finding(
                    &bytes,
                    finding_id,
                    reconciler,
                    authorization,
                    now_unix_seconds,
                )
            })
            .transpose()
    }

    pub fn finding_revision_count(&self, finding_id: &str) -> StateStoreResult<i64> {
        Ok(self.connection.query_row(
            "SELECT COUNT(*) FROM sentrdel_finding_history WHERE finding_id = ?1",
            params![finding_id],
            |row| row.get(0),
        )?)
    }

    pub fn put_coverage_record(&self, record: &CoverageRecord) -> StateStoreResult<bool> {
        require_schema("CoverageRecord", &record.schema_version)?;
        require_identity("CoverageRecord", &record.coverage_id)?;
        let canonical = canonical_json_bytes(record)?;
        self.put_immutable_state(COVERAGE_KIND, &record.coverage_id, canonical)
    }

    pub fn get_coverage_record(
        &self,
        coverage_id: &str,
    ) -> StateStoreResult<Option<CoverageRecord>> {
        let Some(stored) = self.get_immutable_bytes(COVERAGE_KIND, coverage_id)? else {
            return Ok(None);
        };
        let record: CoverageRecord = serde_json::from_slice(&stored)?;
        require_typed_canonical(
            &stored,
            canonical_json_bytes(&record)?,
            "CoverageRecord",
            coverage_id,
        )?;
        require_schema("CoverageRecord", &record.schema_version)?;
        verify_identity("CoverageRecord", coverage_id, &record.coverage_id)?;
        Ok(Some(record))
    }

    /// Persist the latest ProjectProfile projection. A byte-identical refresh is
    /// a no-op; a changed profile replaces only this latest projection.
    pub fn put_project_profile(&self, profile: &ProjectProfile) -> StateStoreResult<bool> {
        require_schema("ProjectProfile", &profile.schema_version)?;
        require_identity("ProjectProfile", &profile.repository_id)?;
        let canonical = canonical_json_bytes(profile)?;
        let changed = self.connection.execute(
            "INSERT INTO sentrdel_project_profiles(repository_id, canonical_json) VALUES (?1, ?2) ON CONFLICT(repository_id) DO UPDATE SET canonical_json = excluded.canonical_json WHERE sentrdel_project_profiles.canonical_json <> excluded.canonical_json",
            params![profile.repository_id, canonical],
        )?;
        Ok(changed == 1)
    }

    pub fn get_project_profile(
        &self,
        repository_id: &str,
    ) -> StateStoreResult<Option<ProjectProfile>> {
        let stored: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT canonical_json FROM sentrdel_project_profiles WHERE repository_id = ?1",
                params![repository_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        let profile: ProjectProfile = serde_json::from_slice(&stored)?;
        require_typed_canonical(
            &stored,
            canonical_json_bytes(&profile)?,
            "ProjectProfile",
            repository_id,
        )?;
        require_schema("ProjectProfile", &profile.schema_version)?;
        verify_identity("ProjectProfile", repository_id, &profile.repository_id)?;
        Ok(Some(profile))
    }

    pub fn put_engine_run(&self, run: &EngineRun) -> StateStoreResult<bool> {
        require_schema("EngineRun", &run.schema_version)?;
        require_identity("EngineRun", &run.run_id)?;
        let canonical = canonical_json_bytes(run)?;
        self.put_immutable_state(ENGINE_RUN_KIND, &run.run_id, canonical)
    }

    pub fn get_engine_run(&self, run_id: &str) -> StateStoreResult<Option<EngineRun>> {
        let Some(stored) = self.get_immutable_bytes(ENGINE_RUN_KIND, run_id)? else {
            return Ok(None);
        };
        let run: EngineRun = serde_json::from_slice(&stored)?;
        require_typed_canonical(&stored, canonical_json_bytes(&run)?, "EngineRun", run_id)?;
        require_schema("EngineRun", &run.schema_version)?;
        verify_identity("EngineRun", run_id, &run.run_id)?;
        Ok(Some(run))
    }

    /// Persist manifest data without granting executable authority. The future
    /// engine runner must still resolve and authorize executables from trusted
    /// user/system configuration.
    pub fn put_engine_manifest(&self, manifest: &EngineManifest) -> StateStoreResult<bool> {
        require_schema("EngineManifest", &manifest.schema_version)?;
        require_identity("EngineManifest engine_id", &manifest.engine_id)?;
        require_identity("EngineManifest adapter_version", &manifest.adapter_version)?;
        let key = pair_key(&manifest.engine_id, &manifest.adapter_version)?;
        let canonical = canonical_json_bytes(manifest)?;
        self.put_immutable_state(ENGINE_MANIFEST_KIND, &key, canonical)
    }

    pub fn get_engine_manifest(
        &self,
        engine_id: &str,
        adapter_version: &str,
    ) -> StateStoreResult<Option<EngineManifest>> {
        let key = pair_key(engine_id, adapter_version)?;
        let Some(stored) = self.get_immutable_bytes(ENGINE_MANIFEST_KIND, &key)? else {
            return Ok(None);
        };
        let manifest: EngineManifest = serde_json::from_slice(&stored)?;
        require_typed_canonical(
            &stored,
            canonical_json_bytes(&manifest)?,
            "EngineManifest",
            &key,
        )?;
        require_schema("EngineManifest", &manifest.schema_version)?;
        verify_identity("EngineManifest engine_id", engine_id, &manifest.engine_id)?;
        verify_identity(
            "EngineManifest adapter_version",
            adapter_version,
            &manifest.adapter_version,
        )?;
        Ok(Some(manifest))
    }

    /// Persist Security Pack manifest data only. Persistence does not grant a
    /// pack authority to create Findings, weaken policy, or bypass engine rules.
    pub fn put_security_pack_manifest(
        &self,
        manifest: &SecurityPackManifest,
    ) -> StateStoreResult<bool> {
        require_schema("SecurityPackManifest", &manifest.schema_version)?;
        require_identity("SecurityPackManifest pack_id", &manifest.pack_id)?;
        require_identity("SecurityPackManifest version", &manifest.version)?;
        let key = pair_key(&manifest.pack_id, &manifest.version)?;
        let canonical = canonical_json_bytes(manifest)?;
        self.put_immutable_state(SECURITY_PACK_MANIFEST_KIND, &key, canonical)
    }

    pub fn get_security_pack_manifest(
        &self,
        pack_id: &str,
        version: &str,
    ) -> StateStoreResult<Option<SecurityPackManifest>> {
        let key = pair_key(pack_id, version)?;
        let Some(stored) = self.get_immutable_bytes(SECURITY_PACK_MANIFEST_KIND, &key)? else {
            return Ok(None);
        };
        let manifest: SecurityPackManifest = serde_json::from_slice(&stored)?;
        require_typed_canonical(
            &stored,
            canonical_json_bytes(&manifest)?,
            "SecurityPackManifest",
            &key,
        )?;
        require_schema("SecurityPackManifest", &manifest.schema_version)?;
        verify_identity("SecurityPackManifest pack_id", pack_id, &manifest.pack_id)?;
        verify_identity("SecurityPackManifest version", version, &manifest.version)?;
        Ok(Some(manifest))
    }

    fn put_immutable_state(
        &self,
        object_kind: &'static str,
        object_key: &str,
        canonical: Vec<u8>,
    ) -> StateStoreResult<bool> {
        let inserted = self.connection.execute(
            "INSERT INTO sentrdel_state_objects(object_kind, object_key, canonical_json) VALUES (?1, ?2, ?3) ON CONFLICT(object_kind, object_key) DO NOTHING",
            params![object_kind, object_key, canonical],
        )?;
        if inserted == 1 {
            return Ok(true);
        }

        let existing: Vec<u8> = self.connection.query_row(
            "SELECT canonical_json FROM sentrdel_state_objects WHERE object_kind = ?1 AND object_key = ?2",
            params![object_kind, object_key],
            |row| row.get(0),
        )?;
        if existing != canonical {
            return Err(StateStoreError::ImmutableConflict {
                object_kind,
                object_id: object_key.to_owned(),
            });
        }
        Ok(false)
    }

    fn get_immutable_bytes(
        &self,
        object_kind: &'static str,
        object_key: &str,
    ) -> StateStoreResult<Option<Vec<u8>>> {
        Ok(self
            .connection
            .query_row(
                "SELECT canonical_json FROM sentrdel_state_objects WHERE object_kind = ?1 AND object_key = ?2",
                params![object_kind, object_key],
                |row| row.get(0),
            )
            .optional()?)
    }
}

fn current_finding_row(
    connection: &Connection,
    finding_id: &str,
) -> StateStoreResult<Option<FindingProjectionRow>> {
    Ok(connection
        .query_row(
            "SELECT p.revision, p.canonical_json, h.canonical_json FROM sentrdel_finding_projection AS p LEFT JOIN sentrdel_finding_history AS h ON h.finding_id = p.finding_id AND h.revision = p.revision WHERE p.finding_id = ?1",
            params![finding_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?)
}

fn decode_finding(
    stored: &[u8],
    finding_id: &str,
    reconciler: &ReconcilerAuthority,
    authorization: Option<&WorkflowAuthorization>,
    now_unix_seconds: i64,
) -> StateStoreResult<Finding> {
    let record: FindingRecord = serde_json::from_slice(stored)?;
    require_typed_canonical(
        stored,
        canonical_json_bytes(&record)?,
        "Finding",
        finding_id,
    )?;
    verify_identity("Finding", finding_id, &record.finding_id)?;
    Ok(Finding::try_from_record(
        record,
        reconciler,
        authorization,
        now_unix_seconds,
    )?)
}

fn require_typed_canonical(
    stored: &[u8],
    recanonical: Vec<u8>,
    object_kind: &'static str,
    object_id: &str,
) -> StateStoreResult<()> {
    if recanonical != stored {
        return Err(StateStoreError::CorruptStoredObject {
            object_kind,
            object_id: object_id.to_owned(),
            detail: "stored bytes are not canonical for the typed schema object",
        });
    }
    Ok(())
}

fn require_schema(object_kind: &'static str, schema_version: &str) -> StateStoreResult<()> {
    if schema_version != SCHEMA_V1 {
        return Err(StateStoreError::UnsupportedSchemaVersion {
            object_kind,
            found: schema_version.to_owned(),
        });
    }
    Ok(())
}

fn require_identity(object_kind: &'static str, value: &str) -> StateStoreResult<()> {
    if value.trim().is_empty() {
        return Err(StateStoreError::EmptyIdentity { object_kind });
    }
    Ok(())
}

fn verify_identity(
    object_kind: &'static str,
    expected: &str,
    actual: &str,
) -> StateStoreResult<()> {
    if expected != actual {
        return Err(StateStoreError::CorruptStoredObject {
            object_kind,
            object_id: expected.to_owned(),
            detail: "row key does not match the stored record identity",
        });
    }
    Ok(())
}

fn pair_key(first: &str, second: &str) -> StateStoreResult<String> {
    Ok(serde_json::to_string(&(first, second))?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rusqlite::params;
    use sentrdel_schema::{
        SCHEMA_V1,
        canonical::canonical_json_bytes,
        coverage::{CoverageRecord, CoverageState},
        engine::{EngineManifest, EngineRun, NetworkRequirement, TerminationReason},
        finding::{
            EpistemicState, Finding, FindingError, ReconciledFindingDraft, ReconcilerAuthority,
            Severity, WorkflowAuthorization, WorkflowState,
        },
        pack::{SecurityPackManifest, SourceProvenance},
        project::ProjectProfile,
    };

    use super::StateStoreError;
    use crate::Store;

    static NEXT_TEMP_DB: AtomicU64 = AtomicU64::new(0);

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEMP_DB.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sentrdel-state-{label}-{}-{sequence}.sqlite3",
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

    fn reconciler() -> ReconcilerAuthority {
        ReconcilerAuthority::from_runtime("sentrdel-reconciler", "sha256:config")
            .expect("fixture reconciler")
    }

    fn finding() -> Finding {
        Finding::new_reconciled(
            ReconciledFindingDraft {
                schema_version: SCHEMA_V1.to_owned(),
                fingerprint: "fixture-fingerprint".to_owned(),
                title: "fixture finding".to_owned(),
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
            &reconciler(),
        )
        .expect("fixture finding")
    }

    fn coverage() -> CoverageRecord {
        CoverageRecord {
            schema_version: SCHEMA_V1.to_owned(),
            coverage_id: "coverage:fixture".to_owned(),
            capability: "fixture".to_owned(),
            scope: ".".to_owned(),
            producer: Some("native".to_owned()),
            provider_dimension: None,
            state: CoverageState::Covered,
            reason_code: None,
            details: None,
            input_digests: vec!["sha256:input".to_owned()],
            observed_at: "2026-08-24T00:00:00Z".to_owned(),
        }
    }

    fn profile() -> ProjectProfile {
        ProjectProfile {
            schema_version: SCHEMA_V1.to_owned(),
            repository_id: "repo:fixture".to_owned(),
            repository_root_digest: "sha256:root".to_owned(),
            languages: vec!["Rust".to_owned()],
            package_ecosystems: vec!["cargo".to_owned()],
            ci_systems: vec!["github-actions".to_owned()],
            mcp_configurations: Vec::new(),
            detected_providers: Vec::new(),
            detected_frameworks: Vec::new(),
            security_packs: Vec::new(),
            created_at: "2026-08-24T00:00:00Z".to_owned(),
            refreshed_at: "2026-08-24T00:00:00Z".to_owned(),
        }
    }

    fn engine_manifest() -> EngineManifest {
        EngineManifest {
            schema_version: SCHEMA_V1.to_owned(),
            engine_id: "fixture-engine".to_owned(),
            adapter_version: "1".to_owned(),
            executable_source: "trusted-config".to_owned(),
            executable_digest: Some("sha256:engine".to_owned()),
            expected_version_constraint: Some("1.x".to_owned()),
            input_dialects: vec!["repo".to_owned()],
            output_dialects: vec!["json".to_owned()],
            capabilities: vec!["fixture".to_owned()],
            timeout_ms: 1_000,
            max_stdout_bytes: 4_096,
            max_stderr_bytes: 4_096,
            allowed_environment_names: vec!["PATH".to_owned()],
            network_requirement: NetworkRequirement::None,
        }
    }

    fn engine_run() -> EngineRun {
        EngineRun {
            schema_version: SCHEMA_V1.to_owned(),
            run_id: "run:fixture".to_owned(),
            engine_manifest_digest: "sha256:manifest".to_owned(),
            input_digests: vec!["sha256:input".to_owned()],
            started_at: "2026-08-24T00:00:00Z".to_owned(),
            finished_at: "2026-08-24T00:00:01Z".to_owned(),
            exit_status: Some(0),
            termination_reason: TerminationReason::Completed,
            stdout_digest: Some("sha256:stdout".to_owned()),
            stderr_digest: None,
            produced_evidence_ids: vec!["sha256:evidence".to_owned()],
            coverage_ids: vec!["coverage:fixture".to_owned()],
        }
    }

    fn pack_manifest() -> SecurityPackManifest {
        SecurityPackManifest {
            schema_version: SCHEMA_V1.to_owned(),
            pack_id: "pack:fixture".to_owned(),
            version: "1".to_owned(),
            provider_or_framework: "fixture".to_owned(),
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
    fn finding_projection_history_is_atomic_and_authority_aware() {
        let temp = TempDb::new("finding-history");
        let mut store = Store::open(&temp.path).expect("store opens");
        let reconciler = reconciler();
        let mut finding = finding();
        let finding_id = finding.finding_id().to_owned();

        assert!(store.put_finding(&finding).expect("first revision"));
        assert!(!store.put_finding(&finding).expect("idempotent replay"));
        assert_eq!(
            store
                .finding_revision_count(&finding_id)
                .expect("history count"),
            1
        );
        let (revision, loaded) = store
            .get_finding(&finding_id, &reconciler, None, 100)
            .expect("current lookup")
            .expect("present");
        assert_eq!(revision, 1);
        assert_eq!(loaded.workflow_state(), &WorkflowState::New);

        let authorization = WorkflowAuthorization::from_runtime("user-policy", "approval:fixture")
            .expect("workflow authority");
        finding
            .transition(WorkflowState::TriagedFixNow, &authorization, None, 101)
            .expect("transition");
        assert!(store.put_finding(&finding).expect("second revision"));
        assert_eq!(
            store
                .finding_revision_count(&finding_id)
                .expect("history count"),
            2
        );

        assert!(matches!(
            store.get_finding(&finding_id, &reconciler, None, 102),
            Err(StateStoreError::FindingValidation(
                FindingError::MissingAuthorization
            ))
        ));
        let (revision, loaded) = store
            .get_finding(&finding_id, &reconciler, Some(&authorization), 102)
            .expect("authorized lookup")
            .expect("present");
        assert_eq!(revision, 2);
        assert_eq!(loaded.workflow_state(), &WorkflowState::TriagedFixNow);

        let original = store
            .get_finding_revision(&finding_id, 1, &reconciler, None, 102)
            .expect("history lookup")
            .expect("revision one");
        assert_eq!(original.workflow_state(), &WorkflowState::New);
    }

    #[test]
    fn current_finding_projection_must_match_immutable_history() {
        let temp = TempDb::new("finding-projection-tamper");
        let mut store = Store::open(&temp.path).expect("store opens");
        let reconciler = reconciler();
        let finding = finding();
        let finding_id = finding.finding_id().to_owned();
        store.put_finding(&finding).expect("persist");

        store
            .connection
            .execute(
                "UPDATE sentrdel_finding_projection SET canonical_json = ?1 WHERE finding_id = ?2",
                params![b"{}".as_slice(), finding_id],
            )
            .expect("test-only projection tamper");

        assert!(matches!(
            store.get_finding(&finding_id, &reconciler, None, 100),
            Err(StateStoreError::CorruptStoredObject { .. })
        ));
    }

    #[test]
    fn typed_canonicality_rejects_missing_optional_fields() {
        let temp = TempDb::new("typed-canonicality");
        let mut store = Store::open(&temp.path).expect("store opens");

        let mut coverage_value = serde_json::to_value(coverage()).expect("coverage value");
        coverage_value
            .as_object_mut()
            .expect("coverage object")
            .remove("producer");
        let coverage_bytes = canonical_json_bytes(&coverage_value).expect("generic canonical JSON");
        store
            .connection
            .execute(
                "INSERT INTO sentrdel_state_objects(object_kind, object_key, canonical_json) VALUES ('coverage', 'coverage:typed-canonical', ?1)",
                params![coverage_bytes],
            )
            .expect("inject schema-noncanonical coverage fixture");
        assert!(matches!(
            store.get_coverage_record("coverage:typed-canonical"),
            Err(StateStoreError::CorruptStoredObject { .. })
        ));

        let finding = finding();
        let finding_id = finding.finding_id().to_owned();
        let mut finding_value = serde_json::to_value(finding.to_record()).expect("finding value");
        finding_value
            .as_object_mut()
            .expect("finding object")
            .remove("primary_location");
        let finding_bytes = canonical_json_bytes(&finding_value).expect("generic canonical JSON");
        store
            .connection
            .execute(
                "INSERT INTO sentrdel_finding_projection(finding_id, revision, canonical_json) VALUES (?1, 1, ?2)",
                params![finding_id, finding_bytes],
            )
            .expect("inject finding projection fixture");
        store
            .connection
            .execute(
                "INSERT INTO sentrdel_finding_history(finding_id, revision, canonical_json) VALUES (?1, 1, ?2)",
                params![finding_id, finding_bytes],
            )
            .expect("inject finding history fixture");
        assert!(matches!(
            store.get_finding(&finding_id, &reconciler(), None, 100),
            Err(StateStoreError::CorruptStoredObject { .. })
        ));
    }

    #[test]
    fn immutable_records_round_trip_and_conflicts_fail_closed() {
        let temp = TempDb::new("immutable-records");
        let store = Store::open(&temp.path).expect("store opens");

        let coverage = coverage();
        assert!(
            store
                .put_coverage_record(&coverage)
                .expect("coverage insert")
        );
        assert!(
            !store
                .put_coverage_record(&coverage)
                .expect("coverage replay")
        );
        assert_eq!(
            store
                .get_coverage_record(&coverage.coverage_id)
                .expect("coverage lookup"),
            Some(coverage.clone())
        );
        let mut changed_coverage = coverage.clone();
        changed_coverage.details = Some("different".to_owned());
        assert!(matches!(
            store.put_coverage_record(&changed_coverage),
            Err(StateStoreError::ImmutableConflict { .. })
        ));

        let run = engine_run();
        assert!(store.put_engine_run(&run).expect("run insert"));
        assert_eq!(
            store.get_engine_run(&run.run_id).expect("run lookup"),
            Some(run)
        );

        let manifest = engine_manifest();
        assert!(
            store
                .put_engine_manifest(&manifest)
                .expect("engine manifest insert")
        );
        assert_eq!(
            store
                .get_engine_manifest(&manifest.engine_id, &manifest.adapter_version)
                .expect("engine manifest lookup"),
            Some(manifest)
        );

        let pack = pack_manifest();
        assert!(
            store
                .put_security_pack_manifest(&pack)
                .expect("pack insert")
        );
        assert_eq!(
            store
                .get_security_pack_manifest(&pack.pack_id, &pack.version)
                .expect("pack lookup"),
            Some(pack)
        );
    }

    #[test]
    fn immutable_state_rows_reject_direct_update_and_delete() {
        let temp = TempDb::new("immutable-sql");
        let store = Store::open(&temp.path).expect("store opens");
        let coverage = coverage();
        store
            .put_coverage_record(&coverage)
            .expect("persist coverage");

        let update = store.connection.execute(
            "UPDATE sentrdel_state_objects SET canonical_json = ?1 WHERE object_kind = 'coverage' AND object_key = ?2",
            params![b"{}".as_slice(), coverage.coverage_id],
        );
        assert!(update.is_err());
        let delete = store.connection.execute(
            "DELETE FROM sentrdel_state_objects WHERE object_kind = 'coverage' AND object_key = ?1",
            params![coverage.coverage_id],
        );
        assert!(delete.is_err());
    }

    #[test]
    fn project_profile_is_latest_projection() {
        let temp = TempDb::new("profile-projection");
        let store = Store::open(&temp.path).expect("store opens");
        let mut profile = profile();
        assert!(store.put_project_profile(&profile).expect("profile insert"));
        assert!(!store.put_project_profile(&profile).expect("profile replay"));

        profile.refreshed_at = "2026-08-24T01:00:00Z".to_owned();
        profile.languages.push("Python".to_owned());
        assert!(
            store
                .put_project_profile(&profile)
                .expect("profile refresh")
        );
        assert_eq!(
            store
                .get_project_profile(&profile.repository_id)
                .expect("profile lookup"),
            Some(profile)
        );
    }

    #[test]
    fn unsupported_schema_versions_are_rejected_before_persist() {
        let temp = TempDb::new("schema-version");
        let store = Store::open(&temp.path).expect("store opens");
        let mut coverage = coverage();
        coverage.schema_version = "future".to_owned();
        assert!(matches!(
            store.put_coverage_record(&coverage),
            Err(StateStoreError::UnsupportedSchemaVersion { .. })
        ));
    }

    #[test]
    fn pair_keys_are_unambiguous_for_manifest_identities() {
        let mut seen = BTreeMap::new();
        seen.insert(super::pair_key("a:b", "c").expect("key"), 1);
        seen.insert(super::pair_key("a", "b:c").expect("key"), 2);
        assert_eq!(seen.len(), 2);
    }
}
