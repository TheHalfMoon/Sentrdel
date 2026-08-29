//! Conservative repository-derived Supabase API schema exposure observations.
//!
//! This module consumes already-bounded repository configuration facts. It does
//! not parse TOML, contact Supabase, infer hosted dashboard state, or create
//! Findings. Explicit repository API configuration can prove repository-derived
//! schema relevance; missing configuration leaves exposure unknown.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde_json::Value;
use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::evidence::{
    EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, EvidenceLocation, EvidenceSubject,
    EvidenceValidationError, ProducerKind,
};

use crate::view::NormalizedRepoPath;

use super::state::ExposureState;

pub const SUPABASE_CONFIG_PATH: &str = "supabase/config.toml";
pub const DEFAULT_MAX_API_EXPOSED_SCHEMAS: usize = 128;
pub const DEFAULT_MAX_API_SCHEMA_NAME_BYTES: usize = 128;
const PRODUCER_ID: &str = "sentrdel.supabase.api-exposure";
const PRODUCER_VERSION: &str = "1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiExposureSource {
    ExplicitConfig,
    SupportedRepositoryDefault,
}

impl ApiExposureSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitConfig => "EXPLICIT_CONFIG",
            Self::SupportedRepositoryDefault => "SUPPORTED_REPOSITORY_DEFAULT",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedExposureState {
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigExposureProvenance {
    pub path: NormalizedRepoPath,
    pub content_digest: String,
    pub line: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiSchemaExposureInput {
    pub api_enabled: bool,
    pub schemas: BTreeSet<String>,
    pub source: ApiExposureSource,
    pub provenance: ConfigExposureProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiSchemaExposureSnapshot {
    repository_api_enabled: Option<bool>,
    repository_schemas: Option<BTreeSet<String>>,
    source: Option<ApiExposureSource>,
    provenance: Option<ConfigExposureProvenance>,
    pub hosted_exposure: HostedExposureState,
}

impl ApiSchemaExposureSnapshot {
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            repository_api_enabled: None,
            repository_schemas: None,
            source: None,
            provenance: None,
            hosted_exposure: HostedExposureState::Unknown,
        }
    }

    #[must_use]
    pub fn repository_schema_exposure(&self, schema: &str) -> ExposureState {
        match (self.repository_api_enabled, &self.repository_schemas) {
            (Some(false), _) => ExposureState::NotProvenApiRelevant,
            (Some(true), Some(schemas)) if schemas.contains(schema) => ExposureState::ApiRelevant,
            (Some(true), Some(_)) => ExposureState::NotProvenApiRelevant,
            _ => ExposureState::Unknown,
        }
    }

    #[must_use]
    pub fn source(&self) -> Option<ApiExposureSource> {
        self.source
    }

    #[must_use]
    pub fn provenance(&self) -> Option<&ConfigExposureProvenance> {
        self.provenance.as_ref()
    }
}

#[derive(Debug)]
pub enum ApiExposureError {
    EmptyCapturedAt,
    WrongConfigPath,
    EmptyContentDigest,
    TooManySchemas { count: usize, max: usize },
    InvalidSchemaName { schema: String },
    Evidence(EvidenceValidationError),
}

impl fmt::Display for ApiExposureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCapturedAt => formatter.write_str("captured_at must not be empty"),
            Self::WrongConfigPath => {
                formatter.write_str("API exposure provenance must be supabase/config.toml")
            }
            Self::EmptyContentDigest => {
                formatter.write_str("API exposure provenance requires a content digest")
            }
            Self::TooManySchemas { count, max } => write!(
                formatter,
                "API exposed schema count {count} exceeds bounded cap {max}"
            ),
            Self::InvalidSchemaName { schema } => {
                write!(formatter, "API exposed schema name is not bounded/canonical: {schema:?}")
            }
            Self::Evidence(error) => write!(formatter, "cannot seal API exposure evidence: {error}"),
        }
    }
}

impl Error for ApiExposureError {}

impl From<EvidenceValidationError> for ApiExposureError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

pub fn observe_api_schema_exposure(
    input: &ApiSchemaExposureInput,
    captured_at: &str,
) -> Result<(ApiSchemaExposureSnapshot, Vec<Evidence>), ApiExposureError> {
    if captured_at.trim().is_empty() {
        return Err(ApiExposureError::EmptyCapturedAt);
    }
    if input.provenance.path.as_str() != SUPABASE_CONFIG_PATH {
        return Err(ApiExposureError::WrongConfigPath);
    }
    if input.provenance.content_digest.trim().is_empty() {
        return Err(ApiExposureError::EmptyContentDigest);
    }
    if input.schemas.len() > DEFAULT_MAX_API_EXPOSED_SCHEMAS {
        return Err(ApiExposureError::TooManySchemas {
            count: input.schemas.len(),
            max: DEFAULT_MAX_API_EXPOSED_SCHEMAS,
        });
    }
    for schema in &input.schemas {
        validate_schema_name(schema)?;
    }

    let snapshot = ApiSchemaExposureSnapshot {
        repository_api_enabled: Some(input.api_enabled),
        repository_schemas: Some(input.schemas.clone()),
        source: Some(input.source),
        provenance: Some(input.provenance.clone()),
        hosted_exposure: HostedExposureState::Unknown,
    };

    let authority =
        EvidenceAuthority::from_runtime(PRODUCER_ID, PRODUCER_VERSION, ProducerKind::NativeRule)?;
    let mut evidence = Vec::new();

    let mut api_attributes = common_attributes(input);
    api_attributes.insert("api_enabled".to_owned(), Value::Bool(input.api_enabled));
    evidence.push(authority.seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: vec![input.provenance.content_digest.clone()],
        observation: if input.api_enabled {
            "Repository Supabase configuration enables the local Data API surface".to_owned()
        } else {
            "Repository Supabase configuration disables the local Data API surface".to_owned()
        },
        security_interpretation: None,
        category: "supabase_api_exposure".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: vec![EvidenceSubject {
            kind: "supabase_api".to_owned(),
            id: "repository-config".to_owned(),
        }],
        locations: vec![config_location(&input.provenance)],
        attributes: api_attributes,
        reproduction: None,
        captured_at: captured_at.to_owned(),
    })?);

    if input.api_enabled {
        for schema in &input.schemas {
            let mut attributes = common_attributes(input);
            attributes.insert("schema".to_owned(), Value::String(schema.clone()));
            attributes.insert("repository_api_relevant".to_owned(), Value::Bool(true));
            evidence.push(authority.seal(EvidenceClaim {
                schema_version: SCHEMA_V1.to_owned(),
                input_digests: vec![input.provenance.content_digest.clone()],
                observation: "Repository Supabase configuration includes a schema in the Data API exposure set"
                    .to_owned(),
                security_interpretation: None,
                category: "supabase_api_exposure".to_owned(),
                epistemic_class: EpistemicClass::Fact,
                confidence_band: None,
                subjects: vec![EvidenceSubject {
                    kind: "supabase_schema".to_owned(),
                    id: schema.clone(),
                }],
                locations: vec![config_location(&input.provenance)],
                attributes,
                reproduction: None,
                captured_at: captured_at.to_owned(),
            })?);
        }
    }

    Ok((snapshot, evidence))
}

fn common_attributes(input: &ApiSchemaExposureInput) -> BTreeMap<String, Value> {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "exposure_source".to_owned(),
        Value::String(input.source.as_str().to_owned()),
    );
    attributes.insert("repository_derived".to_owned(), Value::Bool(true));
    attributes.insert(
        "hosted_exposure".to_owned(),
        Value::String("UNKNOWN".to_owned()),
    );
    attributes
}

fn config_location(provenance: &ConfigExposureProvenance) -> EvidenceLocation {
    EvidenceLocation {
        repo_relative_path: provenance.path.as_str().to_owned(),
        start_line: provenance.line,
        start_column: None,
        end_line: provenance.line,
        end_column: None,
        symbol: None,
        content_digest: Some(provenance.content_digest.clone()),
    }
}

fn validate_schema_name(schema: &str) -> Result<(), ApiExposureError> {
    let valid = !schema.is_empty()
        && schema.len() <= DEFAULT_MAX_API_SCHEMA_NAME_BYTES
        && schema.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
        });
    if valid {
        Ok(())
    } else {
        Err(ApiExposureError::InvalidSchemaName {
            schema: schema.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> ConfigExposureProvenance {
        ConfigExposureProvenance {
            path: NormalizedRepoPath::parse(SUPABASE_CONFIG_PATH, 4096).unwrap(),
            content_digest: "sha256:test-config".to_owned(),
            line: Some(4),
        }
    }

    fn schemas(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn explicit_repository_schemas_prove_static_relevance_only() {
        let input = ApiSchemaExposureInput {
            api_enabled: true,
            schemas: schemas(&["public", "storage"]),
            source: ApiExposureSource::ExplicitConfig,
            provenance: provenance(),
        };
        let (snapshot, evidence) =
            observe_api_schema_exposure(&input, "2026-08-29T12:00:00Z").unwrap();

        assert_eq!(
            snapshot.repository_schema_exposure("public"),
            ExposureState::ApiRelevant
        );
        assert_eq!(
            snapshot.repository_schema_exposure("private"),
            ExposureState::NotProvenApiRelevant
        );
        assert_eq!(snapshot.hosted_exposure, HostedExposureState::Unknown);
        assert_eq!(evidence.len(), 3);
        assert!(evidence.iter().all(|item| {
            item.claim.security_interpretation.is_none()
                && item.claim.attributes.get("hosted_exposure")
                    == Some(&Value::String("UNKNOWN".to_owned()))
        }));
    }

    #[test]
    fn missing_repository_configuration_leaves_exposure_unknown() {
        let snapshot = ApiSchemaExposureSnapshot::unknown();
        assert_eq!(
            snapshot.repository_schema_exposure("public"),
            ExposureState::Unknown
        );
        assert_eq!(snapshot.hosted_exposure, HostedExposureState::Unknown);
        assert!(snapshot.provenance().is_none());
    }

    #[test]
    fn disabled_repository_api_does_not_claim_hosted_state() {
        let input = ApiSchemaExposureInput {
            api_enabled: false,
            schemas: schemas(&["public", "storage"]),
            source: ApiExposureSource::ExplicitConfig,
            provenance: provenance(),
        };
        let (snapshot, evidence) =
            observe_api_schema_exposure(&input, "2026-08-29T12:00:00Z").unwrap();

        assert_eq!(
            snapshot.repository_schema_exposure("public"),
            ExposureState::NotProvenApiRelevant
        );
        assert_eq!(snapshot.hosted_exposure, HostedExposureState::Unknown);
        assert_eq!(evidence.len(), 1);
    }

    #[test]
    fn supported_repository_default_is_labeled_not_promoted_to_hosted_truth() {
        let input = ApiSchemaExposureInput {
            api_enabled: true,
            schemas: schemas(&["public"]),
            source: ApiExposureSource::SupportedRepositoryDefault,
            provenance: provenance(),
        };
        let (snapshot, evidence) =
            observe_api_schema_exposure(&input, "2026-08-29T12:00:00Z").unwrap();

        assert_eq!(
            snapshot.repository_schema_exposure("public"),
            ExposureState::ApiRelevant
        );
        assert_eq!(snapshot.hosted_exposure, HostedExposureState::Unknown);
        assert!(evidence.iter().all(|item| {
            item.claim.attributes.get("exposure_source")
                == Some(&Value::String("SUPPORTED_REPOSITORY_DEFAULT".to_owned()))
        }));
    }

    #[test]
    fn unbounded_or_noncanonical_schema_names_fail_closed() {
        for schema in ["", "Public", "public-private", "public.schema"] {
            let input = ApiSchemaExposureInput {
                api_enabled: true,
                schemas: schemas(&[schema]),
                source: ApiExposureSource::ExplicitConfig,
                provenance: provenance(),
            };
            assert!(matches!(
                observe_api_schema_exposure(&input, "2026-08-29T12:00:00Z"),
                Err(ApiExposureError::InvalidSchemaName { .. })
            ));
        }
    }

    #[test]
    fn provenance_is_bounded_to_canonical_supabase_config() {
        let input = ApiSchemaExposureInput {
            api_enabled: true,
            schemas: schemas(&["public"]),
            source: ApiExposureSource::ExplicitConfig,
            provenance: ConfigExposureProvenance {
                path: NormalizedRepoPath::parse("config.toml", 4096).unwrap(),
                content_digest: "sha256:test".to_owned(),
                line: Some(1),
            },
        };
        assert!(matches!(
            observe_api_schema_exposure(&input, "2026-08-29T12:00:00Z"),
            Err(ApiExposureError::WrongConfigPath)
        ));
    }
}
