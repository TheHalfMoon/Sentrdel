//! Security Pack registry and manifest validation.
//!
//! Packs are untrusted declarative inputs. Registration validates identity,
//! provenance, capability names, and coverage dimensions before a pack can be
//! selected. This layer grants no Finding, policy, verification, process,
//! filesystem, credential, or network authority.

use sentrdel_schema::{SCHEMA_V1, pack::SecurityPackManifest};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

const SUPPORTED_COVERAGE_DIMENSIONS: &[&str] = &[
    "DETECTION",
    "STATIC_POSTURE",
    "LIVE_POSTURE",
    "BUSINESS_LOGIC",
    "RUNTIME",
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PackCoverageDimension {
    Detection,
    StaticPosture,
    LivePosture,
    BusinessLogic,
    Runtime,
}

impl PackCoverageDimension {
    pub fn parse(value: &str) -> Result<Self, PackRegistryError> {
        match value {
            "DETECTION" => Ok(Self::Detection),
            "STATIC_POSTURE" => Ok(Self::StaticPosture),
            "LIVE_POSTURE" => Ok(Self::LivePosture),
            "BUSINESS_LOGIC" => Ok(Self::BusinessLogic),
            "RUNTIME" => Ok(Self::Runtime),
            other => Err(PackRegistryError::UnsupportedCoverageDimension(
                other.to_owned(),
            )),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Detection => "DETECTION",
            Self::StaticPosture => "STATIC_POSTURE",
            Self::LivePosture => "LIVE_POSTURE",
            Self::BusinessLogic => "BUSINESS_LOGIC",
            Self::Runtime => "RUNTIME",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackOutputKind {
    Evidence,
    Coverage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPackManifest {
    manifest: SecurityPackManifest,
    coverage_dimensions: BTreeSet<PackCoverageDimension>,
}

impl ValidatedPackManifest {
    #[must_use]
    pub fn manifest(&self) -> &SecurityPackManifest {
        &self.manifest
    }

    #[must_use]
    pub fn pack_id(&self) -> &str {
        &self.manifest.pack_id
    }

    #[must_use]
    pub fn coverage_dimensions(&self) -> &BTreeSet<PackCoverageDimension> {
        &self.coverage_dimensions
    }

    /// Security Packs may contribute only canonical Evidence and Coverage.
    /// This is intentionally a closed enum rather than a string capability.
    #[must_use]
    pub const fn output_kinds() -> [PackOutputKind; 2] {
        [PackOutputKind::Evidence, PackOutputKind::Coverage]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackRegistryError {
    UnsupportedSchemaVersion(String),
    EmptyField(&'static str),
    EmptyList(&'static str),
    EmptyListValue(&'static str),
    DuplicateListValue { field: &'static str, value: String },
    UnsupportedCoverageDimension(String),
    DuplicatePackId(String),
}

impl fmt::Display for PackRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "unsupported Security Pack schema version: {version}"
                )
            }
            Self::EmptyField(field) => {
                write!(formatter, "Security Pack field {field} must not be empty")
            }
            Self::EmptyList(field) => {
                write!(formatter, "Security Pack list {field} must not be empty")
            }
            Self::EmptyListValue(field) => {
                write!(
                    formatter,
                    "Security Pack list {field} contains an empty value"
                )
            }
            Self::DuplicateListValue { field, value } => {
                write!(
                    formatter,
                    "Security Pack list {field} contains duplicate value {value:?}"
                )
            }
            Self::UnsupportedCoverageDimension(value) => write!(
                formatter,
                "unsupported Security Pack coverage dimension {value:?}; supported dimensions are {}",
                SUPPORTED_COVERAGE_DIMENSIONS.join(",")
            ),
            Self::DuplicatePackId(pack_id) => {
                write!(
                    formatter,
                    "Security Pack id is already registered: {pack_id}"
                )
            }
        }
    }
}

impl Error for PackRegistryError {}

pub fn validate_pack_manifest(
    manifest: SecurityPackManifest,
) -> Result<ValidatedPackManifest, PackRegistryError> {
    if manifest.schema_version != SCHEMA_V1 {
        return Err(PackRegistryError::UnsupportedSchemaVersion(
            manifest.schema_version.clone(),
        ));
    }

    validate_nonempty("pack_id", &manifest.pack_id)?;
    validate_nonempty("version", &manifest.version)?;
    validate_nonempty("provider_or_framework", &manifest.provider_or_framework)?;
    validate_nonempty(
        "source_provenance.source_id",
        &manifest.source_provenance.source_id,
    )?;
    validate_nonempty(
        "source_provenance.exact_ref",
        &manifest.source_provenance.exact_ref,
    )?;
    validate_nonempty(
        "source_provenance.license_expression",
        &manifest.source_provenance.license_expression,
    )?;
    if let Some(digest) = manifest.source_provenance.integrity_digest.as_deref() {
        validate_nonempty("source_provenance.integrity_digest", digest)?;
    }

    validate_unique_list(
        "detection_capabilities",
        &manifest.detection_capabilities,
        false,
    )?;
    validate_unique_list(
        "evidence_capabilities",
        &manifest.evidence_capabilities,
        false,
    )?;
    validate_unique_list("required_engines", &manifest.required_engines, true)?;
    validate_unique_list("required_features", &manifest.required_features, true)?;
    validate_unique_list("coverage_dimensions", &manifest.coverage_dimensions, false)?;

    let mut coverage_dimensions = BTreeSet::new();
    for dimension in &manifest.coverage_dimensions {
        let parsed = PackCoverageDimension::parse(dimension)?;
        coverage_dimensions.insert(parsed);
    }

    Ok(ValidatedPackManifest {
        manifest,
        coverage_dimensions,
    })
}

#[derive(Default)]
pub struct SecurityPackRegistry {
    packs: BTreeMap<String, ValidatedPackManifest>,
}

impl SecurityPackRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        manifest: SecurityPackManifest,
    ) -> Result<&ValidatedPackManifest, PackRegistryError> {
        let validated = validate_pack_manifest(manifest)?;
        let pack_id = validated.pack_id().to_owned();
        if self.packs.contains_key(&pack_id) {
            return Err(PackRegistryError::DuplicatePackId(pack_id));
        }
        self.packs.insert(pack_id.clone(), validated);
        Ok(self.packs.get(&pack_id).expect("just inserted pack"))
    }

    #[must_use]
    pub fn get(&self, pack_id: &str) -> Option<&ValidatedPackManifest> {
        self.packs.get(pack_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &ValidatedPackManifest)> {
        self.packs.iter().map(|(id, pack)| (id.as_str(), pack))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.packs.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packs.is_empty()
    }
}

fn validate_nonempty(field: &'static str, value: &str) -> Result<(), PackRegistryError> {
    if value.trim().is_empty() {
        return Err(PackRegistryError::EmptyField(field));
    }
    Ok(())
}

fn validate_unique_list(
    field: &'static str,
    values: &[String],
    may_be_empty: bool,
) -> Result<(), PackRegistryError> {
    if values.is_empty() && !may_be_empty {
        return Err(PackRegistryError::EmptyList(field));
    }

    let mut seen = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err(PackRegistryError::EmptyListValue(field));
        }
        if !seen.insert(value.as_str()) {
            return Err(PackRegistryError::DuplicateListValue {
                field,
                value: value.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::pack::SourceProvenance;

    fn manifest(pack_id: &str) -> SecurityPackManifest {
        SecurityPackManifest {
            schema_version: SCHEMA_V1.to_owned(),
            pack_id: pack_id.to_owned(),
            version: "0.1.0".to_owned(),
            provider_or_framework: "fixture".to_owned(),
            source_provenance: SourceProvenance {
                source_id: "sentrdel-owned".to_owned(),
                exact_ref: "fixture-v1".to_owned(),
                license_expression: "Apache-2.0".to_owned(),
                integrity_digest: None,
            },
            detection_capabilities: vec!["fixture.detect".to_owned()],
            evidence_capabilities: vec!["fixture.posture".to_owned()],
            required_engines: Vec::new(),
            required_features: Vec::new(),
            coverage_dimensions: vec![
                "DETECTION".to_owned(),
                "STATIC_POSTURE".to_owned(),
                "LIVE_POSTURE".to_owned(),
                "BUSINESS_LOGIC".to_owned(),
                "RUNTIME".to_owned(),
            ],
        }
    }

    #[test]
    fn validates_all_frozen_coverage_dimensions() {
        let validated = validate_pack_manifest(manifest("fixture")).unwrap();
        assert_eq!(validated.coverage_dimensions().len(), 5);
        for expected in [
            PackCoverageDimension::Detection,
            PackCoverageDimension::StaticPosture,
            PackCoverageDimension::LivePosture,
            PackCoverageDimension::BusinessLogic,
            PackCoverageDimension::Runtime,
        ] {
            assert!(validated.coverage_dimensions().contains(&expected));
        }
        assert_eq!(
            ValidatedPackManifest::output_kinds(),
            [PackOutputKind::Evidence, PackOutputKind::Coverage]
        );
    }

    #[test]
    fn rejects_unknown_or_duplicate_dimensions() {
        let mut unknown = manifest("unknown");
        unknown.coverage_dimensions = vec!["DETECTION".to_owned(), "MAGIC".to_owned()];
        assert!(matches!(
            validate_pack_manifest(unknown),
            Err(PackRegistryError::UnsupportedCoverageDimension(value)) if value == "MAGIC"
        ));

        let mut duplicate = manifest("duplicate");
        duplicate.coverage_dimensions = vec!["DETECTION".to_owned(), "DETECTION".to_owned()];
        assert!(matches!(
            validate_pack_manifest(duplicate),
            Err(PackRegistryError::DuplicateListValue {
                field: "coverage_dimensions",
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_identity_provenance_and_capability_lists() {
        let mut empty_id = manifest("fixture");
        empty_id.pack_id = "  ".to_owned();
        assert!(matches!(
            validate_pack_manifest(empty_id),
            Err(PackRegistryError::EmptyField("pack_id"))
        ));

        let mut no_evidence = manifest("fixture");
        no_evidence.evidence_capabilities.clear();
        assert!(matches!(
            validate_pack_manifest(no_evidence),
            Err(PackRegistryError::EmptyList("evidence_capabilities"))
        ));

        let mut bad_provenance = manifest("fixture");
        bad_provenance.source_provenance.exact_ref.clear();
        assert!(matches!(
            validate_pack_manifest(bad_provenance),
            Err(PackRegistryError::EmptyField("source_provenance.exact_ref"))
        ));
    }

    #[test]
    fn registry_rejects_duplicate_ids_and_iterates_deterministically() {
        let mut registry = SecurityPackRegistry::new();
        registry.register(manifest("zeta")).unwrap();
        registry.register(manifest("alpha")).unwrap();
        assert_eq!(registry.len(), 2);
        let ids: Vec<_> = registry.iter().map(|(id, _)| id).collect();
        assert_eq!(ids, vec!["alpha", "zeta"]);
        assert!(matches!(
            registry.register(manifest("alpha")),
            Err(PackRegistryError::DuplicatePackId(pack_id)) if pack_id == "alpha"
        ));
    }

    #[test]
    fn manifest_wire_contract_rejects_authority_escalation_fields() {
        let mut value = serde_json::to_value(manifest("fixture")).unwrap();
        value.as_object_mut().unwrap().insert(
            "finding_capabilities".to_owned(),
            serde_json::json!(["create_finding"]),
        );
        assert!(serde_json::from_value::<SecurityPackManifest>(value).is_err());
    }
}
