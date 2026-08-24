//! JSON Schema generation for public wire contracts.
//!
//! Authoritative sealed in-memory types are intentionally not the public
//! deserialization contract. Public JSON Schemas describe untrusted wire or
//! persistence records that must be rebound to runtime authority before use.

use crate::{
    asel::AgentSecurityEventRecord,
    coverage::CoverageRecord,
    engine::{EngineManifest, EngineRun},
    evidence::EvidenceRecord,
    finding::FindingRecord,
    pack::SecurityPackManifest,
    policy::PolicyDecisionRecord,
    project::ProjectProfile,
    reasoner::ReasonerEvidenceDraft,
};
use schemars::{JsonSchema, SchemaGenerator};
use serde_json::Value;
use std::collections::BTreeMap;

fn schema_value<T: JsonSchema>() -> Result<Value, serde_json::Error> {
    let schema = SchemaGenerator::default().into_root_schema_for::<T>();
    serde_json::to_value(schema)
}

/// Generate every R1 public wire schema with stable filenames.
pub fn export_all() -> Result<BTreeMap<&'static str, Value>, serde_json::Error> {
    let mut schemas = BTreeMap::new();
    schemas.insert("evidence.schema.json", schema_value::<EvidenceRecord>()?);
    schemas.insert("finding.schema.json", schema_value::<FindingRecord>()?);
    schemas.insert("coverage.schema.json", schema_value::<CoverageRecord>()?);
    schemas.insert(
        "asel-event.schema.json",
        schema_value::<AgentSecurityEventRecord>()?,
    );
    schemas.insert(
        "policy-decision.schema.json",
        schema_value::<PolicyDecisionRecord>()?,
    );
    schemas.insert(
        "project-profile.schema.json",
        schema_value::<ProjectProfile>()?,
    );
    schemas.insert(
        "security-pack-manifest.schema.json",
        schema_value::<SecurityPackManifest>()?,
    );
    schemas.insert(
        "engine-manifest.schema.json",
        schema_value::<EngineManifest>()?,
    );
    schemas.insert("engine-run.schema.json", schema_value::<EngineRun>()?);
    schemas.insert(
        "reasoner-evidence.schema.json",
        schema_value::<ReasonerEvidenceDraft>()?,
    );
    Ok(schemas)
}

#[cfg(test)]
mod tests {
    use super::export_all;

    #[test]
    fn all_public_schemas_generate_as_objects() {
        let schemas = export_all().expect("schema generation");
        assert_eq!(schemas.len(), 10);
        for (name, schema) in schemas {
            assert!(name.ends_with(".schema.json"));
            assert!(schema.is_object());
            assert_eq!(
                schema.get("$schema").and_then(|value| value.as_str()),
                Some("https://json-schema.org/draft/2020-12/schema")
            );
        }
    }
}
