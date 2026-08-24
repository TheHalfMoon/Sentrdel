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
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn schema_value<T: JsonSchema>() -> Result<Value, serde_json::Error> {
    let schema = SchemaGenerator::default().into_root_schema_for::<T>();
    serde_json::to_value(schema)
}

/// Add R1 authority constraints that are semantic in Rust but are also useful
/// to non-Rust consumers validating the public wire schema.
fn harden_evidence_schema(schema: &mut Value) {
    if let Some(classes) = schema
        .pointer_mut("/$defs/EpistemicClass/enum")
        .and_then(Value::as_array_mut)
    {
        classes.retain(|value| value.as_str() != Some("VERIFIED"));
    }

    let llm_constraint = json!({
        "if": {
            "properties": {
                "producer": {
                    "properties": {
                        "kind": {"const": "LLM_REASONER"}
                    },
                    "required": ["kind"]
                }
            },
            "required": ["producer"]
        },
        "then": {
            "properties": {
                "claim": {
                    "properties": {
                        "epistemic_class": {
                            "enum": ["INFERENCE", "HYPOTHESIS"]
                        }
                    },
                    "required": ["epistemic_class"]
                }
            },
            "required": ["claim"]
        }
    });

    if let Some(root) = schema.as_object_mut() {
        root.insert("allOf".to_owned(), Value::Array(vec![llm_constraint]));
    }
}

/// Generate every R1 public wire schema with stable filenames.
pub fn export_all() -> Result<BTreeMap<&'static str, Value>, serde_json::Error> {
    let mut schemas = BTreeMap::new();
    let mut evidence = schema_value::<EvidenceRecord>()?;
    harden_evidence_schema(&mut evidence);
    schemas.insert("evidence.schema.json", evidence);
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

    #[test]
    fn evidence_schema_excludes_verified_and_limits_llm_classes() {
        let schemas = export_all().expect("schema generation");
        let evidence = schemas
            .get("evidence.schema.json")
            .expect("evidence schema");
        let classes = evidence
            .pointer("/$defs/EpistemicClass/enum")
            .and_then(|value| value.as_array())
            .expect("epistemic enum");
        assert!(
            !classes
                .iter()
                .any(|value| value.as_str() == Some("VERIFIED"))
        );

        let conditional = evidence
            .get("allOf")
            .and_then(|value| value.as_array())
            .and_then(|values| values.first())
            .expect("LLM conditional");
        let encoded = serde_json::to_string(conditional).expect("encode constraint");
        assert!(encoded.contains("LLM_REASONER"));
        assert!(encoded.contains("INFERENCE"));
        assert!(encoded.contains("HYPOTHESIS"));
        assert!(!encoded.contains("VERIFIED"));
    }
}
