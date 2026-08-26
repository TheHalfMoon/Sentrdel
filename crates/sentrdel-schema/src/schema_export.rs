//! JSON Schema generation for public wire contracts.
//!
//! Authoritative sealed in-memory types are intentionally not the public
//! deserialization contract. Public JSON Schemas describe untrusted wire or
//! persistence records that must be rebound to runtime authority before use.

use crate::{
    SCHEMA_V1,
    asel::AgentSecurityEventRecord,
    coverage::CoverageRecord,
    engine::{EngineManifest, EngineRun},
    evidence::EvidenceRecord,
    finding::FindingRecord,
    graph::{GraphEdge, GraphNode},
    pack::SecurityPackManifest,
    policy::PolicyDecisionRecord,
    project::ProjectProfile,
    reasoner::ReasonerEvidenceDraft,
};
use schemars::{JsonSchema, SchemaGenerator};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const CANONICAL_ID_PATTERN: &str = r"^sha256:[0-9a-f]{64}$";
const NONBLANK_PATTERN: &str = r"\S";

fn schema_value<T: JsonSchema>() -> Result<Value, serde_json::Error> {
    let schema = SchemaGenerator::default().into_root_schema_for::<T>();
    serde_json::to_value(schema)
}

fn set_integer_bounds(schema: &mut Value, pointer: &str, minimum: Value, maximum: Value) {
    let field = schema
        .pointer_mut(pointer)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("missing fixed-width integer schema field at {pointer}"));
    field.insert("minimum".to_owned(), minimum);
    field.insert("maximum".to_owned(), maximum);
}

fn set_u64_bounds(schema: &mut Value, pointer: &str) {
    set_integer_bounds(schema, pointer, json!(u64::MIN), json!(u64::MAX));
}

fn set_i64_bounds(schema: &mut Value, pointer: &str) {
    set_integer_bounds(schema, pointer, json!(i64::MIN), json!(i64::MAX));
}

fn set_i32_bounds(schema: &mut Value, pointer: &str) {
    set_integer_bounds(schema, pointer, json!(i32::MIN), json!(i32::MAX));
}

fn set_string_pattern(schema: &mut Value, pointer: &str, pattern: &str) {
    let field = schema
        .pointer_mut(pointer)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("missing graph string schema field at {pointer}"));
    field.insert("pattern".to_owned(), json!(pattern));
}

fn set_schema_version_const(schema: &mut Value) {
    let field = schema
        .pointer_mut("/properties/schema_version")
        .and_then(Value::as_object_mut)
        .expect("graph schema_version field");
    field.insert("const".to_owned(), json!(SCHEMA_V1));
}

fn harden_graph_provenance(schema: &mut Value) {
    set_string_pattern(schema, "/$defs/GraphProvenanceId", NONBLANK_PATTERN);
    let provenance = schema
        .pointer_mut("/properties/provenance_ids")
        .and_then(Value::as_object_mut)
        .expect("graph provenance array");
    provenance.insert("minItems".to_owned(), json!(1));
    provenance.insert("uniqueItems".to_owned(), json!(true));
}

fn harden_graph_attributes(schema: &mut Value) {
    let canonical_value = json!({
        "oneOf": [
            {"type": "null"},
            {"type": "boolean"},
            {"type": "string"},
            {
                "type": "integer",
                "minimum": i64::MIN,
                "maximum": u64::MAX
            },
            {
                "type": "array",
                "items": {"$ref": "#/$defs/CanonicalGraphValue"}
            },
            {
                "type": "object",
                "additionalProperties": {"$ref": "#/$defs/CanonicalGraphValue"}
            }
        ]
    });

    schema
        .pointer_mut("/$defs")
        .and_then(Value::as_object_mut)
        .expect("graph schema defs")
        .insert("CanonicalGraphValue".to_owned(), canonical_value);

    schema
        .pointer_mut("/properties/attributes")
        .and_then(Value::as_object_mut)
        .expect("graph attributes field")
        .insert(
            "additionalProperties".to_owned(),
            json!({"$ref": "#/$defs/CanonicalGraphValue"}),
        );
}

fn harden_graph_node_schema(schema: &mut Value) {
    set_schema_version_const(schema);
    set_string_pattern(schema, "/$defs/GraphNodeId", CANONICAL_ID_PATTERN);
    set_string_pattern(schema, "/properties/semantic_key", NONBLANK_PATTERN);
    harden_graph_provenance(schema);
    harden_graph_attributes(schema);
}

fn harden_graph_edge_schema(schema: &mut Value) {
    set_schema_version_const(schema);
    set_string_pattern(schema, "/$defs/GraphEdgeId", CANONICAL_ID_PATTERN);
    set_string_pattern(schema, "/$defs/GraphNodeId", CANONICAL_ID_PATTERN);
    set_string_pattern(
        schema,
        "/$defs/GraphConfidenceSource/properties/producer",
        NONBLANK_PATTERN,
    );
    set_string_pattern(
        schema,
        "/$defs/GraphConfidenceSource/properties/producer_version",
        NONBLANK_PATTERN,
    );
    harden_graph_provenance(schema);
    harden_graph_attributes(schema);
}

/// Add R1 authority constraints that are semantic in Rust but must also be
/// visible to non-Rust consumers validating the public wire schema.
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

    let observation_constraint = json!({
        "if": {
            "properties": {
                "claim": {
                    "properties": {
                        "epistemic_class": {"const": "OBSERVATION"}
                    },
                    "required": ["epistemic_class"]
                }
            },
            "required": ["claim"]
        },
        "then": {
            "properties": {
                "producer": {
                    "properties": {
                        "kind": {"const": "RUNTIME_TEST"}
                    },
                    "required": ["kind"]
                }
            },
            "required": ["producer"]
        }
    });

    let runtime_constraint = json!({
        "if": {
            "properties": {
                "producer": {
                    "properties": {
                        "kind": {"const": "RUNTIME_TEST"}
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
                            "enum": ["OBSERVATION", "CONTRADICTION"]
                        }
                    },
                    "required": ["epistemic_class"]
                }
            },
            "required": ["claim"]
        }
    });

    if let Some(root) = schema.as_object_mut() {
        root.insert(
            "allOf".to_owned(),
            Value::Array(vec![
                llm_constraint,
                observation_constraint,
                runtime_constraint,
            ]),
        );
    }

    for field in ["start_line", "start_column", "end_line", "end_column"] {
        set_u64_bounds(
            schema,
            &format!("/$defs/EvidenceLocation/properties/{field}"),
        );
    }
}

fn harden_finding_schema(schema: &mut Value) {
    if let Some(states) = schema
        .pointer_mut("/$defs/WorkflowState/enum")
        .and_then(Value::as_array_mut)
    {
        states.retain(|value| value.as_str() != Some("FIX_VERIFIED"));
    }

    let accepted_risk_constraint = json!({
        "if": {
            "properties": {
                "workflow_state": {"const": "ACCEPTED"}
            },
            "required": ["workflow_state"]
        },
        "then": {
            "properties": {
                "accepted_risk": {"$ref": "#/$defs/AcceptedRiskRecord"}
            },
            "required": ["accepted_risk"]
        },
        "else": {
            "properties": {
                "accepted_risk": {"type": "null"}
            }
        }
    });

    let workflow_authorization_constraint = json!({
        "if": {
            "properties": {
                "workflow_state": {"const": "NEW"}
            },
            "required": ["workflow_state"]
        },
        "then": {
            "properties": {
                "workflow_authority_id": {"type": "null"},
                "workflow_authorization_ref": {"type": "null"}
            }
        },
        "else": {
            "properties": {
                "workflow_authority_id": {"type": "string"},
                "workflow_authorization_ref": {"type": "string"}
            },
            "required": ["workflow_authority_id", "workflow_authorization_ref"]
        }
    });

    if let Some(root) = schema.as_object_mut() {
        root.insert(
            "allOf".to_owned(),
            Value::Array(vec![
                accepted_risk_constraint,
                workflow_authorization_constraint,
            ]),
        );
    }

    set_i64_bounds(
        schema,
        "/$defs/AcceptedRiskRecord/properties/created_at_unix_seconds",
    );
    set_i64_bounds(
        schema,
        "/$defs/AcceptedRiskRecord/properties/expires_at_unix_seconds",
    );
}

fn harden_engine_manifest_schema(schema: &mut Value) {
    for field in ["timeout_ms", "max_stdout_bytes", "max_stderr_bytes"] {
        set_u64_bounds(schema, &format!("/properties/{field}"));
    }
}

fn harden_engine_run_schema(schema: &mut Value) {
    set_i32_bounds(schema, "/properties/exit_status");
}

fn harden_asel_schema(schema: &mut Value) {
    set_u64_bounds(schema, "/properties/sequence");
}

fn harden_reasoner_schema(schema: &mut Value) {
    for field in ["start_line", "start_column", "end_line", "end_column"] {
        set_u64_bounds(
            schema,
            &format!("/$defs/EvidenceLocation/properties/{field}"),
        );
    }
}

/// Generate every R1 public wire schema with stable filenames.
pub fn export_all() -> Result<BTreeMap<&'static str, Value>, serde_json::Error> {
    let mut schemas = BTreeMap::new();

    let mut evidence = schema_value::<EvidenceRecord>()?;
    harden_evidence_schema(&mut evidence);
    schemas.insert("evidence.schema.json", evidence);

    let mut finding = schema_value::<FindingRecord>()?;
    harden_finding_schema(&mut finding);
    schemas.insert("finding.schema.json", finding);

    schemas.insert("coverage.schema.json", schema_value::<CoverageRecord>()?);

    let mut graph_node = schema_value::<GraphNode>()?;
    harden_graph_node_schema(&mut graph_node);
    schemas.insert("graph-node.schema.json", graph_node);

    let mut graph_edge = schema_value::<GraphEdge>()?;
    harden_graph_edge_schema(&mut graph_edge);
    schemas.insert("graph-edge.schema.json", graph_edge);

    let mut asel = schema_value::<AgentSecurityEventRecord>()?;
    harden_asel_schema(&mut asel);
    schemas.insert("asel-event.schema.json", asel);

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

    let mut engine_manifest = schema_value::<EngineManifest>()?;
    harden_engine_manifest_schema(&mut engine_manifest);
    schemas.insert("engine-manifest.schema.json", engine_manifest);

    let mut engine_run = schema_value::<EngineRun>()?;
    harden_engine_run_schema(&mut engine_run);
    schemas.insert("engine-run.schema.json", engine_run);

    let mut reasoner = schema_value::<ReasonerEvidenceDraft>()?;
    harden_reasoner_schema(&mut reasoner);
    schemas.insert("reasoner-evidence.schema.json", reasoner);

    Ok(schemas)
}

#[cfg(test)]
mod tests {
    use super::{CANONICAL_ID_PATTERN, NONBLANK_PATTERN, export_all};

    #[test]
    fn all_public_schemas_generate_as_objects() {
        let schemas = export_all().expect("schema generation");
        assert_eq!(schemas.len(), 12);
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
    fn graph_schemas_expose_runtime_rejection_constraints() {
        let schemas = export_all().expect("schema generation");
        let node = schemas
            .get("graph-node.schema.json")
            .expect("graph node schema");
        let edge = schemas
            .get("graph-edge.schema.json")
            .expect("graph edge schema");

        for schema in [node, edge] {
            assert_eq!(
                schema
                    .pointer("/properties/schema_version/const")
                    .and_then(|value| value.as_str()),
                Some("1")
            );
            assert_eq!(
                schema
                    .pointer("/$defs/GraphProvenanceId/pattern")
                    .and_then(|value| value.as_str()),
                Some(NONBLANK_PATTERN)
            );
            assert_eq!(
                schema
                    .pointer("/properties/provenance_ids/minItems")
                    .and_then(|value| value.as_u64()),
                Some(1)
            );
            assert_eq!(
                schema
                    .pointer("/properties/provenance_ids/uniqueItems")
                    .and_then(|value| value.as_bool()),
                Some(true)
            );
            assert_eq!(
                schema
                    .pointer("/properties/attributes/additionalProperties/$ref")
                    .and_then(|value| value.as_str()),
                Some("#/$defs/CanonicalGraphValue")
            );

            let canonical_value = schema
                .pointer("/$defs/CanonicalGraphValue/oneOf")
                .and_then(|value| value.as_array())
                .expect("canonical graph value union");
            assert!(canonical_value.iter().any(|branch| {
                branch.get("type").and_then(|value| value.as_str()) == Some("integer")
                    && branch.get("minimum") == Some(&serde_json::json!(i64::MIN))
                    && branch.get("maximum") == Some(&serde_json::json!(u64::MAX))
            }));
            assert!(!canonical_value.iter().any(|branch| {
                branch.get("type").and_then(|value| value.as_str()) == Some("number")
            }));
        }

        assert_eq!(
            node.pointer("/$defs/GraphNodeId/pattern")
                .and_then(|value| value.as_str()),
            Some(CANONICAL_ID_PATTERN)
        );
        assert_eq!(
            node.pointer("/properties/semantic_key/pattern")
                .and_then(|value| value.as_str()),
            Some(NONBLANK_PATTERN)
        );
        assert_eq!(
            edge.pointer("/$defs/GraphEdgeId/pattern")
                .and_then(|value| value.as_str()),
            Some(CANONICAL_ID_PATTERN)
        );
        assert_eq!(
            edge.pointer("/$defs/GraphNodeId/pattern")
                .and_then(|value| value.as_str()),
            Some(CANONICAL_ID_PATTERN)
        );
        assert_eq!(
            edge.pointer("/$defs/GraphConfidenceSource/properties/producer/pattern")
                .and_then(|value| value.as_str()),
            Some(NONBLANK_PATTERN)
        );
        assert_eq!(
            edge.pointer("/$defs/GraphConfidenceSource/properties/producer_version/pattern")
                .and_then(|value| value.as_str()),
            Some(NONBLANK_PATTERN)
        );
    }

    #[test]
    fn graph_schema_keeps_confidence_separate_from_epistemic_authority() {
        let schemas = export_all().expect("schema generation");
        let edge = schemas
            .get("graph-edge.schema.json")
            .expect("graph edge schema");
        let bases = edge
            .pointer("/$defs/GraphConfidenceBasis/enum")
            .and_then(|value| value.as_array())
            .expect("graph confidence enum");
        assert_eq!(bases.len(), 3);
        for expected in ["EXTRACTED", "INFERRED", "AMBIGUOUS"] {
            assert!(bases.iter().any(|value| value.as_str() == Some(expected)));
        }
        assert!(!bases.iter().any(|value| value.as_str() == Some("VERIFIED")));
        assert!(edge.pointer("/$defs/EpistemicClass").is_none());
    }

    #[test]
    fn evidence_schema_enforces_r1_authority_limits() {
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

        let encoded = serde_json::to_string(evidence.get("allOf").expect("authority conditionals"))
            .expect("encode constraints");
        assert!(encoded.contains("LLM_REASONER"));
        assert!(encoded.contains("INFERENCE"));
        assert!(encoded.contains("HYPOTHESIS"));
        assert!(encoded.contains("OBSERVATION"));
        assert!(encoded.contains("RUNTIME_TEST"));
        assert!(encoded.contains("CONTRADICTION"));
        assert!(!encoded.contains("VERIFIED"));
    }

    #[test]
    fn finding_schema_enforces_r1_workflow_shape() {
        let schemas = export_all().expect("schema generation");
        let finding = schemas.get("finding.schema.json").expect("finding schema");
        let states = finding
            .pointer("/$defs/WorkflowState/enum")
            .and_then(|value| value.as_array())
            .expect("workflow enum");
        assert!(
            !states
                .iter()
                .any(|value| value.as_str() == Some("FIX_VERIFIED"))
        );

        assert_eq!(
            finding
                .pointer("/allOf/0/then/properties/accepted_risk/$ref")
                .and_then(|value| value.as_str()),
            Some("#/$defs/AcceptedRiskRecord")
        );
        assert_eq!(
            finding
                .pointer("/allOf/0/else/properties/accepted_risk/type")
                .and_then(|value| value.as_str()),
            Some("null")
        );
        assert_eq!(
            finding
                .pointer("/allOf/1/then/properties/workflow_authority_id/type")
                .and_then(|value| value.as_str()),
            Some("null")
        );
        assert_eq!(
            finding
                .pointer("/allOf/1/else/properties/workflow_authority_id/type")
                .and_then(|value| value.as_str()),
            Some("string")
        );
        assert_eq!(
            finding
                .pointer("/allOf/1/else/properties/workflow_authorization_ref/type")
                .and_then(|value| value.as_str()),
            Some("string")
        );
    }

    #[test]
    fn fixed_width_integer_schemas_have_rust_bounds() {
        let schemas = export_all().expect("schema generation");
        let checks = [
            (
                "engine-manifest.schema.json",
                "/properties/timeout_ms",
                serde_json::json!(u64::MIN),
                serde_json::json!(u64::MAX),
            ),
            (
                "engine-run.schema.json",
                "/properties/exit_status",
                serde_json::json!(i32::MIN),
                serde_json::json!(i32::MAX),
            ),
            (
                "evidence.schema.json",
                "/$defs/EvidenceLocation/properties/start_line",
                serde_json::json!(u64::MIN),
                serde_json::json!(u64::MAX),
            ),
            (
                "finding.schema.json",
                "/$defs/AcceptedRiskRecord/properties/created_at_unix_seconds",
                serde_json::json!(i64::MIN),
                serde_json::json!(i64::MAX),
            ),
            (
                "reasoner-evidence.schema.json",
                "/$defs/EvidenceLocation/properties/start_line",
                serde_json::json!(u64::MIN),
                serde_json::json!(u64::MAX),
            ),
            (
                "asel-event.schema.json",
                "/properties/sequence",
                serde_json::json!(u64::MIN),
                serde_json::json!(u64::MAX),
            ),
        ];

        for (name, pointer, minimum, maximum) in checks {
            let field = schemas
                .get(name)
                .and_then(|schema| schema.pointer(pointer))
                .expect("bounded field");
            assert_eq!(field.get("minimum"), Some(&minimum));
            assert_eq!(field.get("maximum"), Some(&maximum));
        }
    }
}
