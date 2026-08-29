use sentrdel_review::pack_registry::{
    PackCoverageDimension, PackOutputKind, SecurityPackRegistry, ValidatedPackManifest,
};
use sentrdel_schema::{
    SCHEMA_V1,
    pack::{SecurityPackManifest, SourceProvenance},
};

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
        evidence_capabilities: vec!["fixture.evidence".to_owned()],
        required_engines: Vec::new(),
        required_features: Vec::new(),
        coverage_dimensions: vec!["DETECTION".to_owned(), "RUNTIME".to_owned()],
    }
}

#[test]
fn registered_pack_retains_only_validated_authority_surface() {
    let mut registry = SecurityPackRegistry::new();
    let pack = registry.register(manifest("fixture.pack")).unwrap();

    assert_eq!(pack.pack_id(), "fixture.pack");
    assert!(
        pack.coverage_dimensions()
            .contains(&PackCoverageDimension::Detection)
    );
    assert!(
        pack.coverage_dimensions()
            .contains(&PackCoverageDimension::Runtime)
    );
    assert_eq!(
        ValidatedPackManifest::output_kinds(),
        [PackOutputKind::Evidence, PackOutputKind::Coverage]
    );
    assert!(registry.get("missing.pack").is_none());
}
