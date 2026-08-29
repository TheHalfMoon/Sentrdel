use sentrdel_review::{
    pack_registry::{PackCoverageDimension, PackOutputKind, SecurityPackRegistry, ValidatedPackManifest},
    supabase_pack::{
        SUPABASE_CAPABILITY_STATIC_AUTH_CONFIG, SUPABASE_CAPABILITY_STATIC_DATABASE,
        SUPABASE_CAPABILITY_STATIC_EDGE_FUNCTIONS, SUPABASE_CAPABILITY_STATIC_KEY_BOUNDARY,
        SUPABASE_CAPABILITY_STATIC_STORAGE, SUPABASE_R2_PACK_ID, SUPABASE_R2_PROVIDER,
        SUPABASE_R2_STATIC_POSTURE_CAPABILITIES, supabase_r2_manifest,
    },
};

#[test]
fn supabase_r2_manifest_registers_under_the_r1_authority_surface() {
    let mut registry = SecurityPackRegistry::new();
    let pack = registry.register(supabase_r2_manifest()).unwrap();

    assert_eq!(pack.pack_id(), SUPABASE_R2_PACK_ID);
    assert_eq!(pack.manifest().provider_or_framework, SUPABASE_R2_PROVIDER);
    assert!(
        pack.coverage_dimensions()
            .contains(&PackCoverageDimension::Detection)
    );
    assert!(
        pack.coverage_dimensions()
            .contains(&PackCoverageDimension::StaticPosture)
    );
    assert!(
        pack.coverage_dimensions()
            .contains(&PackCoverageDimension::LivePosture)
    );
    assert!(
        pack.coverage_dimensions()
            .contains(&PackCoverageDimension::BusinessLogic)
    );
    assert!(
        pack.coverage_dimensions()
            .contains(&PackCoverageDimension::Runtime)
    );
    assert_eq!(
        ValidatedPackManifest::output_kinds(),
        [PackOutputKind::Evidence, PackOutputKind::Coverage]
    );
}

#[test]
fn provider_specific_static_subdimensions_are_capabilities_not_new_global_dimensions() {
    let manifest = supabase_r2_manifest();

    assert_eq!(
        SUPABASE_R2_STATIC_POSTURE_CAPABILITIES,
        [
            SUPABASE_CAPABILITY_STATIC_DATABASE,
            SUPABASE_CAPABILITY_STATIC_STORAGE,
            SUPABASE_CAPABILITY_STATIC_AUTH_CONFIG,
            SUPABASE_CAPABILITY_STATIC_EDGE_FUNCTIONS,
            SUPABASE_CAPABILITY_STATIC_KEY_BOUNDARY,
        ]
    );
    assert_eq!(
        manifest.evidence_capabilities,
        SUPABASE_R2_STATIC_POSTURE_CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        manifest.coverage_dimensions,
        [
            "DETECTION",
            "STATIC_POSTURE",
            "LIVE_POSTURE",
            "BUSINESS_LOGIC",
            "RUNTIME",
        ]
        .map(str::to_owned)
    );
}

#[test]
fn manifest_declares_no_runtime_engine_feature_or_finding_authority() {
    let manifest = supabase_r2_manifest();

    assert!(manifest.required_engines.is_empty());
    assert!(manifest.required_features.is_empty());
    assert!(
        manifest
            .evidence_capabilities
            .iter()
            .all(|capability| !capability.contains("finding") && !capability.contains("policy"))
    );

    let mut value = serde_json::to_value(manifest).unwrap();
    value.as_object_mut().unwrap().insert(
        "finding_capabilities".to_owned(),
        serde_json::json!(["create_finding"]),
    );
    assert!(serde_json::from_value::<sentrdel_schema::pack::SecurityPackManifest>(value).is_err());
}
