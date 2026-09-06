#![forbid(unsafe_code)]

use sentrdel_review::{
    business_logic::{
        model::{
            BusinessLogicLimits, ConfidenceBasis, CrossLayerLink, CrossLayerPath, DataOperation,
            DataOperationKind, FieldSet, FieldSetMode, FrameworkFamily, HttpMethod,
            InvariantDefinition, InvariantEvaluationState, InvariantKind, InvariantRequirement,
            InvariantScope, InvariantSource, LinkBasis, PathState, ResourceKind, ResourceRef,
            RouteObservation, SourceLocation, StableSemanticId,
        },
        protected_properties::{
            ProtectedPropertiesError, ProtectedPropertiesInputs,
            R3_PROTECTED_PROPERTIES_CREATES_FINDINGS, R3_PROTECTED_PROPERTIES_EXECUTES_TARGET_CODE,
            R3_PROTECTED_PROPERTIES_PERFORMS_NETWORK_ACCESS,
            R3_PROTECTED_PROPERTIES_PROVES_RUNTIME_FIELD_SAFETY,
            R3_PROTECTED_PROPERTIES_USES_UNLINKED_ALLOWLIST_AS_SAFETY_PROOF,
            evaluate_protected_properties,
        },
    },
    view::NormalizedRepoPath,
};
use sentrdel_schema::coverage::CoverageState;

fn limits() -> BusinessLogicLimits {
    BusinessLogicLimits::default()
}

fn id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], limits()).expect("stable semantic id")
}

fn location(start: usize) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse("src/r3-t023.js", 4_096).expect("normalized path"),
        start,
        start + 8,
        format!("sha256:{start:064x}"),
    )
    .expect("source location")
}

fn resource(name: &str) -> ResourceRef {
    ResourceRef::new(
        Some("supabase".to_owned()),
        Some("public".to_owned()),
        name,
        ResourceKind::Table,
        None,
        limits(),
    )
    .expect("resource")
}

fn route(pattern: &str, coverage_state: CoverageState) -> RouteObservation {
    RouteObservation::new(
        id("r3.t023.route", pattern),
        FrameworkFamily::Express,
        HttpMethod::Patch,
        pattern,
        Some("handler".to_owned()),
        Vec::new(),
        vec![location(0)],
        coverage_state,
        limits(),
    )
    .expect("route")
}

fn field_set(mode: FieldSetMode, fields: &[&str]) -> FieldSet {
    FieldSet::new(
        mode,
        fields.iter().map(|field| (*field).to_owned()).collect(),
        Vec::new(),
        location(40),
        limits(),
    )
    .expect("field set")
}

fn operation(
    kind: DataOperationKind,
    mutation_fields: Option<FieldSet>,
    coverage_state: CoverageState,
) -> DataOperation {
    DataOperation::new(
        id("r3.t023.operation", "profile-write"),
        kind,
        resource("profiles"),
        None,
        Vec::new(),
        None,
        mutation_fields,
        None,
        None,
        vec![location(60)],
        coverage_state,
        limits(),
    )
    .expect("operation")
}

fn path_with_link(
    route: &RouteObservation,
    operation: &DataOperation,
    path_state: PathState,
    basis: LinkBasis,
    confidence: ConfidenceBasis,
) -> CrossLayerPath {
    let link = CrossLayerLink::new(
        id("r3.t023.link", "route-operation"),
        route.route_id().clone(),
        operation.operation_id().clone(),
        "supported_route_operation",
        basis,
        confidence,
        vec![location(80)],
        limits(),
    )
    .expect("link");
    CrossLayerPath::new(
        id("r3.t023.path", "profile-write"),
        route.route_id().clone(),
        Vec::new(),
        Vec::new(),
        operation.operation_id().clone(),
        None,
        vec![link],
        Vec::new(),
        path_state,
        vec![location(100)],
        limits(),
    )
    .expect("path")
}

fn path(
    route: &RouteObservation,
    operation: &DataOperation,
    path_state: PathState,
) -> CrossLayerPath {
    path_with_link(
        route,
        operation,
        path_state,
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
    )
}

fn invariant(pattern: &str, properties: &[&str]) -> InvariantDefinition {
    InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "protected-properties"),
        InvariantKind::ProtectedProperties,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some(pattern.to_owned()),
            vec![HttpMethod::Patch],
            Some(resource("profiles")),
            Vec::new(),
            Vec::new(),
            limits(),
        )
        .expect("scope"),
        InvariantRequirement::ProtectedProperties {
            protected_properties: properties
                .iter()
                .map(|property| (*property).to_owned())
                .collect(),
            mutation_operations: vec![DataOperationKind::Update, DataOperationKind::Upsert],
        },
        vec![location(120)],
        limits(),
    )
    .expect("invariant")
}

fn evaluate(
    invariant: &InvariantDefinition,
    path: &CrossLayerPath,
    route: &RouteObservation,
    operation: &DataOperation,
) -> InvariantEvaluationState {
    evaluate_protected_properties(
        ProtectedPropertiesInputs {
            invariant,
            path,
            route,
            operation,
        },
        limits(),
    )
    .expect("protected-properties evaluation")
    .state()
}

#[test]
fn broad_request_controlled_mutation_of_protected_resource_is_violated() {
    let route = route("/profiles/:id", CoverageState::Covered);
    let operation = operation(
        DataOperationKind::Update,
        Some(field_set(FieldSetMode::BroadRequestObject, &[])),
        CoverageState::Covered,
    );
    let path = path(&route, &operation, PathState::Supported);
    let invariant = invariant("/profiles/:id", &["role", "is_admin", "tenant_id"]);

    assert_eq!(
        evaluate(&invariant, &path, &route, &operation),
        InvariantEvaluationState::Violated
    );
}

#[test]
fn broad_mode_cannot_masquerade_as_safe_explicit_allowlist() {
    let route = route("/profiles/:id", CoverageState::Covered);
    let operation = operation(
        DataOperationKind::Update,
        Some(field_set(
            FieldSetMode::BroadRequestObject,
            &["display_name", "timezone"],
        )),
        CoverageState::Covered,
    );
    let path = path(&route, &operation, PathState::Supported);
    let invariant = invariant("/profiles/:id", &["role", "is_admin"]);

    assert_eq!(
        evaluate(&invariant, &path, &route, &operation),
        InvariantEvaluationState::Violated
    );
}

#[test]
fn explicit_allowlist_excluding_protected_properties_is_satisfied() {
    let route = route("/profiles/:id", CoverageState::Covered);
    let operation = operation(
        DataOperationKind::Update,
        Some(field_set(
            FieldSetMode::Explicit,
            &["display_name", "timezone"],
        )),
        CoverageState::Covered,
    );
    let path = path(&route, &operation, PathState::Supported);
    let invariant = invariant("/profiles/:id", &["role", "is_admin", "tenant_id"]);

    assert_eq!(
        evaluate(&invariant, &path, &route, &operation),
        InvariantEvaluationState::Satisfied
    );
}

#[test]
fn explicit_mutation_including_protected_property_is_violated() {
    let route = route("/profiles/:id", CoverageState::Covered);
    let operation = operation(
        DataOperationKind::Upsert,
        Some(field_set(
            FieldSetMode::Explicit,
            &["display_name", "is_admin"],
        )),
        CoverageState::Covered,
    );
    let path = path(&route, &operation, PathState::Supported);
    let invariant = invariant("/profiles/:id", &["role", "is_admin", "tenant_id"]);

    assert_eq!(
        evaluate(&invariant, &path, &route, &operation),
        InvariantEvaluationState::Violated
    );
}

#[test]
fn dynamic_or_unknown_field_sets_remain_unknown() {
    for mode in [FieldSetMode::Dynamic, FieldSetMode::Unknown] {
        let route = route("/profiles/:id", CoverageState::Covered);
        let operation = operation(
            DataOperationKind::Update,
            Some(field_set(mode, &[])),
            CoverageState::Covered,
        );
        let path = path(&route, &operation, PathState::Supported);
        let invariant = invariant("/profiles/:id", &["role"]);

        assert_eq!(
            evaluate(&invariant, &path, &route, &operation),
            InvariantEvaluationState::Unknown
        );
    }
}

#[test]
fn missing_mutation_field_set_remains_unknown() {
    let route = route("/profiles/:id", CoverageState::Covered);
    let operation = operation(DataOperationKind::Update, None, CoverageState::Covered);
    let path = path(&route, &operation, PathState::Supported);
    let invariant = invariant("/profiles/:id", &["role"]);

    assert_eq!(
        evaluate(&invariant, &path, &route, &operation),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn partial_path_or_operation_coverage_cannot_be_satisfied_or_violated() {
    let route = route("/profiles/:id", CoverageState::Covered);
    let operation = operation(
        DataOperationKind::Update,
        Some(field_set(FieldSetMode::BroadRequestObject, &[])),
        CoverageState::Partial,
    );
    let path = path(&route, &operation, PathState::Partial);
    let invariant = invariant("/profiles/:id", &["role"]);

    assert_eq!(
        evaluate(&invariant, &path, &route, &operation),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn non_authoritative_path_links_cannot_produce_satisfied() {
    for (basis, confidence) in [
        (LinkBasis::ExplicitAdapterLink, ConfidenceBasis::Inferred),
        (LinkBasis::ExplicitAdapterLink, ConfidenceBasis::Ambiguous),
        (LinkBasis::Unknown, ConfidenceBasis::Extracted),
    ] {
        let route = route("/profiles/:id", CoverageState::Covered);
        let operation = operation(
            DataOperationKind::Update,
            Some(field_set(FieldSetMode::Explicit, &["display_name"])),
            CoverageState::Covered,
        );
        let path = path_with_link(&route, &operation, PathState::Supported, basis, confidence);
        let invariant = invariant("/profiles/:id", &["role"]);
        let state = evaluate(&invariant, &path, &route, &operation);

        assert_eq!(state, InvariantEvaluationState::Unknown);
        assert_ne!(state, InvariantEvaluationState::Satisfied);
    }
}

#[test]
fn route_scope_mismatch_is_not_applicable() {
    let route = route("/profiles/:id", CoverageState::Covered);
    let operation = operation(
        DataOperationKind::Update,
        Some(field_set(FieldSetMode::BroadRequestObject, &[])),
        CoverageState::Covered,
    );
    let path = path(&route, &operation, PathState::Supported);
    let invariant = invariant("/accounts/:id", &["role"]);

    assert_eq!(
        evaluate(&invariant, &path, &route, &operation),
        InvariantEvaluationState::NotApplicable
    );
}

#[test]
fn non_property_mutation_operation_is_not_applicable() {
    let route = route("/profiles/:id", CoverageState::Covered);
    let operation = operation(DataOperationKind::Read, None, CoverageState::Covered);
    let path = path(&route, &operation, PathState::Supported);
    let invariant = invariant("/profiles/:id", &["role"]);

    assert_eq!(
        evaluate(&invariant, &path, &route, &operation),
        InvariantEvaluationState::NotApplicable
    );
}

#[test]
fn invalid_empty_protected_property_requirement_is_rejected_by_model() {
    let result = InvariantDefinition::new(
        id(
            "sentrdel.r3.builtin-invariant",
            "empty-protected-properties",
        ),
        InvariantKind::ProtectedProperties,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some("/profiles/:id".to_owned()),
            vec![HttpMethod::Patch],
            Some(resource("profiles")),
            Vec::new(),
            Vec::new(),
            limits(),
        )
        .expect("scope"),
        InvariantRequirement::ProtectedProperties {
            protected_properties: Vec::new(),
            mutation_operations: vec![DataOperationKind::Update],
        },
        vec![location(130)],
        limits(),
    );

    assert!(result.is_err());
}

#[test]
fn wrong_invariant_kind_is_rejected() {
    let route = route("/profiles/:id", CoverageState::Covered);
    let operation = operation(
        DataOperationKind::Update,
        Some(field_set(FieldSetMode::Explicit, &["display_name"])),
        CoverageState::Covered,
    );
    let path = path(&route, &operation, PathState::Supported);
    let wrong = InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "wrong-kind"),
        InvariantKind::RequiredRole,
        InvariantSource::BuiltIn,
        InvariantScope::new(None, Vec::new(), None, Vec::new(), Vec::new(), limits())
            .expect("scope"),
        InvariantRequirement::RequiredRole {
            required_roles: vec!["admin".to_owned()],
        },
        vec![location(140)],
        limits(),
    )
    .expect("wrong-kind invariant");

    let error = evaluate_protected_properties(
        ProtectedPropertiesInputs {
            invariant: &wrong,
            path: &path,
            route: &route,
            operation: &operation,
        },
        limits(),
    )
    .expect_err("wrong invariant kind must fail");
    assert!(matches!(
        error,
        ProtectedPropertiesError::InvalidInvariantKind
    ));
}

#[test]
fn mismatched_path_route_is_rejected() {
    let primary_route = route("/profiles/:id", CoverageState::Covered);
    let other_route = route("/other/:id", CoverageState::Covered);
    let operation = operation(
        DataOperationKind::Update,
        Some(field_set(FieldSetMode::Explicit, &["display_name"])),
        CoverageState::Covered,
    );
    let path = path(&primary_route, &operation, PathState::Supported);
    let invariant = invariant("/profiles/:id", &["role"]);

    let error = evaluate_protected_properties(
        ProtectedPropertiesInputs {
            invariant: &invariant,
            path: &path,
            route: &other_route,
            operation: &operation,
        },
        limits(),
    )
    .expect_err("mismatched path route must fail");
    assert!(matches!(error, ProtectedPropertiesError::PathRouteMismatch));
}

#[test]
fn t023_authority_canaries_remain_false() {
    const { assert!(!R3_PROTECTED_PROPERTIES_CREATES_FINDINGS) };
    const { assert!(!R3_PROTECTED_PROPERTIES_EXECUTES_TARGET_CODE) };
    const { assert!(!R3_PROTECTED_PROPERTIES_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!R3_PROTECTED_PROPERTIES_PROVES_RUNTIME_FIELD_SAFETY) };
    const { assert!(!R3_PROTECTED_PROPERTIES_USES_UNLINKED_ALLOWLIST_AS_SAFETY_PROOF) };
}
