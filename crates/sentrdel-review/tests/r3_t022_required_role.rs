#![forbid(unsafe_code)]

use sentrdel_review::{
    business_logic::{
        model::{
            BusinessLogicLimits, ComparisonShape, ConfidenceBasis, CrossLayerLink, CrossLayerPath,
            DataOperation, DataOperationKind, DominanceScope, FrameworkFamily, GuardKind,
            GuardObservation, HttpMethod, InvariantDefinition, InvariantEvaluationState,
            InvariantKind, InvariantRequirement, InvariantScope, InvariantSource, LinkBasis,
            PathState, ResourceKind, ResourceRef, RouteObservation, SourceLocation,
            StableSemanticId,
        },
        required_role::{
            R3_REQUIRED_ROLE_CREATES_FINDINGS, R3_REQUIRED_ROLE_EXECUTES_TARGET_CODE,
            R3_REQUIRED_ROLE_PERFORMS_NETWORK_ACCESS,
            R3_REQUIRED_ROLE_PROVES_RUNTIME_AUTHORIZATION,
            R3_REQUIRED_ROLE_USES_ROUTE_NAMING_AS_PRIVILEGE_PROOF,
            R3_REQUIRED_ROLE_USES_UNLINKED_ROLE_TEXT_AS_AUTHORIZATION_PROOF, RequiredRoleInputs,
            evaluate_required_role,
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
        NormalizedRepoPath::parse("src/r3-t022.js", 4_096).expect("normalized path"),
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

fn route(pattern: &str) -> RouteObservation {
    RouteObservation::new(
        id("r3.t022.route", pattern),
        FrameworkFamily::Express,
        HttpMethod::Delete,
        pattern,
        Some("handler".to_owned()),
        Vec::new(),
        vec![location(0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("route")
}

fn operation(resource_name: &str) -> DataOperation {
    DataOperation::new(
        id("r3.t022.operation", resource_name),
        DataOperationKind::Delete,
        resource(resource_name),
        None,
        Vec::new(),
        None,
        None,
        None,
        None,
        vec![location(20)],
        CoverageState::Covered,
        limits(),
    )
    .expect("operation")
}

fn role_guard(
    name: &str,
    values: &[&str],
    dominance: DominanceScope,
    resource_name: Option<&str>,
) -> GuardObservation {
    GuardObservation::new(
        id("r3.t022.guard", name),
        GuardKind::RequiredRole,
        None,
        resource_name.map(resource),
        values.iter().map(|value| (*value).to_owned()).collect(),
        ComparisonShape::Equal,
        dominance,
        vec![location(40)],
        limits(),
    )
    .expect("role guard")
}

fn link(
    name: &str,
    source: StableSemanticId,
    target: StableSemanticId,
    basis: LinkBasis,
    confidence: ConfidenceBasis,
) -> CrossLayerLink {
    CrossLayerLink::new(
        id("r3.t022.link", name),
        source,
        target,
        "supported_privileged_path",
        basis,
        confidence,
        vec![location(60)],
        limits(),
    )
    .expect("link")
}

fn path(
    route: &RouteObservation,
    operation: &DataOperation,
    guard: Option<&GuardObservation>,
    state: PathState,
    authoritative: bool,
) -> CrossLayerPath {
    let mut links = Vec::new();
    let guard_ids = if let Some(guard) = guard {
        links.push(link(
            "route-guard",
            route.route_id().clone(),
            guard.guard_id().clone(),
            if authoritative {
                LinkBasis::ExplicitAdapterLink
            } else {
                LinkBasis::ScipReference
            },
            if authoritative {
                ConfidenceBasis::Extracted
            } else {
                ConfidenceBasis::Ambiguous
            },
        ));
        links.push(link(
            "guard-operation",
            guard.guard_id().clone(),
            operation.operation_id().clone(),
            if authoritative {
                LinkBasis::ExplicitAdapterLink
            } else {
                LinkBasis::ScipReference
            },
            if authoritative {
                ConfidenceBasis::Extracted
            } else {
                ConfidenceBasis::Ambiguous
            },
        ));
        vec![guard.guard_id().clone()]
    } else {
        links.push(link(
            "route-operation",
            route.route_id().clone(),
            operation.operation_id().clone(),
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
        ));
        Vec::new()
    };

    CrossLayerPath::new(
        id("r3.t022.path", "privileged-delete"),
        route.route_id().clone(),
        Vec::new(),
        guard_ids,
        operation.operation_id().clone(),
        None,
        links,
        Vec::new(),
        state,
        vec![location(80)],
        limits(),
    )
    .expect("cross-layer path")
}

fn invariant(pattern: &str, resource_name: &str, roles: &[&str]) -> InvariantDefinition {
    InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "required-role"),
        InvariantKind::RequiredRole,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some(pattern.to_owned()),
            vec![HttpMethod::Delete],
            Some(resource(resource_name)),
            vec![DataOperationKind::Delete],
            Vec::new(),
            limits(),
        )
        .expect("scope"),
        InvariantRequirement::RequiredRole {
            required_roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        },
        vec![location(100)],
        limits(),
    )
    .expect("required-role invariant")
}

fn evaluate(
    invariant: &InvariantDefinition,
    path: &CrossLayerPath,
    route: &RouteObservation,
    guards: &[GuardObservation],
    operation: &DataOperation,
) -> InvariantEvaluationState {
    evaluate_required_role(
        RequiredRoleInputs {
            invariant,
            path,
            route,
            guard_coverage_state: &CoverageState::Covered,
            guards,
            operation,
        },
        limits(),
    )
    .expect("required-role evaluation")
    .state()
}

#[test]
fn matching_dominating_role_guard_on_correlated_path_is_satisfied() {
    let route = route("/admin/accounts/:id");
    let operation = operation("accounts");
    let guard = role_guard(
        "admin",
        &["admin"],
        DominanceScope::SameHandlerPrefix,
        Some("accounts"),
    );
    let path = path(&route, &operation, Some(&guard), PathState::Supported, true);
    let invariant = invariant("/admin/accounts/:id", "accounts", &["admin"]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            std::slice::from_ref(&guard),
            &operation,
        ),
        InvariantEvaluationState::Satisfied
    );
}

#[test]
fn covered_privileged_path_without_role_guard_is_violated() {
    let route = route("/billing/accounts/:id");
    let operation = operation("accounts");
    let path = path(&route, &operation, None, PathState::Supported, true);
    let invariant = invariant("/billing/accounts/:id", "accounts", &["billing-admin"]);

    assert_eq!(
        evaluate(&invariant, &path, &route, &[], &operation),
        InvariantEvaluationState::Violated
    );
}

#[test]
fn incomplete_guard_coverage_stays_unknown_instead_of_inventing_a_missing_guard() {
    let route = route("/admin/accounts/:id");
    let operation = operation("accounts");
    let path = path(&route, &operation, None, PathState::Supported, true);
    let invariant = invariant("/admin/accounts/:id", "accounts", &["admin"]);

    let state = evaluate_required_role(
        RequiredRoleInputs {
            invariant: &invariant,
            path: &path,
            route: &route,
            guard_coverage_state: &CoverageState::Partial,
            guards: &[],
            operation: &operation,
        },
        limits(),
    )
    .expect("partial guard coverage evaluation")
    .state();

    assert_eq!(state, InvariantEvaluationState::Unknown);
    assert_ne!(state, InvariantEvaluationState::Violated);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}

#[test]
fn supported_wrong_role_guard_does_not_satisfy_required_role() {
    let route = route("/admin/accounts/:id");
    let operation = operation("accounts");
    let guard = role_guard(
        "viewer",
        &["viewer"],
        DominanceScope::SupportedMiddlewarePrefix,
        Some("accounts"),
    );
    let path = path(&route, &operation, Some(&guard), PathState::Supported, true);
    let invariant = invariant("/admin/accounts/:id", "accounts", &["admin"]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            std::slice::from_ref(&guard),
            &operation,
        ),
        InvariantEvaluationState::Violated
    );
}

#[test]
fn lexical_or_unlinked_role_text_elsewhere_does_not_authorize_privileged_path() {
    let route = route("/admin/delete-account");
    let operation = operation("accounts");
    let unrelated = role_guard(
        "unlinked-admin-text",
        &["admin"],
        DominanceScope::SameHandlerPrefix,
        Some("accounts"),
    );
    let path = path(&route, &operation, None, PathState::Supported, true);
    let invariant = invariant("/admin/delete-account", "accounts", &["admin"]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            std::slice::from_ref(&unrelated),
            &operation,
        ),
        InvariantEvaluationState::Violated
    );
}

#[test]
fn matching_role_with_unknown_dominance_remains_unknown() {
    let route = route("/admin/accounts/:id");
    let operation = operation("accounts");
    let guard = role_guard("admin", &["admin"], DominanceScope::Unknown, Some("accounts"));
    let path = path(&route, &operation, Some(&guard), PathState::Supported, true);
    let invariant = invariant("/admin/accounts/:id", "accounts", &["admin"]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            std::slice::from_ref(&guard),
            &operation,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn ambiguous_linkage_remains_unknown_and_never_becomes_secure() {
    let route = route("/admin/accounts/:id");
    let operation = operation("accounts");
    let guard = role_guard(
        "admin",
        &["admin"],
        DominanceScope::LinkedHelper,
        Some("accounts"),
    );
    let path = path(&route, &operation, Some(&guard), PathState::Ambiguous, false);
    let invariant = invariant("/admin/accounts/:id", "accounts", &["admin"]);

    let state = evaluate(
        &invariant,
        &path,
        &route,
        std::slice::from_ref(&guard),
        &operation,
    );
    assert_eq!(state, InvariantEvaluationState::Unknown);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}

#[test]
fn invariant_scope_not_route_naming_controls_applicability() {
    let route = route("/admin/accounts/:id");
    let operation = operation("accounts");
    let path = path(&route, &operation, None, PathState::Supported, true);
    let invariant = invariant("/different/route", "accounts", &["admin"]);

    assert_eq!(
        evaluate(&invariant, &path, &route, &[], &operation),
        InvariantEvaluationState::NotApplicable
    );
}

#[test]
fn required_role_evaluator_grants_no_runtime_finding_or_lexical_authority() {
    const { assert!(!R3_REQUIRED_ROLE_CREATES_FINDINGS) };
    const { assert!(!R3_REQUIRED_ROLE_EXECUTES_TARGET_CODE) };
    const { assert!(!R3_REQUIRED_ROLE_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!R3_REQUIRED_ROLE_PROVES_RUNTIME_AUTHORIZATION) };
    const { assert!(!R3_REQUIRED_ROLE_USES_ROUTE_NAMING_AS_PRIVILEGE_PROOF) };
    const { assert!(!R3_REQUIRED_ROLE_USES_UNLINKED_ROLE_TEXT_AS_AUTHORIZATION_PROOF) };
}
