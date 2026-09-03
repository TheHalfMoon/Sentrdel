use sentrdel_review::business_logic::model::{BusinessLogicLimits, ValueOriginKind};
use sentrdel_review::business_logic::route::{
    RouteAdapter, RouteCoverageGapReason, extract_routes,
};
use sentrdel_review::business_logic::value::{ValueCoverageGapReason, extract_value_origins};
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized fixture path")
}

#[test]
fn shadowed_express_callback_name_cannot_route_back_an_unregistered_exported_handler() {
    let source = br#"import express from "express";

const app = express();

export function handler(req) {
  return req.params.id;
}

{
  const handler = (_req, res) => res.end();
  app.get("/registered", handler);
}
"#;

    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/handler-identity.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect shadowed Express callback identity");

    assert!(
        !result
            .values()
            .iter()
            .any(|value| value.origin_kind() == ValueOriginKind::RequestPath)
    );
    assert!(
        result
            .values()
            .iter()
            .any(|value| value.origin_kind() == ValueOriginKind::Unknown)
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == ValueCoverageGapReason::AmbiguousBinding)
    );
}

#[test]
fn shadowed_express_factory_cannot_mint_route_or_request_origin() {
    let source = br#"import express from "express";

function format(express) {
  const app = express();
  app.get("/", (req) => req.params.id);
}
"#;
    let fixture_path = path("src/shadowed-factory.js");

    let routes = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &fixture_path,
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect shadowed Express factory route");
    assert!(routes.routes().is_empty());
    assert!(
        routes
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
    );

    let values = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &fixture_path,
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect shadowed Express factory values");
    assert!(
        !values
            .values()
            .iter()
            .any(|value| value.origin_kind() == ValueOriginKind::RequestPath)
    );
    assert!(
        values
            .gaps()
            .iter()
            .any(|gap| gap.reason() == ValueCoverageGapReason::AmbiguousBinding)
    );
}
