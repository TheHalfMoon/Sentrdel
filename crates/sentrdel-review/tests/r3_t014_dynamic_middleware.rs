use sentrdel_review::business_logic::model::BusinessLogicLimits;
use sentrdel_review::business_logic::route::{
    RouteAdapter, RouteCoverageGapReason, extract_routes,
};
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized fixture path")
}

#[test]
fn dynamic_express_middleware_remains_an_explicit_deterministic_coverage_gap() {
    let source = br#"export function install(app, dynamicMiddleware) {
  app.use(dynamicMiddleware);
}
"#;
    let source_path = path("src/dynamic-middleware.js");
    let limits = BusinessLogicLimits::default();
    let first = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &source_path,
        source,
        limits,
    )
    .expect("first unsupported dynamic middleware classification");
    let second = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &source_path,
        source,
        limits,
    )
    .expect("second unsupported dynamic middleware classification");

    assert_eq!(first, second);
    assert!(first.routes().is_empty());
    assert_eq!(first.gaps().len(), 1);
    assert_eq!(
        first.gaps()[0].reason(),
        RouteCoverageGapReason::UnsupportedMiddleware
    );
}
