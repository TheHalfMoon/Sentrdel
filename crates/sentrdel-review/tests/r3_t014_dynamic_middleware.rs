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
fn dynamic_express_middleware_remains_an_explicit_coverage_gap() {
    let source = br#"export function install(app, dynamicMiddleware) {
  app.use(dynamicMiddleware);
}
"#;
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/dynamic-middleware.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify unsupported dynamic middleware");

    assert!(result.routes().is_empty());
    assert_eq!(result.gaps().len(), 1);
    assert_eq!(
        result.gaps()[0].reason(),
        RouteCoverageGapReason::UnsupportedMiddleware
    );
}
