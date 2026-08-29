use sentrdel_review::project_detection::DetectionLimits;
use sentrdel_review::stack_detection::{
    PathMatchRule, StackDetectorRegistry, StackDetectorSpec, StackKind,
};

const PROVIDER_RULES: &[PathMatchRule] = &[PathMatchRule::Exact("provider.fixture")];
const FRAMEWORK_RULES: &[PathMatchRule] = &[PathMatchRule::Basename("framework.fixture")];
const DETECTORS: &[StackDetectorSpec] = &[
    StackDetectorSpec::new("provider-fixture", StackKind::Provider, PROVIDER_RULES),
    StackDetectorSpec::new("framework-fixture", StackKind::Framework, FRAMEWORK_RULES),
];

#[test]
fn runtime_owned_extension_points_are_detection_only() {
    let registry = StackDetectorRegistry::new(DETECTORS).unwrap();
    let result = registry
        .detect(
            ["provider.fixture", "apps/web/framework.fixture"],
            DetectionLimits::default(),
        )
        .unwrap();

    assert_eq!(result.providers[0].id, "provider-fixture");
    assert_eq!(result.frameworks[0].id, "framework-fixture");
    assert!(!result.has_security_verdict());
}
