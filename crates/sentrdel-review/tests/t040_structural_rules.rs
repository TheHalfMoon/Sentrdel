use sentrdel_review::structural::StructuralRegistry;
use sentrdel_review::structural_rules::{
    HIGH_SIGNAL_STRUCTURAL_RULES, high_signal_structural_rules,
};
use sentrdel_review::view::NormalizedRepoPath;

const POSITIVE: &[u8] = include_bytes!("../../../fixtures/repos/t040-structural/positive.js");
const NEGATIVE: &[u8] = include_bytes!("../../../fixtures/repos/t040-structural/negative.js");

fn path(name: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(name, 128).unwrap()
}

#[test]
fn high_signal_rule_set_is_deliberately_small_and_stable() {
    let rules = high_signal_structural_rules();
    assert_eq!(rules, HIGH_SIGNAL_STRUCTURAL_RULES);
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].id(), "js.eval-call");
    assert_eq!(rules[1].id(), "js.dynamic-function-constructor");
}

#[test]
fn positive_fixture_emits_only_the_expected_structural_observations() {
    let registry = StructuralRegistry::new(high_signal_structural_rules()).unwrap();
    let matches = registry
        .scan(&path("fixtures/positive.js"), POSITIVE)
        .unwrap();
    let ids: Vec<_> = matches.iter().map(|matched| matched.rule_id).collect();

    assert_eq!(ids, vec!["js.dynamic-function-constructor", "js.eval-call"]);
    assert!(
        matches
            .iter()
            .all(|matched| matched.path.as_str() == "fixtures/positive.js")
    );
}

#[test]
fn negative_fixture_does_not_match_names_or_safe_json_parsing() {
    let registry = StructuralRegistry::new(high_signal_structural_rules()).unwrap();
    let matches = registry
        .scan(&path("fixtures/negative.js"), NEGATIVE)
        .unwrap();
    assert!(matches.is_empty());
}

#[test]
fn fixture_replay_is_deterministic() {
    let registry = StructuralRegistry::new(high_signal_structural_rules()).unwrap();
    let expected = registry
        .scan(&path("fixtures/positive.js"), POSITIVE)
        .unwrap();
    for _ in 0..3 {
        assert_eq!(
            registry
                .scan(&path("fixtures/positive.js"), POSITIVE)
                .unwrap(),
            expected
        );
    }
}
