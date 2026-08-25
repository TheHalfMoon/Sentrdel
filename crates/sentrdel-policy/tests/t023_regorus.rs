use sentrdel_policy::{
    Verdict,
    rego::{BoundedRegoPolicy, RegoFailure, RegoPolicyError},
};

const VALID: &str = include_str!("../../../fixtures/policies/t023_valid.rego");
const DISALLOWED_HTTP: &str = include_str!("../../../fixtures/policies/t023_disallowed_http.rego");
const DEEP_INPUT: &str = include_str!("../../../fixtures/policies/t023_deep_input.json");
const ENTRYPOINT: &str = "data.sentrdel.t023.decision";

#[test]
fn valid_fixture_returns_only_bounded_candidates() {
    let policy = BoundedRegoPolicy::compile(VALID, ENTRYPOINT, None).expect("valid fixture");

    assert_eq!(
        policy.evaluate_json(r#"{"action":"read"}"#).verdict(),
        Verdict::Allow
    );
    assert_eq!(
        policy.evaluate_json(r#"{"action":"delete"}"#).verdict(),
        Verdict::Deny
    );
    assert_eq!(
        policy.evaluate_json(r#"{"action":"other"}"#).verdict(),
        Verdict::Ask
    );
}

#[test]
fn disallowed_http_fixture_is_rejected_before_engine_installation() {
    assert_eq!(
        BoundedRegoPolicy::compile(DISALLOWED_HTTP, ENTRYPOINT, None)
            .expect_err("HTTP capability must not enter the bounded policy engine"),
        RegoPolicyError::UnsupportedCall("http.send".to_owned())
    );
}

#[test]
fn bracket_call_cannot_evade_builtin_allowlist() {
    let source = r#"
package sentrdel.t023
import rego.v1

default decision := "deny"
decision := "allow" if object["get"](input, "action", "") == "read"
"#;

    assert_eq!(
        BoundedRegoPolicy::compile(source, ENTRYPOINT, None)
            .expect_err("bracket-form builtin call must be rejected before engine installation"),
        RegoPolicyError::UnsupportedKeyword("bracket-call")
    );
}

#[test]
fn debug_output_redacts_loaded_policy_and_data() {
    const POLICY_SECRET: &str = "T023_POLICY_DEBUG_SECRET";
    const DATA_SECRET: &str = "T023_DATA_DEBUG_SECRET";
    let source = format!(
        "package sentrdel.t023\nimport rego.v1\n# {POLICY_SECRET}\ndecision := \"allow\"\n"
    );
    let data = format!(r#"{{"secret":"{DATA_SECRET}"}}"#);
    let policy = BoundedRegoPolicy::compile(&source, ENTRYPOINT, Some(&data))
        .expect("debug redaction fixture should compile");

    let debug = format!("{policy:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(POLICY_SECRET));
    assert!(!debug.contains(DATA_SECRET));
}

#[test]
fn deep_fixture_is_undecidable_not_allow() {
    let policy = BoundedRegoPolicy::compile(VALID, ENTRYPOINT, None).expect("valid fixture");
    let result = policy.evaluate_json(DEEP_INPUT.trim());

    assert_eq!(result.verdict(), Verdict::Undecidable);
    assert_eq!(result.failure(), Some(RegoFailure::InputTooDeep));
}
