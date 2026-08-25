use sentrdel_policy::{
    Verdict,
    rego::{BoundedRegoPolicy, RegoFailure, MAX_INPUT_BYTES},
};

const ENTRYPOINT: &str = "data.sentrdel.t023.decision";

#[test]
fn execution_timer_expiry_is_undecidable_not_allow() {
    let source = r#"
package sentrdel.t023
import rego.v1

default decision := "deny"
decision := "allow" if {
    some x in input.items
    some y in input.items
    some z in input.items
    x + y + z == -1
}
"#;
    let policy = BoundedRegoPolicy::compile(source, ENTRYPOINT, None)
        .expect("bounded timer regression policy should compile");

    // 512^3 candidate triples are deliberately expensive for the interpreter,
    // while the serialized input remains far below the T023 input-size cap.
    // With the engine-specific timer preserved on the per-action clone this
    // evaluation terminates at the configured deadline instead of exhausting
    // the search and returning the default `deny` verdict.
    let items = std::iter::repeat_n("0", 512).collect::<Vec<_>>().join(",");
    let input = format!(r#"{{"items":[{items}]}}"#);
    assert!(input.len() < MAX_INPUT_BYTES);

    let result = policy.evaluate_json(&input);
    assert_eq!(result.verdict(), Verdict::Undecidable);
    assert_eq!(result.failure(), Some(RegoFailure::EvaluationFailed));
}
