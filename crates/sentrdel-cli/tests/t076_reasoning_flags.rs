use sentrdel_cli::reasoning::{
    NO_NETWORK_FLAG, REASON_FLAG, ReasoningAttempt, ReviewReasoningFlags,
    attach_optional_network_reasoning,
};
use std::cell::Cell;

#[test]
fn reason_is_opt_in_and_no_network_is_an_absolute_network_ceiling() {
    let absent = ReviewReasoningFlags::from_args(["review", "."]);
    assert!(!absent.reason_enabled());
    assert!(!absent.network_reasoning_allowed());

    let enabled = ReviewReasoningFlags::from_args(["review", REASON_FLAG]);
    assert!(enabled.reason_enabled());
    assert!(enabled.network_reasoning_allowed());

    let offline = ReviewReasoningFlags::from_args(["review", REASON_FLAG, NO_NETWORK_FLAG]);
    assert!(offline.reason_enabled());
    assert!(offline.no_network());
    assert!(!offline.network_reasoning_allowed());
}

#[test]
fn no_network_never_invokes_network_reasoner_and_preserves_review() {
    let called = Cell::new(false);
    let deterministic = String::from("deterministic-review-id");
    let result = attach_optional_network_reasoning(
        deterministic.clone(),
        ReviewReasoningFlags::new(true, true),
        || {
            called.set(true);
            Ok::<Vec<&'static str>, &'static str>(vec!["must-not-run"])
        },
    );

    assert!(!called.get());
    assert_eq!(result.deterministic_review(), &deterministic);
    assert_eq!(result.reasoning(), &ReasoningAttempt::NetworkDisabled);
}

#[test]
fn model_failure_cannot_remove_or_replace_deterministic_review() {
    let deterministic = ("review", 42_u64);
    let result = attach_optional_network_reasoning::<_, &'static str, _, _>(
        deterministic,
        ReviewReasoningFlags::new(true, false),
        || Err("model unavailable"),
    );

    assert_eq!(result.deterministic_review(), &deterministic);
    assert_eq!(
        result.reasoning(),
        &ReasoningAttempt::Failed("model unavailable".to_owned())
    );
    assert_eq!(result.into_deterministic_review(), deterministic);
}

#[test]
fn successful_reasoning_is_advisory_and_does_not_replace_review() {
    let deterministic = vec!["finding-a", "finding-b"];
    let result = attach_optional_network_reasoning(
        deterministic.clone(),
        ReviewReasoningFlags::new(true, false),
        || Ok::<_, &'static str>(vec!["inference-evidence"]),
    );

    assert_eq!(result.deterministic_review(), &deterministic);
    assert_eq!(
        result.reasoning(),
        &ReasoningAttempt::Completed(vec!["inference-evidence"])
    );
}
