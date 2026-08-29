use sentrdel_cli::reasoning::{NO_NETWORK_FLAG, REASON_FLAG, ReviewReasoningFlags};

#[test]
fn reason_is_opt_in_and_no_network_is_an_absolute_network_ceiling() {
    let absent = ReviewReasoningFlags::from_args(["review", "."]);
    assert!(!absent.reason_enabled());
    assert!(!absent.network_reasoning_allowed());

    let enabled = ReviewReasoningFlags::from_args(["review", REASON_FLAG]);
    assert!(enabled.reason_enabled());
    assert!(enabled.network_reasoning_allowed());

    let no_network = ReviewReasoningFlags::from_args(["review", REASON_FLAG, NO_NETWORK_FLAG]);
    assert!(no_network.reason_enabled());
    assert!(no_network.no_network());
    assert!(!no_network.network_reasoning_allowed());
}

#[test]
fn t076_flag_reader_ignores_arguments_owned_by_future_command_parser() {
    let flags = ReviewReasoningFlags::from_args([
        "review",
        "--json",
        "packages/api",
        "--unknown-future-flag",
        NO_NETWORK_FLAG,
    ]);

    assert!(!flags.reason_enabled());
    assert!(flags.no_network());
    assert!(!flags.network_reasoning_allowed());
}
