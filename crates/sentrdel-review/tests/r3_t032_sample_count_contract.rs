#![forbid(unsafe_code)]

use serde_json::Value;

const POLICY_BYTES: &[u8] =
    include_bytes!("../../../tests/benchmark/r3-t032-performance-policy.json");

#[test]
fn r3_t032_sample_count_is_exactly_32() {
    let policy: Value = serde_json::from_slice(POLICY_BYTES)
        .expect("R3-T032 performance policy must be valid JSON");
    assert_eq!(policy.get("sample_count").and_then(Value::as_u64), Some(32));
}
