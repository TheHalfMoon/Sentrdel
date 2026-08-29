#![forbid(unsafe_code)]

use sentrdel_guard::{
    mcp::{
        gateway::{McpGatewayLimits, McpInvocation, McpPreflightPolicy},
        protocol::{BoundedStdioReader, McpProtocolError, McpStdioLimits},
    },
    sentrdel_policy::Verdict,
};
use std::{
    env,
    hint::black_box,
    io::{BufReader, Cursor},
    thread::available_parallelism,
    time::{Duration, Instant},
};

const POLICY_TARGET: Duration = Duration::from_millis(50);
const POLICY_SAMPLES: usize = 2_000;

struct FixturePolicy;

impl McpPreflightPolicy for FixturePolicy {
    fn evaluate(&self, invocation: &McpInvocation) -> Verdict {
        if invocation.server() == "fixture-server"
            && invocation.tool() == "read_file"
            && invocation
                .arguments()
                .get("path")
                .and_then(|value| value.as_str())
                .is_some()
        {
            Verdict::Allow
        } else {
            Verdict::Undecidable
        }
    }
}

fn p95(samples: &mut [Duration]) -> Duration {
    assert!(!samples.is_empty(), "latency benchmark requires samples");
    samples.sort_unstable();
    let rank = samples.len().saturating_mul(95).div_ceil(100).max(1);
    samples[rank - 1]
}

#[test]
fn in_process_policy_p95_excludes_transport_and_wait_time() {
    let invocation = McpInvocation::normalize(
        "fixture-server",
        "read_file",
        serde_json::json!({"path":"src/lib.rs","max_bytes":4096}),
        McpGatewayLimits::default(),
    )
    .expect("bounded invocation");
    let policy = FixturePolicy;

    assert_eq!(policy.evaluate(&invocation), Verdict::Allow);
    let mut samples = Vec::with_capacity(POLICY_SAMPLES);
    for _ in 0..POLICY_SAMPLES {
        // Keep transport, downstream forwarding, human approval, and framing wait outside this timer.
        let started = Instant::now();
        let verdict = black_box(&policy).evaluate(black_box(&invocation));
        let elapsed = started.elapsed();
        assert_eq!(verdict, Verdict::Allow);
        samples.push(elapsed);
    }
    let observed = p95(&mut samples);

    println!(
        "{{\"benchmark\":\"sentrdelbench-r1/t080-mcp-policy-latency-v1\",\"machine\":{{\"os\":\"{}\",\"arch\":\"{}\",\"logical_cpus\":{},\"github_actions\":{}}},\"samples\":{},\"p95_micros\":{},\"target_micros\":{},\"passed\":{}}}",
        env::consts::OS,
        env::consts::ARCH,
        available_parallelism().map_or(1, usize::from),
        env::var_os("GITHUB_ACTIONS").is_some(),
        POLICY_SAMPLES,
        observed.as_micros(),
        POLICY_TARGET.as_micros(),
        observed < POLICY_TARGET,
    );

    assert!(
        observed < POLICY_TARGET,
        "in-process MCP policy p95 must remain below 50ms; downstream forwarding, human approval, and framing wait are intentionally outside this timer"
    );
}

#[test]
fn stdio_frame_memory_is_bounded_by_configured_caps() {
    let limits = McpStdioLimits {
        max_frame_bytes: 64,
        max_buffer_bytes: 96,
    };
    assert_eq!(limits.validate().expect("valid bounded limits"), limits);

    let accepted = vec![b'a'; limits.max_frame_bytes];
    let mut accepted_wire = accepted.clone();
    accepted_wire.push(b'\n');
    let mut reader = BoundedStdioReader::new(
        BufReader::with_capacity(7, Cursor::new(accepted_wire)),
        limits,
    )
    .expect("bounded reader");
    assert_eq!(reader.read_frame().expect("bounded frame"), Some(accepted));

    let mut oversized_wire = vec![b'b'; limits.max_frame_bytes + 1];
    oversized_wire.push(b'\n');
    let mut oversized = BoundedStdioReader::new(
        BufReader::with_capacity(7, Cursor::new(oversized_wire)),
        limits,
    )
    .expect("bounded reader");
    assert!(matches!(
        oversized.read_frame(),
        Err(McpProtocolError::FrameTooLarge { max: 64 })
    ));

    let buffer_tighter_than_frame = McpStdioLimits {
        max_frame_bytes: 128,
        max_buffer_bytes: 64,
    };
    assert!(matches!(
        buffer_tighter_than_frame.validate(),
        Err(McpProtocolError::InvalidLimits)
    ));
}
