use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::{BufReader, Cursor};
use std::process::Command;

use sentrdel_guard::R1_REMOTE_MCP_SUPPORTED;
use sentrdel_guard::mcp::environment::McpChildEnvironment;
use sentrdel_guard::mcp::gateway::{
    McpForwarder, McpGatewayError, McpGatewayLimits, McpInvocation, McpPreflightPolicy,
    ScopedApproval, invoke_bounded,
};
use sentrdel_guard::mcp::protocol::{
    BoundedStdioReader, McpProtocolError, McpProtocolVersion, McpStdioLimits,
};
use sentrdel_guard::mcp::untrusted_content::{
    UntrustedMcpContentKind, UntrustedMcpContentLimits, inspect_untrusted_mcp_text,
};
use sentrdel_guard::sentrdel_policy::Verdict;
use serde_json::Value;

const CLIENT_FIXTURE: &[u8] = include_bytes!("../../../fixtures/mcp/t058-client.jsonl");
const SERVER_FIXTURE: &[u8] = include_bytes!("../../../fixtures/mcp/t058-server.jsonl");
const CREDENTIAL_CANARIES: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "SSH_AUTH_SOCK",
    "DATABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY",
];

struct Policy(Verdict);

impl McpPreflightPolicy for Policy {
    fn evaluate(&self, _invocation: &McpInvocation) -> Verdict {
        self.0
    }
}

#[derive(Default)]
struct FixtureForwarder {
    calls: usize,
    result: Vec<u8>,
}

impl McpForwarder for FixtureForwarder {
    fn forward(&mut self, _invocation: &McpInvocation) -> Result<Vec<u8>, String> {
        self.calls += 1;
        Ok(self.result.clone())
    }
}

fn read_frames(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut reader = BoundedStdioReader::new(
        BufReader::new(Cursor::new(bytes.to_vec())),
        McpStdioLimits::default(),
    )
    .expect("bounded fixture reader");
    let mut frames = Vec::new();
    while let Some(frame) = reader.read_frame().expect("valid fixture frame") {
        frames.push(frame);
    }
    frames
}

#[test]
fn fixture_stdio_guard_covers_policy_versions_untrusted_content_and_bounds() {
    let client_frames = read_frames(CLIENT_FIXTURE);
    let server_frames = read_frames(SERVER_FIXTURE);
    assert_eq!(client_frames.len(), 2);
    assert_eq!(server_frames.len(), 2);

    let initialize: Value = serde_json::from_slice(&client_frames[0]).expect("initialize JSON");
    let advertised = initialize["params"]["protocolVersion"]
        .as_str()
        .expect("fixture protocol version");
    assert_eq!(
        McpProtocolVersion::parse_advertised(advertised).expect("supported protocol"),
        McpProtocolVersion::V2026_07_28
    );
    assert!(matches!(
        McpProtocolVersion::parse_advertised("LATEST"),
        Err(McpProtocolError::UnsupportedProtocolVersion(_))
    ));
    assert!(matches!(
        McpProtocolVersion::parse_advertised("2099-01-01"),
        Err(McpProtocolError::UnsupportedProtocolVersion(_))
    ));

    let call: Value = serde_json::from_slice(&client_frames[1]).expect("call JSON");
    let invocation = McpInvocation::normalize(
        "sentrdel-t058-server",
        call["params"]["name"].as_str().expect("tool name"),
        call["params"]["arguments"].clone(),
        McpGatewayLimits::default(),
    )
    .expect("normalized invocation");

    let mut allow_forwarder = FixtureForwarder {
        result: server_frames[1].clone(),
        ..FixtureForwarder::default()
    };
    let allowed = invoke_bounded(
        &invocation,
        &Policy(Verdict::Allow),
        None,
        &mut allow_forwarder,
        McpGatewayLimits::default(),
    )
    .expect("ALLOW must forward");
    assert_eq!(allowed.verdict, Verdict::Allow);
    assert_eq!(allow_forwarder.calls, 1);

    let mut approval = ScopedApproval::for_invocation(&invocation);
    let mut ask_forwarder = FixtureForwarder {
        result: server_frames[1].clone(),
        ..FixtureForwarder::default()
    };
    let asked = invoke_bounded(
        &invocation,
        &Policy(Verdict::Ask),
        Some(&mut approval),
        &mut ask_forwarder,
        McpGatewayLimits::default(),
    )
    .expect("scoped ASK approval must forward once");
    assert_eq!(asked.verdict, Verdict::Ask);
    assert!(approval.is_consumed());
    assert_eq!(ask_forwarder.calls, 1);

    for verdict in [Verdict::Deny, Verdict::Undecidable] {
        let mut forwarder = FixtureForwarder::default();
        let result = invoke_bounded(
            &invocation,
            &Policy(verdict),
            None,
            &mut forwarder,
            McpGatewayLimits::default(),
        );
        assert!(matches!(
            (verdict, result),
            (Verdict::Deny, Err(McpGatewayError::Denied))
                | (Verdict::Undecidable, Err(McpGatewayError::Undecidable))
        ));
        assert_eq!(forwarder.calls, 0);
    }

    let server_result: Value = serde_json::from_slice(&server_frames[1]).expect("server JSON");
    let malicious = server_result["result"]["content"][0]["text"]
        .as_str()
        .expect("malicious fixture text");
    for kind in [
        UntrustedMcpContentKind::ToolDescription,
        UntrustedMcpContentKind::ToolResult,
    ] {
        let telemetry =
            inspect_untrusted_mcp_text(kind, malicious, UntrustedMcpContentLimits::default())
                .expect("bounded telemetry");
        assert!(telemetry.instruction_shaped());
        assert!(telemetry.candidate_rule_ids.len() >= 3);
        assert!(!format!("{telemetry:?}").contains(malicious));
    }

    let mut giant = BoundedStdioReader::new(
        BufReader::new(Cursor::new(vec![b'x'; 33])),
        McpStdioLimits {
            max_frame_bytes: 16,
            max_buffer_bytes: 16,
        },
    )
    .expect("giant reader");
    assert!(matches!(
        giant.read_frame(),
        Err(McpProtocolError::BufferLimitExceeded { max: 16 })
    ));

    let mut unterminated = BoundedStdioReader::new(
        BufReader::new(Cursor::new(br#"{"jsonrpc":"2.0"}"#.to_vec())),
        McpStdioLimits {
            max_frame_bytes: 64,
            max_buffer_bytes: 64,
        },
    )
    .expect("unterminated reader");
    assert!(matches!(
        unterminated.read_frame(),
        Err(McpProtocolError::UnterminatedFrame { .. })
    ));

    assert!(
        !R1_REMOTE_MCP_SUPPORTED,
        "R1 must not expose remote MCP transport"
    );
}

#[test]
fn default_child_environment_drops_credential_canaries_before_stdio_launch() {
    let environment = McpChildEnvironment::from_runtime(BTreeSet::new())
        .expect("default bounded MCP environment");
    let names = environment.environment_names().collect::<BTreeSet<_>>();
    for canary in CREDENTIAL_CANARIES {
        assert!(!names.contains(canary));
    }

    let mut command = Command::new("not-executed");
    command.env("GITHUB_TOKEN", "t058-canary-must-not-survive");
    command.env("OPENAI_API_KEY", "t058-canary-must-not-survive");
    environment.apply_to_command(&mut command);
    let explicit_names = command
        .get_envs()
        .filter_map(|(name, value)| value.map(|_| name))
        .collect::<BTreeSet<_>>();
    assert!(!explicit_names.contains(OsStr::new("GITHUB_TOKEN")));
    assert!(!explicit_names.contains(OsStr::new("OPENAI_API_KEY")));
}
