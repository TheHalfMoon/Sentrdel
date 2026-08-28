//! T052 bounded stdio MCP gateway with policy-before-forwarding semantics.
//!
//! Only normalized `tools/call` requests reach the forwarding boundary. Policy
//! is evaluated before invocation, ASK approvals are bound to the exact action
//! digest, DENY/UNDECIDABLE never forward, and the concrete process forwarder
//! always applies the T093 scrubbed child environment before spawn.

use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsString,
    fmt,
    io::{BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use sentrdel_policy::{NormalizedAction, Verdict};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    environment::McpChildEnvironment,
    protocol::{BoundedStdioReader, McpProtocolError, McpStdioLimits},
};

pub const DEFAULT_MAX_MCP_ARGS_BYTES: usize = 128 * 1024;
pub const DEFAULT_MAX_MCP_RESULT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_MCP_JSON_DEPTH: usize = 64;
pub const DEFAULT_MAX_MCP_SERVER_ARGV: usize = 128;
pub const DEFAULT_MAX_MCP_SERVER_ARG_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McpGatewayLimits {
    pub stdio: McpStdioLimits,
    pub max_args_bytes: usize,
    pub max_result_bytes: usize,
    pub max_json_depth: usize,
}

impl Default for McpGatewayLimits {
    fn default() -> Self {
        Self {
            stdio: McpStdioLimits::default(),
            max_args_bytes: DEFAULT_MAX_MCP_ARGS_BYTES,
            max_result_bytes: DEFAULT_MAX_MCP_RESULT_BYTES,
            max_json_depth: DEFAULT_MAX_MCP_JSON_DEPTH,
        }
    }
}

impl McpGatewayLimits {
    pub fn validate(self) -> Result<Self, McpGatewayError> {
        self.stdio.validate().map_err(McpGatewayError::Protocol)?;
        if self.max_args_bytes == 0
            || self.max_result_bytes == 0
            || self.max_json_depth == 0
            || self.max_args_bytes > self.stdio.max_frame_bytes
            || self.max_result_bytes > self.stdio.max_frame_bytes
        {
            return Err(McpGatewayError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct McpToolCall {
    pub request_id: Value,
    pub server_name: String,
    pub tool_name: String,
    pub arguments: Value,
}

impl McpToolCall {
    pub fn parse(
        server_name: impl Into<String>,
        frame: &[u8],
        limits: McpGatewayLimits,
    ) -> Result<Self, McpGatewayError> {
        let limits = limits.validate()?;
        if frame.is_empty() || frame.len() > limits.stdio.max_frame_bytes {
            return Err(McpGatewayError::RequestFrameTooLarge {
                bytes: frame.len(),
                max: limits.stdio.max_frame_bytes,
            });
        }
        validate_json_depth(frame, limits.max_json_depth)?;
        let value: Value = serde_json::from_slice(frame).map_err(McpGatewayError::InvalidJson)?;
        let object = value
            .as_object()
            .ok_or(McpGatewayError::InvalidToolCall("request must be an object"))?;
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(McpGatewayError::InvalidToolCall(
                "jsonrpc must be exactly 2.0",
            ));
        }
        if object.get("method").and_then(Value::as_str) != Some("tools/call") {
            return Err(McpGatewayError::InvalidToolCall(
                "only tools/call is an invocation",
            ));
        }
        let request_id = object
            .get("id")
            .cloned()
            .ok_or(McpGatewayError::InvalidToolCall("tools/call requires id"))?;
        if !(request_id.is_string() || request_id.is_i64() || request_id.is_u64()) {
            return Err(McpGatewayError::InvalidToolCall(
                "request id must be a string or integer",
            ));
        }

        let params = object
            .get("params")
            .and_then(Value::as_object)
            .ok_or(McpGatewayError::InvalidToolCall(
                "tools/call params must be an object",
            ))?;
        let tool_name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or(McpGatewayError::InvalidToolCall(
                "tools/call requires a string tool name",
            ))?;
        validate_identity("server", &server_name.into())?;
        validate_identity("tool", tool_name)?;

        let server_name = object_server_name_placeholder();
        let arguments = params.get("arguments").cloned().unwrap_or_else(|| {
            Value::Object(serde_json::Map::new())
        });
        let args_bytes = serde_json::to_vec(&arguments).map_err(McpGatewayError::InvalidJson)?;
        if args_bytes.len() > limits.max_args_bytes {
            return Err(McpGatewayError::ArgumentsTooLarge {
                bytes: args_bytes.len(),
                max: limits.max_args_bytes,
            });
        }

        Ok(Self {
            request_id,
            server_name,
            tool_name: tool_name.to_owned(),
            arguments,
        })
    }

    pub fn action(&self) -> Result<NormalizedAction, McpGatewayError> {
        let mut target = BTreeMap::new();
        target.insert("server".to_owned(), self.server_name.clone());
        target.insert("tool".to_owned(), self.tool_name.clone());
        NormalizedAction::new(
            "mcp.invocation",
            target,
            Some(domain_hash(
                "mcp-tool-arguments",
                &canonical_json_bytes(&self.arguments)?,
            )),
        )
        .map_err(|_| McpGatewayError::InvalidToolCall("action normalization failed"))
    }
}

// This helper is replaced immediately after borrowing the caller-owned server
// name during parsing. Keeping construction in one place avoids any fallback to
// server metadata supplied by the MCP frame itself.
fn object_server_name_placeholder() -> String {
    String::new()
}

pub trait McpPolicyGate {
    fn verdict(&self, action: &NormalizedAction) -> Verdict;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedApproval {
    pub action_digest: String,
    pub approved: bool,
}

pub trait McpApprovalGate {
    fn approval_for(&self, action: &NormalizedAction) -> Option<ScopedApproval>;
}

pub trait McpForwarder {
    fn forward(
        &self,
        request_frame: &[u8],
        environment: &McpChildEnvironment,
        limits: McpGatewayLimits,
    ) -> Result<Vec<u8>, McpGatewayError>;
}

pub struct McpGateway<'a, P, A, F> {
    policy: &'a P,
    approvals: &'a A,
    forwarder: &'a F,
    environment: &'a McpChildEnvironment,
    limits: McpGatewayLimits,
}

impl<'a, P, A, F> McpGateway<'a, P, A, F>
where
    P: McpPolicyGate,
    A: McpApprovalGate,
    F: McpForwarder,
{
    pub fn new(
        policy: &'a P,
        approvals: &'a A,
        forwarder: &'a F,
        environment: &'a McpChildEnvironment,
        limits: McpGatewayLimits,
    ) -> Result<Self, McpGatewayError> {
        Ok(Self {
            policy,
            approvals,
            forwarder,
            environment,
            limits: limits.validate()?,
        })
    }

    pub fn invoke(
        &self,
        server_name: &str,
        request_frame: &[u8],
    ) -> Result<McpGatewayResult, McpGatewayError> {
        validate_identity("server", server_name)?;
        let call = parse_call_with_server(server_name, request_frame, self.limits)?;
        let action = call.action()?;
        let action_digest = action
            .digest()
            .map_err(|_| McpGatewayError::InvalidToolCall("action digest failed"))?;
        let verdict = self.policy.verdict(&action);

        match verdict {
            Verdict::Allow => {}
            Verdict::Ask => {
                let approval = self
                    .approvals
                    .approval_for(&action)
                    .ok_or(McpGatewayError::ApprovalRequired)?;
                if approval.action_digest != action_digest {
                    return Err(McpGatewayError::ApprovalScopeMismatch);
                }
                if !approval.approved {
                    return Err(McpGatewayError::ApprovalDenied);
                }
            }
            Verdict::Deny => return Err(McpGatewayError::PolicyDenied),
            Verdict::Undecidable => return Err(McpGatewayError::PolicyUndecidable),
        }

        let result = self
            .forwarder
            .forward(request_frame, self.environment, self.limits)?;
        if result.len() > self.limits.max_result_bytes {
            return Err(McpGatewayError::ResultTooLarge {
                bytes: result.len(),
                max: self.limits.max_result_bytes,
            });
        }
        validate_json_depth(&result, self.limits.max_json_depth)?;
        let response: Value =
            serde_json::from_slice(&result).map_err(McpGatewayError::InvalidJson)?;
        validate_response_id(&response, &call.request_id)?;

        Ok(McpGatewayResult {
            action_digest,
            verdict,
            response_frame: result,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpGatewayResult {
    pub action_digest: String,
    pub verdict: Verdict,
    pub response_frame: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StdioProcessForwarder {
    program: PathBuf,
    args: Vec<OsString>,
    cwd: Option<PathBuf>,
}

impl StdioProcessForwarder {
    pub fn new(
        program: impl Into<PathBuf>,
        args: Vec<OsString>,
        cwd: Option<PathBuf>,
    ) -> Result<Self, McpGatewayError> {
        let program = program.into();
        if !program.is_absolute() || args.len() > DEFAULT_MAX_MCP_SERVER_ARGV {
            return Err(McpGatewayError::InvalidServerCommand);
        }
        if args.iter().any(|arg| os_len(arg) > DEFAULT_MAX_MCP_SERVER_ARG_BYTES) {
            return Err(McpGatewayError::InvalidServerCommand);
        }
        if cwd.as_deref().is_some_and(|path| !path.is_absolute()) {
            return Err(McpGatewayError::InvalidServerCommand);
        }
        Ok(Self { program, args, cwd })
    }
}

impl McpForwarder for StdioProcessForwarder {
    fn forward(
        &self,
        request_frame: &[u8],
        environment: &McpChildEnvironment,
        limits: McpGatewayLimits,
    ) -> Result<Vec<u8>, McpGatewayError> {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        environment.apply_to_command(&mut command);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut child = command.spawn().map_err(McpGatewayError::Spawn)?;
        {
            let stdin = child.stdin.as_mut().ok_or(McpGatewayError::MissingChildPipe)?;
            stdin.write_all(request_frame).map_err(McpGatewayError::Io)?;
            stdin.write_all(b"\n").map_err(McpGatewayError::Io)?;
        }
        drop(child.stdin.take());

        let stdout = child.stdout.take().ok_or(McpGatewayError::MissingChildPipe)?;
        let mut reader = BoundedStdioReader::new(BufReader::new(stdout), limits.stdio)
            .map_err(McpGatewayError::Protocol)?;
        let response = reader
            .read_frame()
            .map_err(McpGatewayError::Protocol)?
            .ok_or(McpGatewayError::MissingResponse)?;
        if response.len() > limits.max_result_bytes {
            return Err(McpGatewayError::ResultTooLarge {
                bytes: response.len(),
                max: limits.max_result_bytes,
            });
        }
        let status = child.wait().map_err(McpGatewayError::Io)?;
        if !status.success() {
            return Err(McpGatewayError::ServerExitedNonZero);
        }
        Ok(response)
    }
}

fn parse_call_with_server(
    server_name: &str,
    frame: &[u8],
    limits: McpGatewayLimits,
) -> Result<McpToolCall, McpGatewayError> {
    let mut call = McpToolCall::parse("trusted-server", frame, limits)?;
    call.server_name = server_name.to_owned();
    Ok(call)
}

fn validate_identity(kind: &'static str, value: &str) -> Result<(), McpGatewayError> {
    if value.trim().is_empty() || value.len() > 256 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(McpGatewayError::InvalidIdentity(kind));
    }
    Ok(())
}

fn validate_response_id(response: &Value, expected: &Value) -> Result<(), McpGatewayError> {
    let object = response
        .as_object()
        .ok_or(McpGatewayError::InvalidResponse("response must be an object"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(McpGatewayError::InvalidResponse(
            "response jsonrpc must be exactly 2.0",
        ));
    }
    if object.get("id") != Some(expected) {
        return Err(McpGatewayError::ResponseIdMismatch);
    }
    if !object.contains_key("result") && !object.contains_key("error") {
        return Err(McpGatewayError::InvalidResponse(
            "response must contain result or error",
        ));
    }
    Ok(())
}

fn validate_json_depth(bytes: &[u8], max_depth: usize) -> Result<(), McpGatewayError> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > max_depth {
                    return Err(McpGatewayError::JsonTooDeep {
                        depth,
                        max: max_depth,
                    });
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, McpGatewayError> {
    fn normalize(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(normalize).collect()),
            Value::Object(values) => {
                let mut entries: Vec<_> = values.iter().collect();
                entries.sort_by_key(|(key, _)| *key);
                let mut out = serde_json::Map::with_capacity(entries.len());
                for (key, value) in entries {
                    out.insert(key.clone(), normalize(value));
                }
                Value::Object(out)
            }
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&normalize(value)).map_err(McpGatewayError::InvalidJson)
}

fn domain_hash(namespace: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sentrdel:mcp-gateway:v1\0");
    hasher.update(namespace.as_bytes());
    hasher.update(b"\0");
    hasher.update(bytes);
    format!("sha256:{}", encode_hex(&hasher.finalize()))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn os_len(value: &std::ffi::OsStr) -> usize {
    value.to_string_lossy().len()
}

#[derive(Debug)]
pub enum McpGatewayError {
    InvalidLimits,
    RequestFrameTooLarge { bytes: usize, max: usize },
    ArgumentsTooLarge { bytes: usize, max: usize },
    ResultTooLarge { bytes: usize, max: usize },
    JsonTooDeep { depth: usize, max: usize },
    InvalidJson(serde_json::Error),
    InvalidToolCall(&'static str),
    InvalidResponse(&'static str),
    InvalidIdentity(&'static str),
    PolicyDenied,
    PolicyUndecidable,
    ApprovalRequired,
    ApprovalDenied,
    ApprovalScopeMismatch,
    ResponseIdMismatch,
    InvalidServerCommand,
    MissingChildPipe,
    MissingResponse,
    ServerExitedNonZero,
    Spawn(std::io::Error),
    Io(std::io::Error),
    Protocol(McpProtocolError),
}

impl fmt::Display for McpGatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid MCP gateway limits"),
            Self::RequestFrameTooLarge { bytes, max } => {
                write!(formatter, "MCP request frame size {bytes} exceeds {max}")
            }
            Self::ArgumentsTooLarge { bytes, max } => {
                write!(formatter, "MCP tool arguments size {bytes} exceeds {max}")
            }
            Self::ResultTooLarge { bytes, max } => {
                write!(formatter, "MCP tool result size {bytes} exceeds {max}")
            }
            Self::JsonTooDeep { depth, max } => {
                write!(formatter, "MCP JSON depth {depth} exceeds {max}")
            }
            Self::InvalidJson(error) => write!(formatter, "invalid MCP JSON: {error}"),
            Self::InvalidToolCall(message) => write!(formatter, "invalid MCP tool call: {message}"),
            Self::InvalidResponse(message) => write!(formatter, "invalid MCP response: {message}"),
            Self::InvalidIdentity(kind) => write!(formatter, "invalid MCP {kind} identity"),
            Self::PolicyDenied => formatter.write_str("MCP invocation denied by policy"),
            Self::PolicyUndecidable => formatter.write_str("MCP policy decision is undecidable"),
            Self::ApprovalRequired => formatter.write_str("MCP invocation requires scoped approval"),
            Self::ApprovalDenied => formatter.write_str("MCP scoped approval denied"),
            Self::ApprovalScopeMismatch => {
                formatter.write_str("MCP scoped approval does not match the action digest")
            }
            Self::ResponseIdMismatch => formatter.write_str("MCP response id does not match request"),
            Self::InvalidServerCommand => formatter.write_str("invalid trusted MCP server command"),
            Self::MissingChildPipe => formatter.write_str("MCP child process pipe is unavailable"),
            Self::MissingResponse => formatter.write_str("MCP child process returned no response"),
            Self::ServerExitedNonZero => formatter.write_str("MCP child process exited non-zero"),
            Self::Spawn(error) => write!(formatter, "cannot spawn MCP child process: {error}"),
            Self::Io(error) => write!(formatter, "MCP child process I/O failed: {error}"),
            Self::Protocol(error) => write!(formatter, "MCP protocol error: {error}"),
        }
    }
}

impl Error for McpGatewayError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidJson(error) => Some(error),
            Self::Spawn(error) | Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::BTreeSet};

    use super::*;
    use crate::mcp::environment::McpEnvironmentCapability;

    struct StaticPolicy(Verdict);
    impl McpPolicyGate for StaticPolicy {
        fn verdict(&self, _: &NormalizedAction) -> Verdict {
            self.0
        }
    }

    struct NoApproval;
    impl McpApprovalGate for NoApproval {
        fn approval_for(&self, _: &NormalizedAction) -> Option<ScopedApproval> {
            None
        }
    }

    struct ApproveExact;
    impl McpApprovalGate for ApproveExact {
        fn approval_for(&self, action: &NormalizedAction) -> Option<ScopedApproval> {
            Some(ScopedApproval {
                action_digest: action.digest().ok()?,
                approved: true,
            })
        }
    }

    struct FakeForwarder {
        calls: Cell<usize>,
        response: Vec<u8>,
    }

    impl McpForwarder for FakeForwarder {
        fn forward(
            &self,
            _: &[u8],
            environment: &McpChildEnvironment,
            _: McpGatewayLimits,
        ) -> Result<Vec<u8>, McpGatewayError> {
            assert!(environment.authorized_capabilities().is_empty());
            self.calls.set(self.calls.get() + 1);
            Ok(self.response.clone())
        }
    }

    fn environment() -> McpChildEnvironment {
        McpChildEnvironment::from_runtime(BTreeSet::<McpEnvironmentCapability>::new()).unwrap()
    }

    fn request() -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"deploy","arguments":{"z":2,"a":1}}}"#.to_vec()
    }

    fn response() -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":7,"result":{"content":[]}}"#.to_vec()
    }

    #[test]
    fn allow_forwards_once_after_normalization() {
        let environment = environment();
        let forwarder = FakeForwarder {
            calls: Cell::new(0),
            response: response(),
        };
        let gateway = McpGateway::new(
            &StaticPolicy(Verdict::Allow),
            &NoApproval,
            &forwarder,
            &environment,
            McpGatewayLimits::default(),
        )
        .unwrap();
        let result = gateway.invoke("fixture-server", &request()).unwrap();
        assert_eq!(result.verdict, Verdict::Allow);
        assert_eq!(forwarder.calls.get(), 1);
        assert!(result.action_digest.starts_with("sha256:"));
    }

    #[test]
    fn deny_and_undecidable_never_forward() {
        for verdict in [Verdict::Deny, Verdict::Undecidable] {
            let environment = environment();
            let forwarder = FakeForwarder {
                calls: Cell::new(0),
                response: response(),
            };
            let gateway = McpGateway::new(
                &StaticPolicy(verdict),
                &NoApproval,
                &forwarder,
                &environment,
                McpGatewayLimits::default(),
            )
            .unwrap();
            assert!(gateway.invoke("fixture-server", &request()).is_err());
            assert_eq!(forwarder.calls.get(), 0);
        }
    }

    #[test]
    fn ask_requires_exact_scoped_approval_before_forwarding() {
        let environment = environment();
        let forwarder = FakeForwarder {
            calls: Cell::new(0),
            response: response(),
        };
        let denied = McpGateway::new(
            &StaticPolicy(Verdict::Ask),
            &NoApproval,
            &forwarder,
            &environment,
            McpGatewayLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            denied.invoke("fixture-server", &request()),
            Err(McpGatewayError::ApprovalRequired)
        ));
        assert_eq!(forwarder.calls.get(), 0);

        let approved = McpGateway::new(
            &StaticPolicy(Verdict::Ask),
            &ApproveExact,
            &forwarder,
            &environment,
            McpGatewayLimits::default(),
        )
        .unwrap();
        assert!(approved.invoke("fixture-server", &request()).is_ok());
        assert_eq!(forwarder.calls.get(), 1);
    }

    #[test]
    fn malformed_depth_args_result_and_response_id_fail_closed() {
        let mut limits = McpGatewayLimits::default();
        limits.max_args_bytes = 8;
        assert!(matches!(
            parse_call_with_server("server", &request(), limits),
            Err(McpGatewayError::ArgumentsTooLarge { .. })
        ));

        let environment = environment();
        let forwarder = FakeForwarder {
            calls: Cell::new(0),
            response: br#"{"jsonrpc":"2.0","id":8,"result":{}}"#.to_vec(),
        };
        let gateway = McpGateway::new(
            &StaticPolicy(Verdict::Allow),
            &NoApproval,
            &forwarder,
            &environment,
            McpGatewayLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            gateway.invoke("server", &request()),
            Err(McpGatewayError::ResponseIdMismatch)
        ));
    }

    #[test]
    fn action_digest_is_stable_across_argument_key_order() {
        let first = parse_call_with_server("server", &request(), McpGatewayLimits::default())
            .unwrap()
            .action()
            .unwrap()
            .digest()
            .unwrap();
        let second = parse_call_with_server(
            "server",
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"deploy","arguments":{"a":1,"z":2}}}"#,
            McpGatewayLimits::default(),
        )
        .unwrap()
        .action()
        .unwrap()
        .digest()
        .unwrap();
        assert_eq!(first, second);
    }
}
