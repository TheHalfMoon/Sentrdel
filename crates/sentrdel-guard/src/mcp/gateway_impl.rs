//! T052 bounded pre-invocation MCP gateway.
//!
//! Invocation bytes are normalized and bounded before policy. `DENY` and
//! `UNDECIDABLE` fail closed. `ASK` requires an exact, one-shot approval.
//! Forwarding stays behind a trusted stdio adapter launched under T093's
//! scrubbed child-environment boundary.

use std::{error::Error, fmt};

use crate::sentrdel_policy::Verdict;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const DEFAULT_MAX_MCP_ARGUMENT_BYTES: usize = 256 * 1024;
pub const DEFAULT_MAX_MCP_RESULT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_MCP_NAME_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McpGatewayLimits {
    pub max_argument_bytes: usize,
    pub max_result_bytes: usize,
    pub max_name_bytes: usize,
}

impl Default for McpGatewayLimits {
    fn default() -> Self {
        Self {
            max_argument_bytes: DEFAULT_MAX_MCP_ARGUMENT_BYTES,
            max_result_bytes: DEFAULT_MAX_MCP_RESULT_BYTES,
            max_name_bytes: DEFAULT_MAX_MCP_NAME_BYTES,
        }
    }
}

impl McpGatewayLimits {
    pub fn validate(self) -> Result<Self, McpGatewayError> {
        if self.max_argument_bytes == 0 || self.max_result_bytes == 0 || self.max_name_bytes == 0 {
            return Err(McpGatewayError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct McpInvocation {
    server: String,
    tool: String,
    arguments: Value,
    arguments_bytes: Vec<u8>,
    scope_digest: String,
}

impl McpInvocation {
    pub fn normalize(
        server: impl Into<String>,
        tool: impl Into<String>,
        arguments: Value,
        limits: McpGatewayLimits,
    ) -> Result<Self, McpGatewayError> {
        let limits = limits.validate()?;
        let server = server.into();
        let tool = tool.into();
        validate_name("server", &server, limits.max_name_bytes)?;
        validate_name("tool", &tool, limits.max_name_bytes)?;

        let arguments_bytes = serde_json::to_vec(&arguments).map_err(McpGatewayError::Json)?;
        if arguments_bytes.len() > limits.max_argument_bytes {
            return Err(McpGatewayError::ArgumentsTooLarge {
                size: arguments_bytes.len(),
                max: limits.max_argument_bytes,
            });
        }

        let scope_digest = scope_digest(&server, &tool, &arguments_bytes);
        Ok(Self {
            server,
            tool,
            arguments,
            arguments_bytes,
            scope_digest,
        })
    }

    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    #[must_use]
    pub fn arguments(&self) -> &Value {
        &self.arguments
    }

    #[must_use]
    pub fn arguments_bytes(&self) -> &[u8] {
        &self.arguments_bytes
    }

    #[must_use]
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }
}

pub trait McpPreflightPolicy {
    fn evaluate(&self, invocation: &McpInvocation) -> Verdict;
}

pub trait McpForwarder {
    /// Forward through the already-authorized bounded stdio transport.
    /// Concrete child launch must use T093 `McpChildEnvironment`.
    fn forward(&mut self, invocation: &McpInvocation) -> Result<Vec<u8>, String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedApproval {
    scope_digest: String,
    consumed: bool,
}

impl ScopedApproval {
    #[must_use]
    pub fn for_invocation(invocation: &McpInvocation) -> Self {
        Self {
            scope_digest: invocation.scope_digest.clone(),
            consumed: false,
        }
    }

    fn consume_for(&mut self, invocation: &McpInvocation) -> Result<(), McpGatewayError> {
        if self.consumed {
            return Err(McpGatewayError::ApprovalAlreadyConsumed);
        }
        if self.scope_digest != invocation.scope_digest {
            return Err(McpGatewayError::ApprovalScopeMismatch);
        }
        self.consumed = true;
        Ok(())
    }

    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpGatewayOutcome {
    pub verdict: Verdict,
    pub scope_digest: String,
    pub result: Vec<u8>,
}

pub fn invoke_bounded<P, F>(
    invocation: &McpInvocation,
    policy: &P,
    approval: Option<&mut ScopedApproval>,
    forwarder: &mut F,
    limits: McpGatewayLimits,
) -> Result<McpGatewayOutcome, McpGatewayError>
where
    P: McpPreflightPolicy,
    F: McpForwarder,
{
    let limits = limits.validate()?;
    let verdict = policy.evaluate(invocation);

    match verdict {
        Verdict::Allow => {}
        Verdict::Ask => approval
            .ok_or(McpGatewayError::ApprovalRequired)?
            .consume_for(invocation)?,
        Verdict::Deny => return Err(McpGatewayError::Denied),
        Verdict::Undecidable => return Err(McpGatewayError::Undecidable),
    }

    let result = forwarder
        .forward(invocation)
        .map_err(McpGatewayError::Forwarding)?;
    if result.len() > limits.max_result_bytes {
        return Err(McpGatewayError::ResultTooLarge {
            size: result.len(),
            max: limits.max_result_bytes,
        });
    }

    Ok(McpGatewayOutcome {
        verdict,
        scope_digest: invocation.scope_digest.clone(),
        result,
    })
}

#[derive(Debug)]
pub enum McpGatewayError {
    InvalidLimits,
    EmptyName(&'static str),
    PaddedName(&'static str),
    NameTooLarge {
        field: &'static str,
        size: usize,
        max: usize,
    },
    Json(serde_json::Error),
    ArgumentsTooLarge {
        size: usize,
        max: usize,
    },
    ResultTooLarge {
        size: usize,
        max: usize,
    },
    ApprovalRequired,
    ApprovalScopeMismatch,
    ApprovalAlreadyConsumed,
    Denied,
    Undecidable,
    Forwarding(String),
}

impl fmt::Display for McpGatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("MCP gateway limits must be non-zero"),
            Self::EmptyName(field) => write!(formatter, "MCP {field} name must not be empty"),
            Self::PaddedName(field) => write!(formatter, "MCP {field} name must not be padded"),
            Self::NameTooLarge { field, size, max } => write!(
                formatter,
                "MCP {field} name is {size} bytes and exceeds cap {max}"
            ),
            Self::Json(error) => write!(formatter, "MCP arguments cannot be serialized: {error}"),
            Self::ArgumentsTooLarge { size, max } => write!(
                formatter,
                "MCP arguments are {size} bytes and exceed cap {max}"
            ),
            Self::ResultTooLarge { size, max } => write!(
                formatter,
                "MCP result is {size} bytes and exceeds cap {max}"
            ),
            Self::ApprovalRequired => {
                formatter.write_str("MCP invocation requires scoped approval")
            }
            Self::ApprovalScopeMismatch => {
                formatter.write_str("MCP approval does not match invocation scope")
            }
            Self::ApprovalAlreadyConsumed => {
                formatter.write_str("MCP scoped approval was already consumed")
            }
            Self::Denied => formatter.write_str("MCP invocation denied by preflight policy"),
            Self::Undecidable => {
                formatter.write_str("MCP invocation policy was undecidable; failing closed")
            }
            Self::Forwarding(error) => write!(formatter, "MCP stdio forwarding failed: {error}"),
        }
    }
}

impl Error for McpGatewayError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_name(field: &'static str, value: &str, max: usize) -> Result<(), McpGatewayError> {
    if value.is_empty() {
        return Err(McpGatewayError::EmptyName(field));
    }
    if value.trim() != value {
        return Err(McpGatewayError::PaddedName(field));
    }
    if value.len() > max {
        return Err(McpGatewayError::NameTooLarge {
            field,
            size: value.len(),
            max,
        });
    }
    Ok(())
}

fn scope_digest(server: &str, tool: &str, arguments: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sentrdel:mcp-invocation:v1\0");
    hasher.update(server.as_bytes());
    hasher.update(b"\0");
    hasher.update(tool.as_bytes());
    hasher.update(b"\0");
    hasher.update(arguments);
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Policy(Verdict);

    impl McpPreflightPolicy for Policy {
        fn evaluate(&self, _invocation: &McpInvocation) -> Verdict {
            self.0
        }
    }

    #[derive(Default)]
    struct Forwarder {
        calls: usize,
        result: Vec<u8>,
    }

    impl McpForwarder for Forwarder {
        fn forward(&mut self, _invocation: &McpInvocation) -> Result<Vec<u8>, String> {
            self.calls += 1;
            Ok(self.result.clone())
        }
    }

    fn invocation(tool: &str) -> McpInvocation {
        McpInvocation::normalize(
            "fixture-server",
            tool,
            serde_json::json!({"path":"src/lib.rs"}),
            McpGatewayLimits::default(),
        )
        .expect("invocation")
    }

    #[test]
    fn allow_forwards_once() {
        let request = invocation("read_file");
        let mut forwarder = Forwarder {
            result: br#"{"ok":true}"#.to_vec(),
            ..Forwarder::default()
        };
        let outcome = invoke_bounded(
            &request,
            &Policy(Verdict::Allow),
            None,
            &mut forwarder,
            McpGatewayLimits::default(),
        )
        .expect("allowed");
        assert_eq!(outcome.verdict, Verdict::Allow);
        assert_eq!(forwarder.calls, 1);
    }

    #[test]
    fn deny_and_undecidable_never_forward() {
        for verdict in [Verdict::Deny, Verdict::Undecidable] {
            let request = invocation("dangerous");
            let mut forwarder = Forwarder::default();
            assert!(
                invoke_bounded(
                    &request,
                    &Policy(verdict),
                    None,
                    &mut forwarder,
                    McpGatewayLimits::default(),
                )
                .is_err()
            );
            assert_eq!(forwarder.calls, 0);
        }
    }

    #[test]
    fn ask_requires_exact_one_shot_scope() {
        let request = invocation("write_file");
        let other = invocation("delete_file");
        let mut approval = ScopedApproval::for_invocation(&request);
        let mut forwarder = Forwarder::default();
        assert!(matches!(
            invoke_bounded(
                &other,
                &Policy(Verdict::Ask),
                Some(&mut approval),
                &mut forwarder,
                McpGatewayLimits::default(),
            ),
            Err(McpGatewayError::ApprovalScopeMismatch)
        ));
        assert!(!approval.is_consumed());
        invoke_bounded(
            &request,
            &Policy(Verdict::Ask),
            Some(&mut approval),
            &mut forwarder,
            McpGatewayLimits::default(),
        )
        .expect("approved");
        assert!(approval.is_consumed());
        assert!(matches!(
            invoke_bounded(
                &request,
                &Policy(Verdict::Ask),
                Some(&mut approval),
                &mut forwarder,
                McpGatewayLimits::default(),
            ),
            Err(McpGatewayError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(forwarder.calls, 1);
    }

    #[test]
    fn resource_caps_fail_closed() {
        let limits = McpGatewayLimits {
            max_argument_bytes: 8,
            max_result_bytes: 4,
            max_name_bytes: 64,
        };
        assert!(matches!(
            McpInvocation::normalize(
                "server",
                "tool",
                serde_json::json!({"large":"payload"}),
                limits
            ),
            Err(McpGatewayError::ArgumentsTooLarge { .. })
        ));

        let request = invocation("read");
        let mut forwarder = Forwarder {
            result: vec![0; 5],
            ..Forwarder::default()
        };
        assert!(matches!(
            invoke_bounded(
                &request,
                &Policy(Verdict::Allow),
                None,
                &mut forwarder,
                McpGatewayLimits {
                    max_result_bytes: 4,
                    ..McpGatewayLimits::default()
                },
            ),
            Err(McpGatewayError::ResultTooLarge { .. })
        ));
    }

    #[test]
    fn scope_digest_binds_server_tool_and_arguments() {
        let first = invocation("read_file");
        let second = McpInvocation::normalize(
            "fixture-server",
            "read_file",
            serde_json::json!({"path":"README.md"}),
            McpGatewayLimits::default(),
        )
        .expect("second");
        let third = McpInvocation::normalize(
            "other-server",
            "read_file",
            serde_json::json!({"path":"src/lib.rs"}),
            McpGatewayLimits::default(),
        )
        .expect("third");
        assert_ne!(first.scope_digest(), second.scope_digest());
        assert_ne!(first.scope_digest(), third.scope_digest());
    }
}
