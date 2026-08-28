#![forbid(unsafe_code)]
//! Guard surfaces. R1 MCP enforcement is bounded stdio only.

pub mod mcp;
pub mod sentrdel_policy;

pub const R1_REMOTE_MCP_SUPPORTED: bool = false;
pub const R1_STDIO_MCP_PLANNED: bool = true;
