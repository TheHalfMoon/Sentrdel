//! Trusted boundaries for the R1 bounded stdio MCP guard.

pub mod environment;
#[path = "gateway_impl.rs"]
pub mod gateway;
pub mod inventory;
pub mod protocol;
