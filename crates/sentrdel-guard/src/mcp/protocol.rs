//! Sentrdel-owned bounded stdio MCP framing and explicit protocol negotiation.
//!
//! The qualified RMCP SDK is a model/protocol reference only at this boundary.
//! Sentrdel deliberately owns hostile-input framing, buffering, and version
//! admission instead of inheriting SDK transport defaults or `LATEST` behavior.

use std::{error::Error, fmt, io::BufRead};

use serde_json::Value;

pub const QUALIFIED_RMCP_VERSION: &str = "3.1.4";
pub const QUALIFIED_RMCP_REF: &str = "4a738b9dd99eaca418b614afa433a0cbdaf8d056";

pub const DEFAULT_MAX_MCP_FRAME_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_MCP_BUFFER_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McpStdioLimits {
    pub max_frame_bytes: usize,
    pub max_buffer_bytes: usize,
}

impl Default for McpStdioLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_MCP_FRAME_BYTES,
            max_buffer_bytes: DEFAULT_MAX_MCP_BUFFER_BYTES,
        }
    }
}

impl McpStdioLimits {
    pub fn validate(self) -> Result<Self, McpProtocolError> {
        if self.max_frame_bytes == 0
            || self.max_buffer_bytes == 0
            || self.max_frame_bytes > self.max_buffer_bytes
        {
            return Err(McpProtocolError::InvalidLimits);
        }
        Ok(self)
    }
}

pub struct BoundedStdioReader<R> {
    reader: R,
    limits: McpStdioLimits,
}

impl<R: BufRead> BoundedStdioReader<R> {
    pub fn new(reader: R, limits: McpStdioLimits) -> Result<Self, McpProtocolError> {
        Ok(Self {
            reader,
            limits: limits.validate()?,
        })
    }

    pub fn read_frame(&mut self) -> Result<Option<Vec<u8>>, McpProtocolError> {
        let mut frame = Vec::new();

        loop {
            let available = self.reader.fill_buf().map_err(McpProtocolError::Io)?;
            if available.is_empty() {
                if frame.is_empty() {
                    return Ok(None);
                }
                return Err(McpProtocolError::UnterminatedFrame {
                    buffered: frame.len(),
                });
            }

            let newline = available.iter().position(|byte| *byte == b'\n');
            let take = newline.map_or(available.len(), |index| index + 1);
            let body_take = newline.map_or(take, |index| index);
            let projected = frame.len().checked_add(body_take).ok_or(
                McpProtocolError::BufferLimitExceeded {
                    max: self.limits.max_buffer_bytes,
                },
            )?;

            if projected > self.limits.max_buffer_bytes {
                return Err(McpProtocolError::BufferLimitExceeded {
                    max: self.limits.max_buffer_bytes,
                });
            }
            if projected > self.limits.max_frame_bytes {
                return Err(McpProtocolError::FrameTooLarge {
                    max: self.limits.max_frame_bytes,
                });
            }

            frame.extend_from_slice(&available[..body_take]);
            self.reader.consume(take);

            if newline.is_some() {
                if frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                if frame.is_empty() {
                    return Err(McpProtocolError::EmptyFrame);
                }
                return Ok(Some(frame));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum McpProtocolVersion {
    V2024_11_05,
    V2025_03_26,
    V2025_06_18,
    V2025_11_25,
    V2026_07_28,
}

impl McpProtocolVersion {
    pub const ALLOWLIST: &[Self] = &[
        Self::V2024_11_05,
        Self::V2025_03_26,
        Self::V2025_06_18,
        Self::V2025_11_25,
        Self::V2026_07_28,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2024_11_05 => "2024-11-05",
            Self::V2025_03_26 => "2025-03-26",
            Self::V2025_06_18 => "2025-06-18",
            Self::V2025_11_25 => "2025-11-25",
            Self::V2026_07_28 => "2026-07-28",
        }
    }

    pub fn parse_advertised(value: &str) -> Result<Self, McpProtocolError> {
        let version = match value {
            "2024-11-05" => Self::V2024_11_05,
            "2025-03-26" => Self::V2025_03_26,
            "2025-06-18" => Self::V2025_06_18,
            "2025-11-25" => Self::V2025_11_25,
            "2026-07-28" => Self::V2026_07_28,
            _ => {
                return Err(McpProtocolError::UnsupportedProtocolVersion(
                    value.to_owned(),
                ));
            }
        };
        debug_assert!(Self::ALLOWLIST.contains(&version));
        Ok(version)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitializeEnvelope {
    Request,
    Response,
}

pub fn initialize_protocol_version(
    frame: &[u8],
) -> Result<(InitializeEnvelope, McpProtocolVersion), McpProtocolError> {
    let value: Value = serde_json::from_slice(frame).map_err(McpProtocolError::InvalidJson)?;
    let object = value.as_object().ok_or(McpProtocolError::InvalidEnvelope)?;

    let request_version = object
        .get("params")
        .and_then(Value::as_object)
        .and_then(|params| params.get("protocolVersion"));
    let response_version = object
        .get("result")
        .and_then(Value::as_object)
        .and_then(|result| result.get("protocolVersion"));

    let (envelope, raw) = match (request_version, response_version) {
        (Some(_), Some(_)) => return Err(McpProtocolError::AmbiguousProtocolVersion),
        (Some(raw), None) => (InitializeEnvelope::Request, raw),
        (None, Some(raw)) => (InitializeEnvelope::Response, raw),
        (None, None) => return Err(McpProtocolError::MissingProtocolVersion),
    };
    let raw = raw
        .as_str()
        .ok_or(McpProtocolError::NonStringProtocolVersion)?;
    Ok((envelope, McpProtocolVersion::parse_advertised(raw)?))
}

#[derive(Debug)]
pub enum McpProtocolError {
    InvalidLimits,
    Io(std::io::Error),
    FrameTooLarge { max: usize },
    BufferLimitExceeded { max: usize },
    UnterminatedFrame { buffered: usize },
    EmptyFrame,
    InvalidJson(serde_json::Error),
    InvalidEnvelope,
    MissingProtocolVersion,
    AmbiguousProtocolVersion,
    NonStringProtocolVersion,
    UnsupportedProtocolVersion(String),
}

impl fmt::Display for McpProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str(
                "MCP stdio limits must be non-zero and max frame must not exceed max buffer",
            ),
            Self::Io(error) => write!(formatter, "MCP stdio read failed: {error}"),
            Self::FrameTooLarge { max } => {
                write!(formatter, "MCP stdio frame exceeds {max} byte limit")
            }
            Self::BufferLimitExceeded { max } => {
                write!(
                    formatter,
                    "MCP stdio buffered bytes exceed {max} byte limit"
                )
            }
            Self::UnterminatedFrame { buffered } => write!(
                formatter,
                "MCP stdio stream ended with an unterminated {buffered}-byte frame"
            ),
            Self::EmptyFrame => formatter.write_str("MCP stdio frame must not be empty"),
            Self::InvalidJson(error) => write!(formatter, "invalid MCP JSON frame: {error}"),
            Self::InvalidEnvelope => formatter.write_str("MCP frame must be a JSON object"),
            Self::MissingProtocolVersion => {
                formatter.write_str("MCP initialize envelope is missing protocolVersion")
            }
            Self::AmbiguousProtocolVersion => formatter.write_str(
                "MCP initialize envelope contains both request and response protocolVersion fields",
            ),
            Self::NonStringProtocolVersion => {
                formatter.write_str("MCP protocolVersion must be a string")
            }
            Self::UnsupportedProtocolVersion(version) => {
                write!(formatter, "unsupported MCP protocol version: {version}")
            }
        }
    }
}

impl Error for McpProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidJson(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use super::*;

    fn reader(
        bytes: &[u8],
        max_frame_bytes: usize,
    ) -> BoundedStdioReader<BufReader<Cursor<Vec<u8>>>> {
        BoundedStdioReader::new(
            BufReader::with_capacity(3, Cursor::new(bytes.to_vec())),
            McpStdioLimits {
                max_frame_bytes,
                max_buffer_bytes: max_frame_bytes.saturating_add(8),
            },
        )
        .expect("reader")
    }

    #[test]
    fn bounded_reader_accepts_lf_and_crlf_without_delimiters() {
        let mut input = reader(b"{\"a\":1}\n{\"b\":2}\r\n", 64);
        assert_eq!(input.read_frame().unwrap(), Some(br#"{"a":1}"#.to_vec()));
        assert_eq!(input.read_frame().unwrap(), Some(br#"{"b":2}"#.to_vec()));
        assert_eq!(input.read_frame().unwrap(), None);
    }

    #[test]
    fn oversized_and_unterminated_frames_fail_closed() {
        let mut oversized = reader(b"123456789\n", 8);
        assert!(matches!(
            oversized.read_frame(),
            Err(McpProtocolError::FrameTooLarge { max: 8 })
        ));

        let mut unterminated = reader(b"{\"jsonrpc\":\"2.0\"}", 64);
        assert!(matches!(
            unterminated.read_frame(),
            Err(McpProtocolError::UnterminatedFrame { .. })
        ));
    }

    #[test]
    fn initialize_versions_are_explicitly_allowlisted() {
        for version in McpProtocolVersion::ALLOWLIST {
            let frame = format!(
                r#"{{"jsonrpc":"2.0","id":1,"params":{{"protocolVersion":"{}"}}}}"#,
                version.as_str()
            );
            assert_eq!(
                initialize_protocol_version(frame.as_bytes()).unwrap(),
                (InitializeEnvelope::Request, *version)
            );
        }

        let future = br#"{"jsonrpc":"2.0","id":1,"params":{"protocolVersion":"2099-01-01"}}"#;
        assert!(matches!(
            initialize_protocol_version(future),
            Err(McpProtocolError::UnsupportedProtocolVersion(version)) if version == "2099-01-01"
        ));
    }

    #[test]
    fn response_negotiation_is_parsed_without_default_or_latest_semantics() {
        let response = br#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2026-07-28"}}"#;
        assert_eq!(
            initialize_protocol_version(response).unwrap(),
            (
                InitializeEnvelope::Response,
                McpProtocolVersion::V2026_07_28
            )
        );

        let symbolic_latest = br#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"LATEST"}}"#;
        assert!(matches!(
            initialize_protocol_version(symbolic_latest),
            Err(McpProtocolError::UnsupportedProtocolVersion(version)) if version == "LATEST"
        ));
    }

    #[test]
    fn malformed_or_ambiguous_negotiation_fails_closed() {
        assert!(matches!(
            initialize_protocol_version(b"[]"),
            Err(McpProtocolError::InvalidEnvelope)
        ));
        assert!(matches!(
            initialize_protocol_version(br#"{"jsonrpc":"2.0"}"#),
            Err(McpProtocolError::MissingProtocolVersion)
        ));
        assert!(matches!(
            initialize_protocol_version(br#"{"params":{"protocolVersion":7}}"#),
            Err(McpProtocolError::NonStringProtocolVersion)
        ));
        assert!(matches!(
            initialize_protocol_version(
                br#"{"params":{"protocolVersion":"2025-11-25"},"result":{"protocolVersion":"2025-11-25"}}"#
            ),
            Err(McpProtocolError::AmbiguousProtocolVersion)
        ));
    }

    #[test]
    fn qualified_sdk_pin_is_not_a_transport_authority() {
        assert_eq!(QUALIFIED_RMCP_VERSION, "3.1.4");
        assert_eq!(
            QUALIFIED_RMCP_REF,
            "4a738b9dd99eaca418b614afa433a0cbdaf8d056"
        );
    }
}
