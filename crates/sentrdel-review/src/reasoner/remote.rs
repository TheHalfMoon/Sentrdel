//! Explicit generic remote HTTP reasoner transport.
//!
//! The endpoint is caller-selected configuration, not provider authority. This
//! adapter performs no DNS discovery, redirects, TLS negotiation, provider SDK
//! calls, credential discovery, or implicit whole-repository upload. Its request
//! body can contain only the already-bounded `ReasonerRequest` instruction and
//! selected Evidence records.

use super::{Reasoner, ReasonerError, ReasonerRequest};
use sentrdel_schema::reasoner::ReasonerEvidenceDraft;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const MAX_HOST_HEADER_BYTES: usize = 512;
const MAX_PATH_BYTES: usize = 2 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_HTTP_REQUEST_BODY_BYTES: usize = 512 * 1024;
const MAX_CONFIGURED_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct RemoteHttpConfig {
    enabled: bool,
    address: SocketAddr,
    host_header: String,
    path: String,
    connect_timeout: Duration,
    io_timeout: Duration,
    max_response_bytes: usize,
}

impl RemoteHttpConfig {
    #[must_use]
    pub fn enabled(
        address: SocketAddr,
        host_header: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            enabled: true,
            address,
            host_header: host_header.into(),
            path: path.into(),
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(20),
            max_response_bytes: 256 * 1024,
        }
    }

    #[must_use]
    pub fn disabled(
        address: SocketAddr,
        host_header: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        let mut config = Self::enabled(address, host_header, path);
        config.enabled = false;
        config
    }

    #[must_use]
    pub fn with_timeouts(mut self, connect_timeout: Duration, io_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self.io_timeout = io_timeout;
        self
    }

    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }
}

pub struct RemoteHttpReasoner {
    config: RemoteHttpConfig,
}

impl RemoteHttpReasoner {
    pub fn new(config: RemoteHttpConfig) -> Result<Self, ReasonerError> {
        validate_config(&config)?;
        Ok(Self { config })
    }

    fn request_body(&self, request: &ReasonerRequest) -> Result<Vec<u8>, ReasonerError> {
        let body = serde_json::to_vec(&serde_json::json!({
            "schema": "sentrdel-reasoner-v1",
            "instruction": &request.instruction,
            "evidence": &request.evidence,
        }))
        .map_err(|error| {
            ReasonerError::new(format!("remote reasoner request encoding failed: {error}"))
        })?;
        if body.len() > MAX_HTTP_REQUEST_BODY_BYTES {
            return Err(ReasonerError::new(format!(
                "remote reasoner HTTP request body size {} exceeds cap {MAX_HTTP_REQUEST_BODY_BYTES}",
                body.len()
            )));
        }
        Ok(body)
    }

    fn call_remote(
        &self,
        request: &ReasonerRequest,
    ) -> Result<Vec<ReasonerEvidenceDraft>, ReasonerError> {
        let body = self.request_body(request)?;
        let mut stream =
            TcpStream::connect_timeout(&self.config.address, self.config.connect_timeout).map_err(
                |error| ReasonerError::new(format!("remote reasoner connect failed: {error}")),
            )?;
        stream
            .set_read_timeout(Some(self.config.io_timeout))
            .map_err(|error| {
                ReasonerError::new(format!(
                    "remote reasoner read-timeout setup failed: {error}"
                ))
            })?;
        stream
            .set_write_timeout(Some(self.config.io_timeout))
            .map_err(|error| {
                ReasonerError::new(format!(
                    "remote reasoner write-timeout setup failed: {error}"
                ))
            })?;

        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.config.path,
            self.config.host_header,
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .and_then(|()| stream.flush())
            .map_err(|error| {
                ReasonerError::new(format!("remote reasoner request write failed: {error}"))
            })?;

        let max_wire_bytes = MAX_HTTP_HEADER_BYTES
            .checked_add(self.config.max_response_bytes)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| ReasonerError::new("remote reasoner response size overflow"))?;
        let mut wire = Vec::new();
        stream
            .take(u64::try_from(max_wire_bytes).unwrap_or(u64::MAX))
            .read_to_end(&mut wire)
            .map_err(|error| {
                ReasonerError::new(format!("remote reasoner response read failed: {error}"))
            })?;
        if wire.len() == max_wire_bytes {
            return Err(ReasonerError::new(
                "remote reasoner response exceeded configured bounds",
            ));
        }

        parse_response(&wire, self.config.max_response_bytes)
    }
}

impl Reasoner for RemoteHttpReasoner {
    fn id(&self) -> &str {
        "explicit-remote-http"
    }

    fn reason(
        &self,
        request: &ReasonerRequest,
    ) -> Result<Vec<ReasonerEvidenceDraft>, ReasonerError> {
        self.call_remote(request)
    }
}

fn validate_config(config: &RemoteHttpConfig) -> Result<(), ReasonerError> {
    if !config.enabled {
        return Err(ReasonerError::new(
            "remote reasoner is disabled by configuration",
        ));
    }
    if config.host_header.is_empty()
        || config.host_header.len() > MAX_HOST_HEADER_BYTES
        || !config.host_header.is_ascii()
        || config
            .host_header
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(ReasonerError::new(
            "remote reasoner Host header is invalid or oversized",
        ));
    }
    if !config.path.starts_with('/')
        || config.path.len() > MAX_PATH_BYTES
        || !config.path.is_ascii()
        || config
            .path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(ReasonerError::new(
            "remote reasoner path is invalid or oversized",
        ));
    }
    if config.connect_timeout.is_zero() || config.io_timeout.is_zero() {
        return Err(ReasonerError::new(
            "remote reasoner timeouts must be non-zero",
        ));
    }
    if config.max_response_bytes == 0 || config.max_response_bytes > MAX_CONFIGURED_RESPONSE_BYTES {
        return Err(ReasonerError::new(format!(
            "remote reasoner max response bytes must be within 1..={MAX_CONFIGURED_RESPONSE_BYTES}"
        )));
    }
    Ok(())
}

fn parse_response(
    wire: &[u8],
    max_response_bytes: usize,
) -> Result<Vec<ReasonerEvidenceDraft>, ReasonerError> {
    let header_end = find_bytes(wire, b"\r\n\r\n")
        .ok_or_else(|| ReasonerError::new("remote reasoner returned malformed HTTP headers"))?;
    if header_end > MAX_HTTP_HEADER_BYTES {
        return Err(ReasonerError::new(
            "remote reasoner HTTP headers exceeded cap",
        ));
    }
    let header = std::str::from_utf8(&wire[..header_end])
        .map_err(|_| ReasonerError::new("remote reasoner HTTP headers were not UTF-8"))?;
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| ReasonerError::new("remote reasoner HTTP status line missing"))?;
    let mut status_parts = status.split_whitespace();
    let protocol = status_parts.next().unwrap_or_default();
    if protocol != "HTTP/1.1" && protocol != "HTTP/1.0" {
        return Err(ReasonerError::new(
            "remote reasoner returned unsupported HTTP version",
        ));
    }
    let status_code = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| ReasonerError::new("remote reasoner returned malformed HTTP status"))?;
    if !(200..300).contains(&status_code) {
        return Err(ReasonerError::new(format!(
            "remote reasoner returned HTTP status {status_code}"
        )));
    }

    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(ReasonerError::new(
                "remote reasoner returned malformed HTTP header",
            ));
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
        {
            return Err(ReasonerError::new(
                "remote reasoner chunked/encoded HTTP responses are not supported in T073",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(ReasonerError::new(
                    "remote reasoner returned duplicate Content-Length",
                ));
            }
            content_length = Some(value.trim().parse::<usize>().map_err(|_| {
                ReasonerError::new("remote reasoner returned invalid Content-Length")
            })?);
        }
    }

    let content_length = content_length
        .ok_or_else(|| ReasonerError::new("remote reasoner response requires Content-Length"))?;
    if content_length > max_response_bytes {
        return Err(ReasonerError::new(format!(
            "remote reasoner response body size {content_length} exceeds cap {max_response_bytes}"
        )));
    }
    let body_start = header_end + 4;
    let body = wire
        .get(body_start..)
        .ok_or_else(|| ReasonerError::new("remote reasoner response body missing"))?;
    if body.len() != content_length {
        return Err(ReasonerError::new(format!(
            "remote reasoner response length mismatch: declared {content_length}, received {}",
            body.len()
        )));
    }

    serde_json::from_slice::<Vec<ReasonerEvidenceDraft>>(body)
        .map_err(|error| ReasonerError::new(format!("remote reasoner draft JSON invalid: {error}")))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
