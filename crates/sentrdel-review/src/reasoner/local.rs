//! Explicit local-only Ollama-compatible HTTP reasoner transport.
//!
//! This adapter is configuration-gated and accepts only loopback socket
//! addresses. It never performs DNS resolution, TLS, redirects, provider SDK
//! calls, credential discovery, or remote endpoint selection.

use super::{Reasoner, ReasonerError, ReasonerRequest};
use sentrdel_schema::reasoner::ReasonerEvidenceDraft;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const MAX_MODEL_BYTES: usize = 256;
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_HTTP_REQUEST_BODY_BYTES: usize = 512 * 1024;
const MAX_CONFIGURED_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct LocalOllamaConfig {
    enabled: bool,
    address: SocketAddr,
    model: String,
    connect_timeout: Duration,
    io_timeout: Duration,
    max_response_bytes: usize,
}

impl LocalOllamaConfig {
    #[must_use]
    pub fn enabled(address: SocketAddr, model: impl Into<String>) -> Self {
        Self {
            enabled: true,
            address,
            model: model.into(),
            connect_timeout: Duration::from_secs(2),
            io_timeout: Duration::from_secs(15),
            max_response_bytes: 256 * 1024,
        }
    }

    #[must_use]
    pub fn disabled(address: SocketAddr, model: impl Into<String>) -> Self {
        let mut config = Self::enabled(address, model);
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

pub struct LocalOllamaReasoner {
    config: LocalOllamaConfig,
}

impl LocalOllamaReasoner {
    pub fn new(config: LocalOllamaConfig) -> Result<Self, ReasonerError> {
        validate_config(&config)?;
        Ok(Self { config })
    }

    fn request_body(&self, request: &ReasonerRequest) -> Result<Vec<u8>, ReasonerError> {
        let prompt = serde_json::json!({
            "instruction": &request.instruction,
            "evidence": &request.evidence,
        });
        let body = serde_json::to_vec(&serde_json::json!({
            "model": &self.config.model,
            "prompt": prompt.to_string(),
            "stream": false,
            "format": "json",
        }))
        .map_err(|error| ReasonerError::new(format!("local reasoner request encoding failed: {error}")))?;
        if body.len() > MAX_HTTP_REQUEST_BODY_BYTES {
            return Err(ReasonerError::new(format!(
                "local reasoner HTTP request body size {} exceeds cap {MAX_HTTP_REQUEST_BODY_BYTES}",
                body.len()
            )));
        }
        Ok(body)
    }

    fn call_ollama(&self, request: &ReasonerRequest) -> Result<Vec<ReasonerEvidenceDraft>, ReasonerError> {
        let body = self.request_body(request)?;
        let mut stream = TcpStream::connect_timeout(&self.config.address, self.config.connect_timeout)
            .map_err(|error| ReasonerError::new(format!("local reasoner connect failed: {error}")))?;
        stream
            .set_read_timeout(Some(self.config.io_timeout))
            .map_err(|error| ReasonerError::new(format!("local reasoner read-timeout setup failed: {error}")))?;
        stream
            .set_write_timeout(Some(self.config.io_timeout))
            .map_err(|error| ReasonerError::new(format!("local reasoner write-timeout setup failed: {error}")))?;

        let head = format!(
            "POST /api/generate HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.config.address,
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .and_then(|()| stream.flush())
            .map_err(|error| ReasonerError::new(format!("local reasoner request write failed: {error}")))?;

        let max_wire_bytes = MAX_HTTP_HEADER_BYTES
            .checked_add(self.config.max_response_bytes)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| ReasonerError::new("local reasoner response size overflow"))?;
        let mut wire = Vec::new();
        stream
            .take(u64::try_from(max_wire_bytes).unwrap_or(u64::MAX))
            .read_to_end(&mut wire)
            .map_err(|error| ReasonerError::new(format!("local reasoner response read failed: {error}")))?;
        if wire.len() == max_wire_bytes {
            return Err(ReasonerError::new("local reasoner response exceeded configured bounds"));
        }

        parse_ollama_response(&wire, self.config.max_response_bytes)
    }
}

impl Reasoner for LocalOllamaReasoner {
    fn id(&self) -> &str {
        "local-ollama-http"
    }

    fn reason(
        &self,
        request: &ReasonerRequest,
    ) -> Result<Vec<ReasonerEvidenceDraft>, ReasonerError> {
        self.call_ollama(request)
    }
}

fn validate_config(config: &LocalOllamaConfig) -> Result<(), ReasonerError> {
    if !config.enabled {
        return Err(ReasonerError::new("local reasoner is disabled by configuration"));
    }
    if !config.address.ip().is_loopback() {
        return Err(ReasonerError::new(
            "T072 local reasoner endpoint must be a loopback address",
        ));
    }
    if config.model.trim().is_empty() {
        return Err(ReasonerError::new("local reasoner model must not be empty"));
    }
    if config.model.len() > MAX_MODEL_BYTES {
        return Err(ReasonerError::new(format!(
            "local reasoner model length {} exceeds cap {MAX_MODEL_BYTES}",
            config.model.len()
        )));
    }
    if config.connect_timeout.is_zero() || config.io_timeout.is_zero() {
        return Err(ReasonerError::new("local reasoner timeouts must be non-zero"));
    }
    if config.max_response_bytes == 0 || config.max_response_bytes > MAX_CONFIGURED_RESPONSE_BYTES {
        return Err(ReasonerError::new(format!(
            "local reasoner max response bytes must be within 1..={MAX_CONFIGURED_RESPONSE_BYTES}"
        )));
    }
    Ok(())
}

fn parse_ollama_response(
    wire: &[u8],
    max_response_bytes: usize,
) -> Result<Vec<ReasonerEvidenceDraft>, ReasonerError> {
    let header_end = find_bytes(wire, b"\r\n\r\n")
        .ok_or_else(|| ReasonerError::new("local reasoner returned malformed HTTP headers"))?;
    if header_end > MAX_HTTP_HEADER_BYTES {
        return Err(ReasonerError::new("local reasoner HTTP headers exceeded cap"));
    }

    let header = std::str::from_utf8(&wire[..header_end])
        .map_err(|_| ReasonerError::new("local reasoner HTTP headers were not UTF-8"))?;
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| ReasonerError::new("local reasoner HTTP status line missing"))?;
    let mut status_parts = status.split_whitespace();
    let protocol = status_parts.next().unwrap_or_default();
    if protocol != "HTTP/1.1" && protocol != "HTTP/1.0" {
        return Err(ReasonerError::new("local reasoner returned unsupported HTTP version"));
    }
    let status_code = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| ReasonerError::new("local reasoner returned malformed HTTP status"))?;
    if !(200..300).contains(&status_code) {
        return Err(ReasonerError::new(format!(
            "local reasoner returned HTTP status {status_code}"
        )));
    }

    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(ReasonerError::new("local reasoner returned malformed HTTP header"));
        };
        if name.eq_ignore_ascii_case("transfer-encoding") && !value.trim().eq_ignore_ascii_case("identity") {
            return Err(ReasonerError::new(
                "local reasoner chunked/encoded HTTP responses are not supported in T072",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(ReasonerError::new("local reasoner returned duplicate Content-Length"));
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| ReasonerError::new("local reasoner returned invalid Content-Length"))?,
            );
        }
    }

    let content_length = content_length
        .ok_or_else(|| ReasonerError::new("local reasoner response requires Content-Length"))?;
    if content_length > max_response_bytes {
        return Err(ReasonerError::new(format!(
            "local reasoner response body size {content_length} exceeds cap {max_response_bytes}"
        )));
    }
    let body_start = header_end + 4;
    let body = wire
        .get(body_start..)
        .ok_or_else(|| ReasonerError::new("local reasoner response body missing"))?;
    if body.len() != content_length {
        return Err(ReasonerError::new(format!(
            "local reasoner response length mismatch: declared {content_length}, received {}",
            body.len()
        )));
    }

    let outer: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| ReasonerError::new(format!("local reasoner response JSON invalid: {error}")))?;
    let response = outer
        .get("response")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ReasonerError::new("local reasoner Ollama response field missing"))?;
    serde_json::from_str::<Vec<ReasonerEvidenceDraft>>(response)
        .map_err(|error| ReasonerError::new(format!("local reasoner draft JSON invalid: {error}")))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}
