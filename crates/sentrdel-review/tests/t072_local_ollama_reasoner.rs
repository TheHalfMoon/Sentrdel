use sentrdel_review::reasoner::local::{LocalOllamaConfig, LocalOllamaReasoner};
use sentrdel_review::reasoner::{Reasoner, ReasonerLimits, ReasonerRequest};
use sentrdel_schema::reasoner::ReasonerEpistemicClass;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn serve_once(body: String) -> (SocketAddr, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture server");
    let address = listener.local_addr().expect("fixture address");
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fixture request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set fixture timeout");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let body_start = loop {
            let read = stream.read(&mut buffer).expect("read fixture request");
            assert!(read > 0, "fixture request ended before headers");
            request.extend_from_slice(&buffer[..read]);
            if let Some(index) = find_bytes(&request, b"\r\n\r\n") {
                break index + 4;
            }
            assert!(request.len() < 64 * 1024, "fixture headers exceeded cap");
        };
        let header = std::str::from_utf8(&request[..body_start]).expect("fixture headers UTF-8");
        let content_length = header
            .split("\r\n")
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            })
            .expect("content length present");
        while request.len() < body_start + content_length {
            let read = stream.read(&mut buffer).expect("read fixture request body");
            assert!(read > 0, "fixture request body truncated");
            request.extend_from_slice(&buffer[..read]);
        }
        sender.send(request).expect("capture request");

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write fixture response");
    });
    (address, receiver, handle)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn ollama_body() -> String {
    let drafts = serde_json::json!([{
        "input_digests": [],
        "observation": "model-generated advisory context",
        "security_interpretation": "possible security impact",
        "category": "reasoner.local.fixture",
        "epistemic_class": "HYPOTHESIS",
        "confidence_band": null,
        "subjects": [],
        "locations": [],
        "attributes": {},
        "captured_at": "2026-08-29T00:00:00Z"
    }]);
    serde_json::json!({ "response": drafts.to_string() }).to_string()
}

#[test]
fn config_gate_and_loopback_boundary_fail_before_network() {
    let loopback: SocketAddr = "127.0.0.1:11434".parse().expect("loopback address");
    let disabled = LocalOllamaConfig::disabled(loopback, "fixture-model");
    let error = LocalOllamaReasoner::new(disabled)
        .err()
        .expect("disabled config must fail");
    assert!(error.to_string().contains("disabled by configuration"));

    let remote: SocketAddr = "192.0.2.1:11434".parse().expect("remote address");
    let error = LocalOllamaReasoner::new(LocalOllamaConfig::enabled(remote, "fixture-model"))
        .err()
        .expect("remote endpoint must fail");
    assert!(error.to_string().contains("loopback"));
}

#[test]
fn local_adapter_uses_bounded_ollama_generate_contract() {
    let (address, captured, handle) = serve_once(ollama_body());
    let reasoner = LocalOllamaReasoner::new(
        LocalOllamaConfig::enabled(address, "fixture-model")
            .with_timeouts(Duration::from_secs(2), Duration::from_secs(2)),
    )
    .expect("local reasoner");
    let request = ReasonerRequest::new(
        "analyze selected evidence",
        Vec::new(),
        ReasonerLimits::default(),
    )
    .expect("bounded request");

    let drafts = reasoner.reason(&request).expect("local reasoning");
    assert_eq!(reasoner.id(), "local-ollama-http");
    assert_eq!(drafts.len(), 1);
    assert_eq!(
        drafts[0].epistemic_class,
        ReasonerEpistemicClass::Hypothesis
    );

    let wire = captured.recv().expect("captured request");
    handle.join().expect("fixture server");
    let body_start = find_bytes(&wire, b"\r\n\r\n").expect("request header boundary") + 4;
    let header = std::str::from_utf8(&wire[..body_start]).expect("request header UTF-8");
    assert!(header.starts_with("POST /api/generate HTTP/1.1\r\n"));
    assert!(!header.to_ascii_lowercase().contains("authorization:"));

    let body: serde_json::Value =
        serde_json::from_slice(&wire[body_start..]).expect("request JSON");
    assert_eq!(body["model"], "fixture-model");
    assert_eq!(body["stream"], false);
    assert_eq!(body["format"], "json");
    let prompt: serde_json::Value =
        serde_json::from_str(body["prompt"].as_str().expect("prompt string")).expect("prompt JSON");
    assert_eq!(prompt["instruction"], "analyze selected evidence");
    assert_eq!(prompt["evidence"], serde_json::json!([]));
}

#[test]
fn local_adapter_rejects_response_larger_than_configured_cap() {
    let (address, _captured, handle) = serve_once(ollama_body());
    let reasoner = LocalOllamaReasoner::new(
        LocalOllamaConfig::enabled(address, "fixture-model")
            .with_timeouts(Duration::from_secs(2), Duration::from_secs(2))
            .with_max_response_bytes(8),
    )
    .expect("local reasoner");
    let request = ReasonerRequest::new("review", Vec::new(), ReasonerLimits::default())
        .expect("bounded request");

    let error = reasoner
        .reason(&request)
        .err()
        .expect("oversized response must fail");
    assert!(
        error.to_string().contains("exceeded configured bounds")
            || error.to_string().contains("exceeds cap")
    );
    handle.join().expect("fixture server");
}
