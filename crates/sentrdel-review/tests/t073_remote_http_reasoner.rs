use sentrdel_review::reasoner::remote::{RemoteHttpConfig, RemoteHttpReasoner};
use sentrdel_review::reasoner::{Reasoner, ReasonerLimits, ReasonerRequest};
use sentrdel_schema::reasoner::ReasonerEpistemicClass;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

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
            .expect("write response");
    });
    (address, receiver, handle)
}

fn drafts_body() -> String {
    serde_json::json!([{
        "input_digests": [],
        "observation": "remote advisory output",
        "security_interpretation": "possible impact",
        "category": "reasoner.remote.fixture",
        "epistemic_class": "INFERENCE",
        "confidence_band": null,
        "subjects": [],
        "locations": [],
        "attributes": {},
        "captured_at": "2026-08-29T00:00:00Z"
    }])
    .to_string()
}

#[test]
fn disabled_and_header_injection_configs_fail_before_network() {
    let address: SocketAddr = "192.0.2.1:8080".parse().expect("address");
    let disabled = RemoteHttpConfig::disabled(address, "example.test", "/reason");
    assert!(
        RemoteHttpReasoner::new(disabled)
            .err()
            .expect("disabled must fail")
            .to_string()
            .contains("disabled")
    );

    assert!(
        RemoteHttpReasoner::new(RemoteHttpConfig::enabled(
            address,
            "example.test\r\nAuthorization: injected",
            "/reason",
        ))
        .err()
        .expect("header injection must fail")
        .to_string()
        .contains("Host header")
    );
}

#[test]
fn explicit_remote_adapter_sends_only_bounded_reasoner_contract() {
    let (address, captured, handle) = serve_once(drafts_body());
    let reasoner = RemoteHttpReasoner::new(
        RemoteHttpConfig::enabled(address, "reasoner.example", "/v1/reason")
            .with_timeouts(Duration::from_secs(2), Duration::from_secs(2)),
    )
    .expect("remote reasoner");
    let request = ReasonerRequest::new(
        "review selected evidence",
        Vec::new(),
        ReasonerLimits::default(),
    )
    .expect("bounded request");

    let drafts = reasoner.reason(&request).expect("remote reasoning");
    assert_eq!(reasoner.id(), "explicit-remote-http");
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].epistemic_class, ReasonerEpistemicClass::Inference);

    let wire = captured.recv().expect("captured request");
    handle.join().expect("fixture server");
    let body_start = find_bytes(&wire, b"\r\n\r\n").expect("header boundary") + 4;
    let header = std::str::from_utf8(&wire[..body_start]).expect("header UTF-8");
    assert!(header.starts_with("POST /v1/reason HTTP/1.1\r\n"));
    assert!(header.contains("Host: reasoner.example\r\n"));
    assert!(!header.to_ascii_lowercase().contains("authorization:"));

    let body: serde_json::Value =
        serde_json::from_slice(&wire[body_start..]).expect("request JSON");
    assert_eq!(body["schema"], "sentrdel-reasoner-v1");
    assert_eq!(body["instruction"], "review selected evidence");
    assert_eq!(body["evidence"], serde_json::json!([]));
    assert!(body.get("repository").is_none());
    assert!(body.get("files").is_none());
    assert!(body.get("workspace").is_none());
}

#[test]
fn remote_adapter_rejects_oversized_response() {
    let (address, _captured, handle) = serve_once(drafts_body());
    let reasoner = RemoteHttpReasoner::new(
        RemoteHttpConfig::enabled(address, "reasoner.example", "/reason")
            .with_timeouts(Duration::from_secs(2), Duration::from_secs(2))
            .with_max_response_bytes(8),
    )
    .expect("remote reasoner");
    let request = ReasonerRequest::new("review", Vec::new(), ReasonerLimits::default())
        .expect("bounded request");

    let error = reasoner
        .reason(&request)
        .expect_err("oversized response must fail");
    assert!(
        error.to_string().contains("exceeded configured bounds")
            || error.to_string().contains("exceeds cap")
    );
    handle.join().expect("fixture server");
}
