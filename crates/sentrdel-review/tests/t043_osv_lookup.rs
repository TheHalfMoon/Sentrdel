use sentrdel_review::dependency::{Ecosystem, PackageVersion};
use sentrdel_review::osv::{
    MAX_OSV_RESPONSE_BYTES, NetworkPolicy, OsvCache, OsvError, OsvLookupStatus, OsvTransport,
    OsvTransportError, build_query_request, lookup_package,
};
use serde_json::Value;
use std::collections::VecDeque;

fn cargo_package() -> PackageVersion {
    PackageVersion {
        ecosystem: Ecosystem::Cargo,
        name: "fixture-crate".to_owned(),
        version: "1.2.3".to_owned(),
    }
}

fn npm_package() -> PackageVersion {
    PackageVersion {
        ecosystem: Ecosystem::Npm,
        name: "@scope/fixture".to_owned(),
        version: "4.5.6".to_owned(),
    }
}

#[derive(Default)]
struct ScriptedTransport {
    responses: VecDeque<Result<Vec<u8>, OsvTransportError>>,
    requests: Vec<Vec<u8>>,
}

impl ScriptedTransport {
    fn with_responses(responses: Vec<Result<&'static [u8], OsvTransportError>>) -> Self {
        Self {
            responses: responses
                .into_iter()
                .map(|result| result.map(<[u8]>::to_vec))
                .collect(),
            requests: Vec::new(),
        }
    }
}

impl OsvTransport for ScriptedTransport {
    fn query(&mut self, request: &[u8]) -> Result<Vec<u8>, OsvTransportError> {
        self.requests.push(request.to_vec());
        self.responses
            .pop_front()
            .unwrap_or(Err(OsvTransportError::Rejected))
    }
}

#[test]
fn request_uses_osv_ecosystem_names_and_exact_versions() {
    let cargo: Value = serde_json::from_slice(&build_query_request(&cargo_package(), None).unwrap())
        .unwrap();
    assert_eq!(cargo["package"]["ecosystem"], "crates.io");
    assert_eq!(cargo["package"]["name"], "fixture-crate");
    assert_eq!(cargo["version"], "1.2.3");

    let npm: Value = serde_json::from_slice(
        &build_query_request(&npm_package(), Some("next-page")).unwrap(),
    )
    .unwrap();
    assert_eq!(npm["package"]["ecosystem"], "npm");
    assert_eq!(npm["package"]["name"], "@scope/fixture");
    assert_eq!(npm["page_token"], "next-page");
}

#[test]
fn no_network_never_invokes_transport_and_uses_fresh_cache() {
    let bytes = br#"{
      "schema_version":"1",
      "entries":[{
        "ecosystem":"cargo",
        "name":"fixture-crate",
        "version":"1.2.3",
        "fetched_at_epoch_seconds":100,
        "advisories":[{"id":"OSV-TEST-1","summary":"fixture advisory"}]
      }]
    }"#;
    let mut cache = OsvCache::from_bytes(bytes).unwrap();
    let mut transport = ScriptedTransport::default();

    let outcome = lookup_package(
        &cargo_package(),
        NetworkPolicy::NoNetwork,
        105,
        10,
        &mut cache,
        &mut transport,
    )
    .unwrap();

    assert_eq!(outcome.status, OsvLookupStatus::FreshCache);
    assert!(outcome.status.is_complete());
    assert_eq!(outcome.matches[0].advisory_id, "OSV-TEST-1");
    assert!(transport.requests.is_empty());
}

#[test]
fn no_network_reports_stale_or_missing_cache_without_transport() {
    let bytes = br#"{
      "schema_version":"1",
      "entries":[{
        "ecosystem":"cargo",
        "name":"fixture-crate",
        "version":"1.2.3",
        "fetched_at_epoch_seconds":100,
        "advisories":[{"id":"OSV-STALE","summary":"stale fixture"}]
      }]
    }"#;
    let mut stale_cache = OsvCache::from_bytes(bytes).unwrap();
    let mut transport = ScriptedTransport::default();
    let stale = lookup_package(
        &cargo_package(),
        NetworkPolicy::NoNetwork,
        200,
        10,
        &mut stale_cache,
        &mut transport,
    )
    .unwrap();
    assert_eq!(stale.status, OsvLookupStatus::StaleCache);
    assert!(!stale.status.is_complete());
    assert_eq!(stale.matches[0].advisory_id, "OSV-STALE");

    let mut empty_cache = OsvCache::new();
    let missing = lookup_package(
        &cargo_package(),
        NetworkPolicy::NoNetwork,
        200,
        10,
        &mut empty_cache,
        &mut transport,
    )
    .unwrap();
    assert_eq!(missing.status, OsvLookupStatus::SkippedByPolicy);
    assert!(!missing.status.is_complete());
    assert!(missing.matches.is_empty());
    assert!(transport.requests.is_empty());
}

#[test]
fn network_lookup_follows_bounded_pagination_deduplicates_and_populates_cache() {
    let mut transport = ScriptedTransport::with_responses(vec![
        Ok(br#"{"vulns":[{"id":"OSV-2","summary":"second"}],"next_page_token":"page-2"}"#),
        Ok(br#"{"vulns":[{"id":"OSV-1","summary":"first"},{"id":"OSV-2","summary":"duplicate"}]}"#),
    ]);
    let mut cache = OsvCache::new();

    let outcome = lookup_package(
        &cargo_package(),
        NetworkPolicy::AllowNetwork,
        1_000,
        300,
        &mut cache,
        &mut transport,
    )
    .unwrap();
    assert_eq!(outcome.status, OsvLookupStatus::Network);
    assert!(outcome.status.is_complete());
    let ids: Vec<_> = outcome
        .matches
        .iter()
        .map(|matched| matched.advisory_id.as_str())
        .collect();
    assert_eq!(ids, vec!["OSV-1", "OSV-2"]);
    assert_eq!(transport.requests.len(), 2);
    let second_request: Value = serde_json::from_slice(&transport.requests[1]).unwrap();
    assert_eq!(second_request["page_token"], "page-2");

    let mut must_not_run = ScriptedTransport::default();
    let cached = lookup_package(
        &cargo_package(),
        NetworkPolicy::AllowNetwork,
        1_100,
        300,
        &mut cache,
        &mut must_not_run,
    )
    .unwrap();
    assert_eq!(cached.status, OsvLookupStatus::FreshCache);
    assert!(must_not_run.requests.is_empty());
}

#[test]
fn network_unavailable_is_visible_and_stale_cache_is_not_marked_complete() {
    let mut empty_cache = OsvCache::new();
    let mut unavailable = ScriptedTransport::with_responses(vec![Err(OsvTransportError::Unavailable)]);
    let missing = lookup_package(
        &cargo_package(),
        NetworkPolicy::AllowNetwork,
        1_000,
        10,
        &mut empty_cache,
        &mut unavailable,
    )
    .unwrap();
    assert_eq!(missing.status, OsvLookupStatus::NetworkUnavailable);
    assert!(!missing.status.is_complete());
    assert!(missing.matches.is_empty());

    let bytes = br#"{
      "schema_version":"1",
      "entries":[{
        "ecosystem":"cargo",
        "name":"fixture-crate",
        "version":"1.2.3",
        "fetched_at_epoch_seconds":1,
        "advisories":[{"id":"OSV-STALE","summary":"stale fixture"}]
      }]
    }"#;
    let mut stale_cache = OsvCache::from_bytes(bytes).unwrap();
    let mut unavailable = ScriptedTransport::with_responses(vec![Err(OsvTransportError::TimedOut)]);
    let stale = lookup_package(
        &cargo_package(),
        NetworkPolicy::AllowNetwork,
        1_000,
        10,
        &mut stale_cache,
        &mut unavailable,
    )
    .unwrap();
    assert_eq!(stale.status, OsvLookupStatus::StaleCache);
    assert!(!stale.status.is_complete());
    assert_eq!(stale.matches[0].advisory_id, "OSV-STALE");
}

#[test]
fn malformed_oversized_and_repeated_pagination_fail_closed() {
    let mut malformed = ScriptedTransport::with_responses(vec![Ok(br#"{"vulns":"wrong"}"#)]);
    let mut cache = OsvCache::new();
    assert!(matches!(
        lookup_package(
            &cargo_package(),
            NetworkPolicy::AllowNetwork,
            10,
            10,
            &mut cache,
            &mut malformed,
        ),
        Err(OsvError::InvalidResponse(_))
    ));

    let oversized = vec![b'x'; MAX_OSV_RESPONSE_BYTES + 1];
    let mut oversized_transport = ScriptedTransport {
        responses: VecDeque::from([Ok(oversized)]),
        requests: Vec::new(),
    };
    assert!(matches!(
        lookup_package(
            &cargo_package(),
            NetworkPolicy::AllowNetwork,
            10,
            10,
            &mut cache,
            &mut oversized_transport,
        ),
        Err(OsvError::InputTooLarge { .. })
    ));

    let page = Ok(br#"{"vulns":[],"next_page_token":"same"}"# as &'static [u8]);
    let mut repeated = ScriptedTransport::with_responses(vec![page.clone(), page]);
    assert!(matches!(
        lookup_package(
            &cargo_package(),
            NetworkPolicy::AllowNetwork,
            10,
            10,
            &mut cache,
            &mut repeated,
        ),
        Err(OsvError::RepeatedPageToken)
    ));
}

#[test]
fn cache_round_trip_is_deterministic_and_rejects_unknown_fields() {
    let source = br#"{
      "schema_version":"1",
      "entries":[{
        "ecosystem":"npm",
        "name":"@scope/fixture",
        "version":"4.5.6",
        "fetched_at_epoch_seconds":77,
        "advisories":[
          {"id":"OSV-B","summary":"b"},
          {"id":"OSV-A","summary":"a"}
        ]
      }]
    }"#;
    let cache = OsvCache::from_bytes(source).unwrap();
    let encoded = cache.to_bytes().unwrap();
    assert_eq!(cache, OsvCache::from_bytes(&encoded).unwrap());
    assert_eq!(encoded, OsvCache::from_bytes(&encoded).unwrap().to_bytes().unwrap());

    assert!(matches!(
        OsvCache::from_bytes(br#"{"schema_version":"1","entries":[],"extra":true}"#),
        Err(OsvError::InvalidCache(_))
    ));
}
