# Engine Adapter Dependency Qualification

**Scope:** R1 `sentrdel-engine` strict external-result adaptation only.  
**Date:** 2026-08-26  
**Policy:** `docs/security/dependency-policy.md`  
**Related substrate qualification:** `docs/third-party/schema-dependency-qualification.md`

## Decision

T028 adds direct `sentrdel-engine` use of the already exact-pinned `serde 1.0.229` and `serde_json 1.0.151` packages. No new package, version, checksum, native library, downloaded artifact, or network-at-build behavior is introduced into `Cargo.lock`; the lockfile delta adds only these two existing dependency edges to `sentrdel-engine`.

| Dependency | Exact version | Engine-adapter purpose | Privileged build surface | Decision |
|---|---:|---|---|---|
| serde | 1.0.229 | Strict typed decoding of the bounded Sentrdel-native JSON and SARIF envelopes after allocation-bounded structural preflight | package build script; the workspace enables the `serde_derive` procedural macro through the existing `derive` feature | ADOPT EXISTING PIN / ELEVATED MANUAL REVIEW |
| serde_json | 1.0.151 | JSON decoding for the two explicit T028 output dialects and bounded canonical attribute values after preflight | package build script | ADOPT EXISTING PIN / ELEVATED MANUAL REVIEW |

## Security boundary

These dependencies do not receive process, filesystem, network, credential, Finding, CoverageRecord, or policy authority. T027 still owns the sole external process runner. T028 first applies a Sentrdel-owned non-materializing structural preflight with byte, depth, node, collection, and attribute-subtree limits; only preflight-approved bytes reach serde deserialization. Producer identity and trusted provenance remain runtime-owned and are not decoded from engine output.

The existing schema-substrate qualification remains scoped to `sentrdel-schema`; this record is the explicit rationale and elevated-review callout for the new direct `sentrdel-engine` use. Exact package checksums in `Cargo.lock` remain canonical, and CI must continue using `--locked`.

## Review disposition

Because both packages execute build-time code and `serde` participates in a procedural-macro path, this T028 dependency-edge change requires elevated/manual review despite introducing no new resolved package. Exact pinning is necessary but is not treated as a substitute for that review.
