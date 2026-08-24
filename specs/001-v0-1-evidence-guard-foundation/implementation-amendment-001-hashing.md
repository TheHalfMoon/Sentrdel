# Implementation Amendment 001 — R1 Canonical Hashing

**Date:** 2026-08-24  
**Status:** BINDING_FOR_R1  
**Scope:** Canonical Evidence/ASEL/content identifiers only

## Decision

R1 uses domain-separated **SHA-256** canonical identifiers in the machine form:

```text
sha256:<lowercase-hex>
```

This amendment supersedes any earlier R1 planning/task/data-model/quickstart/readiness reference that names BLAKE3 as the canonical content-addressing algorithm. It does not change the Evidence, Finding, Coverage, ASEL, graph, or policy product semantics.

## Reason

Implementation-time dependency qualification reviewed the 2026-08-20 crates.io supply-chain incident involving malicious `arrayref@0.3.10`. BLAKE3 1.8.7 removed the `arrayref` dependency and is **not** classified here as compromised. However, BLAKE3 1.8.7 still carries a substantial `build.rs`, a `cc` build dependency, compiler probing, and architecture-specific assembly/C build paths.

R1 needs stable collision-resistant identifiers but does not need BLAKE3-specific throughput enough to justify that additional build-time authority. RustCrypto `sha2 0.11.0` provides a smaller pure-Rust/no-package-build-script boundary for this use.

## Canonical profile

R1 canonical hashing covers deterministic, redacted canonical JSON bytes using explicit domain separation:

```text
"sentrdel:v1\0" || namespace || "\0" || canonical_json
```

Floating-point JSON numbers are rejected by the R1 canonical profile. Object keys are lexically deterministic and array ordering remains semantic.

## Migration rule

Changing the canonical hashing algorithm after R1 requires an explicit schema/storage migration or versioned identifier namespace. No implementation may silently reinterpret an existing `sha256:` identifier under another algorithm.

## Security note

Secret handling rules remain stricter than generic content IDs: Sentrdel must not persist a stable unkeyed digest computed solely from a discovered secret value.
