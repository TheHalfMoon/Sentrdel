# rusqlite / libsqlite3-sys Dependency Qualification — T016

**Qualification ID:** DQ-RUSQLITE-001  
**Date:** 2026-08-24  
**Decision:** `ADOPT_PRIVILEGED_NATIVE_DEPENDENCY`  
**Scope:** R1 T016 SQLite connection, migrations, and WAL only

## Qualified published packages

- Registry/source: crates.io, locked by exact package version + registry checksum in committed `Cargo.lock`
- Repository metadata: `rusqlite/rusqlite`
- `rusqlite`: **0.40.2**, published 2026-08-08, MIT
- `rusqlite 0.40.2` registry checksum: `23f2a97da3e3873c73cb2a2e71b35c40ff95e0b1eefa8d72d8499a6928c3b5b3`
- Native target dependency: **`libsqlite3-sys 0.38.2`**, published 2026-08-08, MIT
- `libsqlite3-sys 0.38.2` registry checksum: `f1d20bef17f513b9b3004532233187769cd072d790971f4e4da0e346eb6401e8`
- Bundled SQLite documented for this pair: **3.53.2**
- Rust 1.98 resolver lockfile artifact SHA-256 before commit: `fbbd67b254f3cbd8dc91e4453a2cd6241469e95b0e20380808a915bbc6ee36fb`
- `libsqlite3-sys 0.38.2` package contains the SQLite amalgamation and build script used by the selected `bundled` feature

The live GitHub default branch observed during qualification does not present a release tree identical to the already-published crates.io `rusqlite 0.40.2` package. Therefore Sentrdel does **not** invent a Git commit binding for this package release. The authoritative source identity for T016 is the crates.io package version plus checksum recorded by Cargo in the committed lockfile. Upstream repository metadata remains provenance/context, not the package-byte identity.

## Why 0.40.2 rather than 0.40.1

An initial resolver proof using exact `rusqlite =0.40.1` selected `libsqlite3-sys 0.38.2` because the 0.40.1 manifest uses a compatible semver requirement rather than an exact native-binding pin. `rusqlite 0.40.2` is the current published patch release and its non-wasm dependency metadata explicitly names `libsqlite3-sys 0.38.2`, matching the package Cargo actually resolves. This removes an avoidable qualification mismatch.

## License

- `rusqlite`: MIT
- `libsqlite3-sys`: MIT
- bundled SQLite amalgamation: SQLite public-domain dedication as documented by upstream

These terms are compatible with Sentrdel Core's Apache-2.0 policy. Required third-party attribution remains part of release compliance.

## Selected Cargo feature profile

```toml
rusqlite = { version = "=0.40.2", default-features = false, features = ["bundled"] }
```

Rationale:

- exact top-level version pin;
- disable `rusqlite` default cache/wasm feature set because T016 does not need it;
- enable `bundled` so Linux/macOS/Windows use one known SQLite source version rather than whatever SQLite happens to be installed on the host;
- `bundled` selects pregenerated bindings; T016 does **not** enable `buildtime_bindgen`, SQLCipher, load/loadable-extension APIs, rusqlite macros, hooks, virtual tables, functions, backup, session, or serialization features.

## Privileged build/runtime authority

This dependency is **not** Rust-only and is admitted as privileged supply-chain code.

`libsqlite3-sys 0.38.2` declares and executes `build.rs`. Under `bundled`, that path:

- executes with developer/CI build authority;
- invokes the `cc` crate/toolchain to compile the vendored SQLite C amalgamation;
- uses pregenerated Rust bindings rather than enabling build-time bindgen;
- reads Cargo/build environment variables;
- honors SQLite-related build variables such as `SQLITE_MAX_VARIABLE_NUMBER`, `SQLITE_MAX_EXPR_DEPTH`, and `LIBSQLITE3_FLAGS` upstream;
- links native SQLite code into the Sentrdel binary.

The published crate exposes pkg-config/vcpkg helpers for other feature paths, but the selected bundled feature compiles the embedded SQLite amalgamation. No upstream build-script download is required for this selected profile; registry package retrieval itself is normal Cargo resolution governed by the committed lockfile/source policy.

## Security review

### Positive

- `rusqlite 0.40.2` is the current published rusqlite release observed on 2026-08-24.
- Its native target dependency metadata aligns with the current `libsqlite3-sys 0.38.2` release.
- The bundled SQLite version is 3.53.2, which SQLite identifies as the fix version for CVE-2026-11822 / CVE-2026-11824 affecting earlier FTS5 code.
- The historical `libsqlite3-sys` advisory CVE-2022-35737 affects versions before 0.25.1 and therefore does not affect 0.38.2.
- Sentrdel uses Sentrdel-owned fixed migration SQL and parameterized SQL for future dynamic values; T016 exposes no repository-controlled SQL.
- Sentrdel trusted crates retain `unsafe_code = "forbid"`; unsafe FFI remains encapsulated by the qualified dependency.

### Residual risk

- Native C compilation materially increases Sentrdel's build-time and memory-safety TCB.
- SQLite upstream is newer than bundled 3.53.2 at qualification time (3.53.4 exists). No reviewed advisory requires a version later than 3.53.2, but later maintenance releases include additional bug fixes.
- The bundled SQLite C configuration contains capabilities such as FTS5 and compile-time load-extension support. Sentrdel does not enable rusqlite's extension-loading API feature and T016 exposes no extension-loading path.
- The build script can be influenced by SQLite-specific environment variables. Release/self-security CI should eventually scrub or explicitly set build environment policy for reproducible privileged dependency builds under T082.
- A future rusqlite/SQLite update requires fresh review before changing the exact pin/lockfile.

## Alternatives considered

### System SQLite — rejected for R1

Would avoid compiling the bundled amalgamation, but makes the actual SQLite version and patch posture host-dependent. The supported system floor is far older than the security-fixed 3.53.2 line, and Windows/macOS/Linux resolution differs. This weakens reproducibility and makes security posture depend on the developer machine.

### Direct SQLite FFI / custom wrapper — rejected

Would recreate unsafe FFI and database-wrapper responsibilities inside Sentrdel with a larger maintenance/security burden.

### Pure-Rust SQLite reimplementation — rejected

Not required for R1 and not justified against the maturity/auditability of SQLite for Sentrdel's durable local-store boundary.

## T016 constraints

This admission authorizes only:

- opening Sentrdel-owned local SQLite files;
- enabling/checking foreign keys;
- enabling/checking WAL mode;
- Sentrdel-owned deterministic schema migrations;
- migration/version integrity tests.

It does **not** authorize T017+ Evidence persistence, repository-provided SQL, extension loading, SQLCipher, arbitrary ATTACH targets, target-repository database mutation, or any live external database access.

## Lockfile gate

**PASS for dependency capture.** Rust 1.98 generated the committed `Cargo.lock`; it contains exact registry checksums for `rusqlite 0.40.2`, `libsqlite3-sys 0.38.2`, and the resolved transitive build/runtime graph. The temporary lockfile-capture workflow step was removed before final qualification. All final CI runs use the canonical `--locked` workflow.

## Requalification triggers

Re-review is required before:

- changing `rusqlite`, `libsqlite3-sys`, or bundled SQLite version/source;
- dropping `bundled` or using a host SQLite;
- enabling `buildtime_bindgen`, extension loading, SQLCipher, hooks/functions/vtab/session features;
- exposing repository-controlled SQL or database paths outside Sentrdel-owned state;
- accepting a security advisory affecting the selected versions/features.
