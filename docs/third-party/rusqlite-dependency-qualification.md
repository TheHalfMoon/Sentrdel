# rusqlite / libsqlite3-sys Dependency Qualification — T016

**Qualification ID:** DQ-RUSQLITE-001  
**Date:** 2026-08-24  
**Decision:** `ADOPT_PRIVILEGED_NATIVE_DEPENDENCY`  
**Scope:** R1 T016 SQLite connection, migrations, and WAL only

## Exact upstream

- Repository: `rusqlite/rusqlite`
- Release: `rusqlite 0.40.1`
- Exact release commit: `6d3c282dc5531a57eb4e22ece3207f00c95d0fb0`
- `Cargo.toml` blob: `314296058b4db8ee10154afd3ff70bf7263f5db4`
- `libsqlite3-sys/Cargo.toml` blob: `ed6810b28bd32910dc2d0b4844c340bb18f6a014`
- `libsqlite3-sys/build.rs` blob: `897706477e095bfb05bb5919d5d24695a2775cb2`
- `README.md` blob: `d0dfa7c25f6f207f1b0e7c767d1a4ee955199d9e`
- Transitive native binding crate: `libsqlite3-sys 0.38.1`
- Bundled SQLite in this release: `3.53.2`

## License

- `rusqlite`: MIT
- `libsqlite3-sys`: MIT
- bundled SQLite amalgamation: SQLite public-domain dedication as documented by upstream

These terms are compatible with Sentrdel Core's Apache-2.0 policy. Required third-party attribution remains part of release compliance.

## Selected Cargo feature profile

```toml
rusqlite = { version = "=0.40.1", default-features = false, features = ["bundled"] }
```

Rationale:

- exact top-level version pin;
- disable `rusqlite` default `cache`/`ffi-sqlite-wasm-rs` features because T016 does not need them;
- enable `bundled` so Linux/macOS/Windows use one known SQLite source version rather than whatever SQLite happens to be installed on the host;
- `bundled` selects pregenerated bindings; T016 does **not** enable `buildtime_bindgen`, SQLCipher, loadable extensions, rusqlite macros, hooks, virtual tables, functions, backup, or serialization features.

## Privileged build/runtime authority

This dependency is **not** Rust-only and is admitted as privileged supply-chain code.

`libsqlite3-sys 0.38.1` declares and executes `build.rs`. Under `bundled`, that build script:

- executes with developer/CI build authority;
- invokes the `cc` crate/toolchain to compile the vendored SQLite C amalgamation;
- copies pregenerated Rust bindings into Cargo `OUT_DIR`;
- reads Cargo/build environment variables;
- honors SQLite-related build variables such as `SQLITE_MAX_VARIABLE_NUMBER`, `SQLITE_MAX_EXPR_DEPTH`, and `LIBSQLITE3_FLAGS` upstream;
- links native SQLite code into the Sentrdel binary.

The transitive crate also has default build-helper features for `pkg-config`/`vcpkg`; the selected bundled path is expected to compile the embedded amalgamation rather than select an arbitrary host SQLite library.

**No dependency download is performed by the upstream build script for this selected feature profile.** SQLite source is embedded in the published `libsqlite3-sys` crate. Cargo registry fetching itself remains ordinary package resolution and is governed by Sentrdel lockfile/source policy.

## Security review

### Positive

- `rusqlite 0.40.1` is the current released rusqlite version observed during qualification.
- The release includes a fix for SQL injection through tainted SAVEPOINT names.
- The bundled SQLite version is 3.53.2, which SQLite identifies as the fix version for CVE-2026-11822 / CVE-2026-11824 affecting FTS5 memory corruption on earlier versions.
- Sentrdel uses parameterized SQL for dynamic values and does not expose repository-controlled migration SQL.
- Sentrdel trusted crates retain `unsafe_code = "forbid"`; unsafe FFI remains encapsulated by the qualified dependency.

### Residual risk

- Native C compilation materially increases Sentrdel's build-time and memory-safety TCB.
- SQLite upstream is newer than the bundled 3.53.2 at qualification time (3.53.4 exists). No known SQLite CVE observed in the qualification sources requires a version later than 3.53.2, but maintenance releases contain additional bug fixes.
- The bundled build compiles several SQLite capabilities into the C library, including FTS5 and load-extension support. Sentrdel does not enable rusqlite's `load_extension` API feature and T016 does not expose an extension-loading surface.
- A future rusqlite/SQLite update requires a fresh dependency review before changing the exact pin/lockfile.

## Alternatives considered

### System SQLite — rejected for R1

Would avoid compiling the bundled amalgamation, but makes the actual SQLite version and patch posture host-dependent. The upstream minimum accepted system SQLite is much older than the security-fixed 3.53.2 line, and Windows/macOS/Linux resolution differs. This weakens reproducibility and makes security claims depend on the developer machine.

### Direct SQLite FFI / custom wrapper — rejected

Would recreate unsafe FFI and database wrapper responsibilities inside Sentrdel with a larger maintenance/security burden.

### Pure-Rust SQLite reimplementation — rejected

Not required for R1 and substantially less mature for Sentrdel's durable local-store requirement.

## T016 constraints

This admission authorizes only:

- opening Sentrdel-owned local SQLite files;
- enabling/checking foreign keys;
- enabling/checking WAL mode;
- Sentrdel-owned deterministic schema migrations;
- migration/version integrity tests.

It does **not** authorize T017+ Evidence persistence, repository-provided SQL, extension loading, SQLCipher, arbitrary ATTACH targets, target-repository database mutation, or any live external database access.

## Requalification triggers

Re-review is required before:

- changing `rusqlite` or `libsqlite3-sys` version/source;
- dropping `bundled` or using a host SQLite;
- enabling `buildtime_bindgen`, `load_extension`, SQLCipher, hooks/functions/vtab/session features;
- exposing repository-controlled SQL or database paths outside Sentrdel-owned state;
- accepting a security advisory affecting the selected versions/features.
