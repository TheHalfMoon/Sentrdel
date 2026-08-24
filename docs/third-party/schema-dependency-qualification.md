# Schema Substrate Dependency Qualification

**Scope:** R1 canonical schema substrate only.  
**Date:** 2026-08-24  
**Policy:** `docs/security/dependency-policy.md`

## Decision

Sentrdel pins a deliberately small schema dependency set. Dependencies with build-time authority or procedural macros are treated as privileged build inputs and remain pinned/lockfile-reviewed.

| Dependency | Exact top-level version | License | Build/proc-macro surface | R1 decision |
|---|---:|---|---|---|
| serde | 1.0.229 | MIT OR Apache-2.0 | package build script; `serde_derive` proc macro enabled by `derive` | ADOPT / PIN / ELEVATED REVIEW |
| serde_json | 1.0.151 | MIT OR Apache-2.0 | package build script | ADOPT / PIN / ELEVATED REVIEW |
| schemars | 1.2.2 | MIT | no package build script; `schemars_derive` proc macro enabled | ADOPT / PIN / ELEVATED REVIEW |
| sha2 | 0.11.0 | MIT OR Apache-2.0 | pure Rust package; no package build script | ADOPT / PIN |
| blake3 | 1.8.7 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception | `build.rs`, `cc` build dependency, compiler probing/assembly/C paths | DEFER FOR R1 |

## Hashing deviation from the original R1 plan

The original Spec Kit plan selected BLAKE3 content addressing. During implementation qualification, the 2026-08-20 crates.io supply-chain incident involving malicious `arrayref@0.3.10` was reviewed. BLAKE3 1.8.7 removed the `arrayref` dependency, so this document does **not** classify BLAKE3 1.8.7 as compromised. However, its current package still executes a substantial `build.rs` and uses the `cc` build dependency/compiler probing.

R1 needs stable collision-resistant canonical object identifiers, not BLAKE3-specific performance. Therefore R1 uses SHA-256 through RustCrypto `sha2 0.11.0` to reduce unnecessary build-time authority. The identifier format is `sha256:<lowercase-hex>`. This choice may be revisited under a later performance/security qualification without changing the evidence model's product semantics.

## Resolved lockfile surface

The committed R1 lockfile resolves 26 packages. The materially privileged transitive build surface includes the proc-macro toolchain (`serde_derive`, `schemars_derive`, `ref-cast-impl`, `proc-macro2`, `quote`, `syn`, `serde_derive_internals`) plus platform/runtime helpers such as `cpufeatures`. No BLAKE3/`cc`/`arrayref` dependency is present in this R1 lockfile.

The exact Cargo checksums in `Cargo.lock`, rather than this prose list, are canonical. CI must use `--locked` and must not regenerate dependency versions at merge time.

## Donor-source boundary

The founder has separately authorized reuse of the discussed GitHub donor code in Sentrdel. That authorization allows future copy/port/adaptation, but PR #3 contains no donor-source import. Actual donor imports remain separate changes with exact repository/ref/file provenance and security qualification recorded in `docs/third-party/source-qualification-ledger.md`.
