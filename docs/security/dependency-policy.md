# Dependency Security Policy

Sentrdel's dependency graph is part of the trusted computing base.

## Admission

Every new dependency must document:

- capability required and why std/owned code is insufficient;
- exact crate/version/source and license;
- maintenance/security status;
- whether it has `build.rs`, proc macros, native code, downloaded artifacts, network access, credential access, or unusual filesystem/process behavior;
- feature set enabled and why;
- removal/replacement cost.

Prefer small Rust-native dependencies with minimal features. Disable default features unless they are explicitly needed and reviewed.

Direct third-party workspace dependency requirements are exact `=version` requirements. `Cargo.lock` is committed. Unknown registries, unknown Git sources, and wildcard requirements fail policy.

## Privileged dependencies

`build.rs`, proc macros, native compilation/linking, downloaded artifacts, credential/network behavior, and unusual filesystem/process behavior execute with elevated developer/CI authority. They require elevated review before admission. A permissive license does not make a crate trustworthy.

T091 makes compile/link privilege mechanically auditable:

- `docs/security/privileged-dependencies.toml` declares exact package/version records for every third-party `custom-build`, `proc-macro`, and native Cargo `links` surface observed by locked `cargo metadata`;
- `scripts/validate_dependency_governance.py` fails if an observed privileged surface is undeclared, a declaration is stale/duplicated, or its qualification reference is absent;
- direct qualification records such as `RQ-001`/`PWQ-001` remain authoritative for their adopted dependencies;
- `SSQ-001` in `docs/third-party/t091-self-security-tool-qualification.md` records the locked transitive privileged-surface closure without overclaiming a line-by-line source audit.

A dependency change must update qualification/declarations rather than weakening the validator.

## Required gates

Canonical early self-security gate: `.github/workflows/self-security.yml` (`Self Security` / `Dependency security`). It runs on every pull request and on `main`/`impl/**` pushes so later branch governance can require one stable check name.

The gate requires:

- exact `rust-toolchain.toml` / Rust 1.98.0 use;
- committed, locked Cargo resolution;
- exact direct workspace dependency versions;
- crates.io-only third-party Cargo sources under current R1 policy;
- privileged dependency declarations and qualification references;
- `cargo-audit 0.22.2` advisory scan of Sentrdel's `Cargo.lock`;
- `cargo-deny 0.20.2` advisories/bans/licenses/sources checks using committed `deny.toml`;
- checksum verification of downloaded self-security tool artifacts before execution.

The qualified CI tool records and artifact digests are frozen in `docs/third-party/t091-self-security-tool-qualification.md`. Version/artifact changes require ordinary elevated review and updated qualification.

## Trusted-workspace execution boundary

Cargo-based self-security tools run **only on Sentrdel's trusted first-party workspace**. The T091 workflow has no target-repository parameter, no alternate working-directory input, read-only repository permissions, and checkout credentials are not persisted.

Do not run Cargo, `cargo-audit`, `cargo-deny`, or later `cargo-vet` against arbitrary target repositories as an analysis primitive: target Cargo configuration can select executable wrappers/helpers and target manifests/build scripts are untrusted.

This boundary does not prohibit Sentrdel from parsing untrusted target manifests/lockfiles as bounded data in later product features; it prohibits executing target-controlled Cargo tooling/configuration during ordinary analysis.

## Tool provenance and limitations

- `cargo-audit 0.22.2`: official RustSec release, verified signed annotated tag, checksum-pinned Linux MUSL release artifact.
- `cargo-deny 0.20.2`: official Embark Studios release, checksum-pinned Linux MUSL release artifact; upstream annotated tag was unsigned at qualification and that limitation is explicit.

Both tools are downloaded native executables with filesystem and network capability. Their CI authority is bounded by checksum verification, fixed versions/URLs, read-only repository permissions, and the trusted-workspace execution boundary. Successful tool output is a dependency-policy signal, not proof that every dependency is behaviorally safe.

## Release-grade continuation

T091 establishes the early dependency self-security gate. T082 later completes release-grade self-security, refresh policy, and any broader vetting/attestation requirements.
