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

## Privileged dependencies

`build.rs`, proc macros, native compilation and download-at-build behavior execute with developer/CI authority. They require elevated review before admission. A permissive license does not make a crate trustworthy.

## Required gates

- exact `rust-toolchain.toml` pin;
- committed `Cargo.lock` after dependency resolution;
- `cargo audit` advisory gate;
- `cargo deny check` license/source/advisory policy;
- no wildcard dependency requirements;
- exact source qualification for copied/vendored code/data.

`cargo-vet` may later be used only in Sentrdel's trusted first-party workspace. Do not run Cargo/cargo-vet against arbitrary target repositories as an analysis primitive: repository Cargo config can select executable wrappers/helpers.

## Current bootstrap

The Phase-1 bootstrap intentionally has no third-party Rust crate dependencies. Each later dependency enters through its corresponding Spec Kit task and qualification record.
