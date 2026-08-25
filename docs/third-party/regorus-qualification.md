# Regorus 0.11.0 qualification — T023

**Status:** QUALIFIED_FOR_BOUNDED_IN_PROCESS_POLICY_ONLY  
**Qualified version:** `regorus = 0.11.0`  
**Crates.io checksum:** `3cc4dc91481b1d4001ba7f2e81f7faf674142e0ac36d37d79e5f02764d06571e`  
**Upstream tag:** `regorus-v0.11.0` (`microsoft/regorus`)  
**Annotated tag object:** `dd544d82a8a307b543fc31965e27ca8ba8f61e01`  
**Upstream commit:** `f98865fc980b9919d201e20969d9b28685ee72bc`  
**Release date:** 2026-07-21  
**License expression:** `MIT AND Apache-2.0 AND BSD-3-Clause`  
**Adoption mode:** `NATIVE_DEP`; no upstream source is copied into Sentrdel.

## Why this version

Regorus 0.11.0 is the minimum accepted line for Sentrdel R1. Its security changelog adds a hard rejection for data nested beyond 128 levels instead of risking stack overflow. Sentrdel does not rely on that upstream ceiling as its primary boundary: T023 applies a stricter JSON depth cap before Regorus parses policy data or action input.

## Cargo feature qualification

Sentrdel pins the exact release and disables Regorus defaults:

```toml
regorus = { version = "=0.11.0", default-features = false, features = ["std", "arc"] }
```

The upstream default feature set enables `full-opa`, `arc`, and `rvm`; `full-opa` in turn enables capabilities including HTTP, network, time, YAML, UUID, regex, URL query handling, OPA runtime information, coverage, and other broad policy functionality. Those policy-language capabilities are not admitted into the R1 policy boundary.

Qualified features:

- `std`: required for the bounded in-process execution timer and normal host operation. Upstream `std` also activates the optional `msvc_spectre_libs` dependency; that privileged transitive surface is explicitly recorded below.
- `arc`: changes Regorus internal shared references to thread-safe reference counting without admitting policy-language I/O capabilities.

Explicitly not enabled by Sentrdel T023:

- `full-opa`
- `http`
- `net`
- `time`
- `yaml`
- `uuid`
- `urlquery`
- `regex`
- `glob`
- `jsonschema`
- `opa-runtime`
- `rvm`
- `azure_policy`
- allocator/mimalloc features

Sentrdel additionally accepts only a deliberately small source subset and builtin-call allowlist before policy source reaches Regorus. Import validation is fail-closed for line-oriented, same-line, and split-token forms so Regorus' whitespace-tolerant top-level grammar cannot bypass the Sentrdel import allowlist.

## Privileged dependency review

### Regorus `build.rs`

The Regorus package contains `build.rs`, so it receives elevated review under Sentrdel dependency policy.

Observed behavior at upstream commit `f98865fc980b9919d201e20969d9b28685ee72bc`:

1. It copies the repository's `scripts/pre-commit` and `scripts/pre-push` into `.git/hooks` **only when the Regorus source itself is built from a checkout whose local `.git` path is a directory**.
2. The crates.io dependency source used by Cargo is an unpacked package, not the upstream Git checkout, so that `.git` condition is not satisfied in the normal Sentrdel dependency build.
3. Its only subprocess path (`git rev-parse HEAD`) is compiled under Regorus feature `opa-runtime`. Sentrdel disables default features and does not enable `opa-runtime`.
4. No artifact download, network fetch, credential access, or repository-target hook execution is required by the qualified Sentrdel feature set.
5. The build script always emits a normal Cargo rerun directive after those guarded paths.

### `msvc_spectre_libs` native/link surface

Regorus feature `std` activates `msvc_spectre_libs = 0.1.3` with its upstream `error` feature. This is a privileged transitive dependency and must not be described as "no native-code surface":

- crates.io checksum: `29e871a9861f3664f18b7e04e9301d4edd55090c2dadb4b1c602e26ab32b1f5b`;
- it has a `cc` build dependency and, on Windows MSVC targets, locates and links Microsoft's Spectre-mitigated CRT/libraries;
- its own documentation states that it does nothing for non-MSVC targets;
- because Regorus enables its `error` feature, a Windows MSVC build without the Spectre-mitigated libraries can fail rather than silently fall back.

T023 therefore qualifies the dependency for the currently proven CI target, but does **not** claim Windows-MSVC build qualification from the Ubuntu-only exact-head evidence. Any future Windows release gate must install/prove the required Spectre libraries or revise the Regorus feature/dependency strategy under a new qualification delta.

### Procedural-macro/build transitive closure

The committed lockfile introduces ordinary Rust transitive dependencies including compile-time/build surfaces such as `thiserror-impl` and build-script-driven crates. They remain exact-lockfile governed and are admitted only as the dependency closure of exact-pinned Regorus 0.11.0; no such transitive is granted policy, network, credential, target-repository, or Sentrdel authority. Any Regorus version/feature change requires a fresh lockfile and privileged-surface delta review.

This qualification does **not** authorize building Regorus from an arbitrary target repository checkout or enabling additional Regorus features without a new dependency review.

## Sentrdel wrapper boundary

Regorus is not exposed as Sentrdel's policy authority. `sentrdel-policy` owns a bounded wrapper that enforces before evaluation:

- policy source byte/line/column limits;
- static data byte and JSON-depth limits;
- per-action input byte and JSON-depth limits;
- object-only data/input documents;
- Rego v1;
- a fixed validated `data.<package>.<rule>` entrypoint;
- a small tested import/subset/builtin allowlist;
- strict builtin errors;
- compile/entrypoint validation outside the action hot path;
- an engine-specific execution timer;
- fail-closed mapping of evaluation/parse/output failures to `UNDECIDABLE`.

The wrapper does not expose arbitrary query evaluation, file policy loading, extensions, target compilation, or network-capable builtins.

## Precompiled/timer note

`Engine::compile_with_entrypoint` is called during policy construction so invalid or missing entrypoints fail before the policy is installed. Regorus `CompiledPolicy::eval_with_input` creates an internal engine whose engine-specific execution timer configuration is not carried from the compiling engine. Therefore T023 retains and clones the already-loaded/prepared `Engine` for hot-path `eval_rule`, preserving the engine-specific timer while still keeping policy parse/load/entrypoint compilation outside each action evaluation. Sentrdel does not replace this with an unbounded compiled-policy evaluation merely to claim a faster path.

## Authority/non-claims

- Rust kernel invariants remain outside Rego and cannot be weakened by this dependency.
- T023 returns only a repository/external policy **candidate** verdict. T024 owns monotonic policy composition and repository-policy narrowing validation.
- A Regorus failure is never `ALLOW`; it becomes `UNDECIDABLE` and is resolved fail-closed only at the existing Rust enforcement boundary.
- This qualification does not admit Regorus file I/O, HTTP, network, time, runtime metadata, extension registration, Azure targets, or arbitrary query APIs into Sentrdel's public policy surface.
- This qualification does not claim Windows-MSVC build support until a Windows exact-head build gate proves the required native link environment.
