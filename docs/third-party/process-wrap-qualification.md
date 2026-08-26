# process-wrap 9.1.0 / nix 0.31.3 qualification — T027

**Status:** `QUALIFIED_FOR_T027_UNIX_PROCESS_LIFECYCLE_CONTAINMENT`  
**Qualified Sentrdel evidence target:** Ubuntu 24.04 / Rust 1.98.0  
**Adoption mode:** `NATIVE_DEP`; no upstream source is copied into Sentrdel.

## Qualified identities

### process-wrap

- crate: `process-wrap = 9.1.0`
- crates.io checksum: `2e842efad9119158434d193c6682e2ebee4b44d6ad801d7b349623b3f57cdf55`
- upstream repository: `watchexec/process-wrap`
- tag: `v9.1.0`
- annotated tag object: `d61729ff63bb9e5c731c8c5720bfffbc9350d167`
- upstream commit: `3d856eebd02799d025237134db51d05bbc4f1434`
- release date: 2026-03-08
- license: `Apache-2.0 OR MIT`
- upstream MSRV: Rust 1.87.0

### nix

- crate: `nix = 0.31.3`
- crates.io checksum: `cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d`
- upstream repository: `nix-rust/nix`
- tag: `v0.31.3`
- annotated tag object: `9cd968a1af35b46b05ed41e05acfcca5d02a5645`
- upstream commit: `b5933ca178802b558a667514f717a86b3a1cedcc`
- license: `MIT`

Sentrdel pins `nix` directly only so the Unix containment wrapper can identify `ESRCH` structurally when a process group has already drained. The process-group implementation itself is provided through `process-wrap`.

## Why std-only code is insufficient here

T027 must prevent a timed-out or output-capped external engine from leaving ordinary descendants alive with inherited stdout/stderr handles. `std::process::Child::kill` targets the direct child and does not provide a cross-platform process-tree ownership primitive. A first-party implementation would therefore require platform-specific FFI or unsafe code for POSIX process groups and Windows Job Objects inside a crate that deliberately has `#![forbid(unsafe_code)]`.

The admitted dependency narrows that privileged capability to process lifecycle containment while Sentrdel retains the authority decisions, executable selection, argv construction, cwd validation, environment clearing, time/output limits, and result interpretation.

## Feature qualification

Sentrdel uses the exact dependency declaration:

```toml
process-wrap = { version = "=9.1.0", default-features = false, features = ["std", "process-group", "job-object"] }
```

Enabled:

- `std` — std-based process wrapper frontend;
- `process-group` — POSIX process-group lifecycle wrapper on Unix;
- `job-object` — Windows Job Object lifecycle wrapper on Windows.

Explicitly not enabled:

- `tokio1`;
- `tracing`;
- `process-session`;
- `creation-flags`;
- `kill-on-drop`;
- `reset-sigmask`.

The T027 implementation selects the containment primitive in first-party code using compile-time target configuration. Repository or engine data cannot choose or disable the containment mode.

## Privileged dependency review

### process-wrap

The qualified `process-wrap` source tree has no package `build.rs`. Its admitted runtime behavior is nevertheless privileged by design: it creates and controls external processes, configures a POSIX process group on Unix, and contains the Windows path in a Job Object. This is exactly the narrow capability T027 needs and is not treated as an ordinary data-processing dependency.

The Unix implementation uses OS process-group signaling and wait behavior through `nix`. The Windows implementation uses the `windows` crate and Windows Job Object APIs. These surfaces include platform FFI/unsafe code in the dependency closure even though Sentrdel's `sentrdel-engine` crate itself forbids unsafe code.

### nix

`nix 0.31.3` has a `build.rs` and therefore receives elevated review. At the qualified ref, that build script uses `cfg_aliases` and emits Cargo `rustc-check-cfg` declarations. No subprocess execution, artifact download, network access, credential access, or target-repository hook behavior was observed in the qualified build script.

The crate is an OS syscall wrapper and contains privileged/unsafe implementation internally. Sentrdel's direct use is limited to comparing a Unix raw OS error with `Errno::ESRCH`; it is not granted executable-selection, repository, policy, network, or credential authority.

### Windows transitive closure

Enabling `job-object` introduces the target-specific `windows 0.62.2` closure and associated proc-macro/interface crates into the committed lockfile. This closure is lockfile-governed and passed source/license/advisory policy checks, but the current T027 evidence was executed on Ubuntu. Therefore this qualification does **not** claim Windows runtime correctness or release qualification.

## Sentrdel-owned containment boundary

The first-party wrapper preserves these rules:

- only a canonical executable already admitted by trusted user/system configuration may be spawned;
- repository data cannot select an executable or shell command;
- arguments are passed as argv values; no shell evaluation exists;
- cwd is canonicalized and confined to the admitted workspace;
- child environment starts from `env_clear()` and only explicitly allowlisted names/values are added;
- manifest-derived wall-clock/stdout/stderr limits have hard Sentrdel maxima;
- denied declared network requirements fail closed before spawn;
- timeout, output-cap, pipe failure, and root-exit cleanup terminate the contained process group/job before reader joins;
- a Unix `ESRCH` is treated as quiescent only because it means the addressed process group no longer exists; other containment errors remain fail-closed;
- raw stdout/stderr remain untrusted bytes. T028, not this dependency, owns interpretation/adaptation.

## Qualification evidence

Dependency admission was proven on Sentrdel branch head `f61b71cae9f66168863da6768d24dbd2822f0160` by GitHub Actions run `32916506528` (`T027 Dependency Qualification`). The gate:

1. generated the candidate Cargo lockfile under Rust 1.98.0;
2. resolved and displayed the exact workspace dependency tree;
3. passed `cargo fmt --check`;
4. passed `cargo check --workspace --all-targets --locked`;
5. passed the full workspace test suite, including the T027 descendant-survivor regression;
6. passed `cargo clippy --workspace --all-targets --locked -- -D warnings`;
7. passed pinned `cargo-audit 0.22.0` against the trusted Sentrdel workspace;
8. passed pinned `cargo-deny 0.20.2 check` with advisories, bans, licenses, and sources all OK.

The admitted candidate `Cargo.lock` has SHA-256:

`2f2b02c588a15f8a5db888431240622dd02b2bdaf3ac5206fe515eb876cb8743`

The initial deny run correctly exposed versionless first-party path dependencies as wildcard requirements. Sentrdel did not weaken `deny.toml`; the engine, policy, and store links to `sentrdel-schema` were instead pinned to the workspace version `=0.0.0`, after which `cargo-deny` passed without a waiver or ignore.

## Regression evidence

The T027 Unix process-tree regression launches a root fixture that creates a descendant retaining inherited pipes. Both remain alive past the Sentrdel execution deadline unless containment intervenes. Sentrdel must return `Timeout` within the bounded call, then wait beyond the descendant's planned survivor write and prove that no marker file appears. This passed in the exact qualification run.

Environment-scrubbing, output-cap, non-zero, timeout, workspace-executable rejection, source binding, and denied-network declaration tests also pass under the same semantic qualification.

## Authority and non-claims

This qualification does not grant `process-wrap`, `nix`, or the external engine any Sentrdel policy authority.

It specifically does **not** claim:

- hostile-code sandboxing;
- an OS network sandbox;
- credential discovery or inheritance;
- target-repository build/script execution authority;
- T028 raw-result/SARIF interpretation;
- T030 CoverageRecord construction;
- T036 bootstrap/DI wiring;
- Windows Job Object runtime qualification from the Ubuntu evidence.

`NetworkAccessPolicy` remains a declaration/admission gate. A future task requiring actual per-process network isolation needs a separate qualified sandbox primitive.

## Maintenance and replacement

`process-wrap 10.0.0` was released on 2026-08-24 and includes breaking wrapper behavior plus Windows fixes. Sentrdel does not silently float to that line: 9.1.0 remains exact-pinned because it is the version proven by the T027 Unix regression. Any upgrade, feature change, or Windows release claim requires a fresh qualification delta and lockfile review.

Removal/replacement requires preserving the tested process-tree lifecycle semantics on every claimed platform. A first-party replacement would need separately reviewed platform FFI/unsafe code or another qualified containment primitive. The direct `nix` dependency can be removed if the chosen containment API later exposes an equally precise structured representation for an already-absent Unix process group.
