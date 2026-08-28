# T091 Self-Security Tool Qualification

**Status:** R1 binding qualification for the early self-security CI gate.  
**Scope:** Sentrdel's own trusted Rust workspace only. These records do not authorize running Cargo, `cargo-audit`, or `cargo-deny` against arbitrary target repositories.

## SATQ-001 — RustSec cargo-audit 0.22.2

- **Role:** advisory scanner for Sentrdel's committed `Cargo.lock`.
- **Upstream:** `RustSec/rustsec`.
- **Release/tag:** `cargo-audit/v0.22.2`.
- **Annotated tag object:** `78bd4d48923d207898e94827cbd79d73903a85fa`.
- **Dereferenced source commit:** `281452c35cf0870969042374110f099a411bc185`.
- **Tag verification at qualification:** GitHub reported a valid verified SSH signature.
- **License at the qualified source commit:** `Apache-2.0 OR MIT`.
- **CI artifact:** `cargo-audit-x86_64-unknown-linux-musl-v0.22.2.tgz` from the official GitHub release.
- **Required artifact SHA-256:** `7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428`.
- **Runtime capability:** reads Sentrdel's lockfile and dependency metadata; obtains/updates RustSec advisory data over the network; executes as a downloaded native binary in CI.
- **Credential requirement:** none. The T091 job has repository `contents: read` only and checkout credentials are not persisted.
- **Adoption decision:** `QUALIFY` for read-only self-audit of Sentrdel's own trusted workspace.
- **Rejected use:** target-repository auditing, arbitrary path input, mutable version selection, unverified artifact execution, or treating an unavailable advisory source as PASS.

The release endpoint is not treated as immutable authority by itself. CI verifies the frozen artifact SHA-256 before extraction/execution; changed bytes fail closed.

## SDTQ-001 — Embark Studios cargo-deny 0.20.2

- **Role:** dependency advisory, license, bans, and source-policy enforcement for Sentrdel's own Cargo graph.
- **Upstream:** `EmbarkStudios/cargo-deny`.
- **Release/tag:** `0.20.2`.
- **Annotated tag object:** `87da103c554376c89a641116f835a41073a9d774`.
- **Dereferenced source commit:** `bca0dde53651ee946720e4540b5ce2610bec8f06`.
- **Tag verification at qualification:** GitHub reported the annotated tag as unsigned. This is retained as an explicit provenance limitation rather than represented as verified signing.
- **License at the qualified source commit:** `MIT OR Apache-2.0`.
- **CI artifact:** `cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz` from the official GitHub release.
- **Required artifact SHA-256:** `9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f`.
- **Runtime capability:** reads Cargo manifests/lock/registry metadata, evaluates `deny.toml`, and may access registry/advisory metadata over the network.
- **Credential requirement:** none. The T091 job has repository `contents: read` only and checkout credentials are not persisted.
- **Adoption decision:** `QUALIFY_WITH_UNSIGNED_TAG_LIMITATION` for read-only dependency-policy checking of Sentrdel's own trusted workspace.
- **Rejected use:** target-repository execution, mutable action/tag execution, unverified artifact execution, or use as proof that a dependency is behaviorally safe.

The exact release artifact SHA-256 is the CI byte-integrity guard. The unsigned upstream tag remains a documented trust limitation and requires normal elevated review on version changes.

## SSQ-001 — Locked privileged dependency surface closure

This record covers the **mechanical privileged-surface declaration gate** for the current locked third-party Cargo closure. It is not a claim that every transitive crate has received a line-by-line source audit.

The gate combines:

1. committed `Cargo.lock`;
2. crates.io-only third-party Cargo sources;
3. exact direct workspace dependency versions;
4. `cargo-audit` advisories;
5. `cargo-deny` advisories/licenses/bans/sources;
6. `cargo metadata --locked` inspection of every non-workspace package target;
7. explicit declarations in `docs/security/privileged-dependencies.toml` for every observed `custom-build`, `proc-macro`, or native `links` surface;
8. existing direct-dependency qualification records such as `RQ-001` and `PWQ-001` where available.

A new or changed package that exposes an undeclared privileged surface fails the validator. A declaration must bind an exact package name/version, the observed privilege class, an owner, rationale, and a qualification reference.

### Authority limit

`SSQ-001` means the locked closure is **registered and gated**, not that transitive package behavior is proven safe. T082 remains responsible for release-grade completion and any broader audit/vetting policy. Future dependency changes must update the lockfile/declarations/qualification under ordinary review rather than weakening this gate.

## RCSQ-001 — ref-cast 1.0.27 build script

- **Upstream:** `dtolnay/ref-cast`.
- **Release/tag:** `1.0.27`.
- **Annotated tag object:** `bfba91917e39852d1c46f80bf89c5206c1a8b9a2`.
- **Dereferenced source commit:** `971b90557fc096216a52b2672a6ab5d39523162c`.
- **Tag verification:** GitHub reported a valid verified PGP signature.
- **Privileged surface:** `build.rs` / `custom-build`.
- **Observed behavior at the qualified commit:** reads Cargo-provided `OUT_DIR`, package patch version, and `RUSTC`; writes one generated `private.rs` file under `OUT_DIR`; invokes only the Cargo-selected Rust compiler with `--version`; emits Cargo cfg/check-cfg directives.
- **Network/credential behavior observed in the qualified build script:** none.
- **Filesystem authority:** write is limited by the script logic to `OUT_DIR/private.rs`; no repository source mutation path was observed in the qualified file.
- **Subprocess authority:** invokes only the executable named by Cargo's `RUSTC` environment variable with one `--version` argument.
- **Decision:** `QUALIFIED_FOR_LOCKED_TRANSITIVE_BUILD_SCRIPT` at exactly `ref-cast 1.0.27` in Sentrdel's trusted workspace.
- **Limitation:** this qualification is for the exact build script at the exact signed tag/commit, not blanket approval of future ref-cast releases or arbitrary transitive code.

## SJSQ-001 — serde_json 1.0.151 build script

- **Upstream:** `serde-rs/json`.
- **Release/tag:** `v1.0.151`.
- **Annotated tag object:** `23d32e33e1bf94b3a1dd8248d1090d5c994417ec`.
- **Dereferenced source commit:** `de8500740cdcabffb9734f503e4889def823cf10`.
- **Tag verification:** GitHub reported a valid verified PGP signature.
- **Privileged surface:** `build.rs` / `custom-build`.
- **Observed behavior at the qualified commit:** reads Cargo-provided `CARGO_CFG_TARGET_ARCH` and `CARGO_CFG_TARGET_POINTER_WIDTH`, then emits `cargo:rustc-check-cfg` and a target-dependent `fast_arithmetic` cfg value.
- **Network/credential/filesystem/subprocess behavior observed in the qualified build script:** none.
- **Decision:** `QUALIFIED_FOR_LOCKED_TRANSITIVE_BUILD_SCRIPT` at exactly `serde_json 1.0.151` in Sentrdel's trusted workspace.
- **Limitation:** this qualification covers the exact build script only and does not convert serde_json output into security authority or approve future versions automatically.

## CHLQ-001 — chacha20 0.10.2 lock-only yanked resolution

- **Trigger:** T091 `cargo-deny` correctly rejected locked `chacha20 0.10.1` because crates.io marks that release yanked.
- **Dependency path:** `regorus 0.11.0 -> rand 0.10.2 -> chacha20`.
- **Canonical registry evidence:** `rust-lang/crates.io-index` entry for `chacha20 0.10.2` reports `yanked=false`, Rust 1.85 minimum, and checksum `65c35e4b699c7e15ccbe7ee35c005e4fc0a278d22238a2857e6ce2dadeda1b06`.
- **Compatibility:** the normal dependency shape needed by the locked graph is unchanged from 0.10.1: `cfg-if`, target-specific `cpufeatures`, and optional `rand_core`; `rand 0.10.2` accepts the 0.10.x line.
- **Upstream:** `RustCrypto/stream-ciphers`.
- **Release/tag:** lightweight tag `chacha20-v0.10.2` at commit `6b236b758a0279f64d777797514813b2cb572c8b`.
- **Tag limitation:** the ref points directly to a commit, so there is no annotated tag object/signature to claim. Registry checksum + exact source commit + Cargo/CI resolution are the integrity evidence used here.
- **Manifest at exact commit:** package version `0.10.2`, license `MIT OR Apache-2.0`, Rust 1.85 minimum, pure Rust package manifest with no package `build.rs` declaration and no native `links` field.
- **Change admitted:** `Cargo.lock` version/checksum only, from yanked `0.10.1` to non-yanked `0.10.2`; no direct workspace dependency requirement or Sentrdel code changes.
- **Decision:** `QUALIFIED_FOR_LOCK_ONLY_NON_YANKED_RESOLUTION`.
- **Required proof:** Schema Lock Qualification, Bootstrap CI, and Self Security must all pass on the exact head before T091 can close. If Cargo resolves a different graph than this record, the change is not qualified.

## CI execution boundary

The T091 workflow intentionally has no target-repository parameter and no alternate working-directory input. It checks out only the current Sentrdel repository, then runs:

- `cargo metadata --locked` on Sentrdel;
- Sentrdel's dependency-governance validator;
- `cargo audit --file Cargo.lock` on Sentrdel;
- `cargo deny check advisories bans licenses sources` on Sentrdel.

This boundary is part of the qualification. Reusing these Cargo commands as an analysis primitive against untrusted repositories would require a different specification and security model because target Cargo configuration may select executable helpers/wrappers.
