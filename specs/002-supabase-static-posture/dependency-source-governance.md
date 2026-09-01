# R2-T030 Dependency and Source Governance Qualification

**Task:** `R2-T030`  
**Status:** QUALIFIED_CANDIDATE — canonical task closure remains gated on exact-head CI, clean review, expected-head merge, post-merge protected-main evidence, and fail-closed repository-governance verification.  
**Qualification baseline:** `8cc82eebaa40a3a96d11472c1ba3c3d97e9e8e18` — canonical R2-T001 readiness closeout.  
**Qualified repository candidate:** `a68f722e7113ebb8694c7eefdcf2810bc9af5349` — canonical R2-T029 closeout.

## Decision

R2 introduced **no Cargo dependency graph change and no donor-source governance change** between the canonical R2 implementation-readiness baseline and the R2-T029 canonical frontier. No new dependency qualification or privileged-surface admission is required for R2-T030.

The existing locked dependency graph remains subject to the qualified R1 self-security controls. This record does not broaden any donor reuse authorization, dependency capability, target-execution permission, or provider/network authority.

## Immutable graph and governance evidence

The following repository artifacts have identical Git blob identities at the R2-T001 readiness baseline and the R2-T029 canonical frontier:

| Artifact | Blob SHA at `8cc82eeb...` | Blob SHA at `a68f722e...` | T030 result |
|---|---|---|---|
| `Cargo.toml` | `e1446832a7b10f919de226b1a20eae9e7ecc9072` | `e1446832a7b10f919de226b1a20eae9e7ecc9072` | UNCHANGED |
| `Cargo.lock` | `31af0a11c16f20ecbcc3f422dc314b557fdfbb2f` | `31af0a11c16f20ecbcc3f422dc314b557fdfbb2f` | UNCHANGED |
| `docs/security/privileged-dependencies.toml` | `01be5b27fbd9b0d030dbaa1f15a09b0009f94e6d` | `01be5b27fbd9b0d030dbaa1f15a09b0009f94e6d` | UNCHANGED |
| `docs/third-party/source-qualification-ledger.md` | `6c5b47dc91a810f5c460edc72504f61cc8fcb1fb` | `6c5b47dc91a810f5c460edc72504f61cc8fcb1fb` | UNCHANGED |

A repository compare from `8cc82eebaa40a3a96d11472c1ba3c3d97e9e8e18` through `a68f722e7113ebb8694c7eefdcf2810bc9af5349` likewise contains no `Cargo.toml`, `Cargo.lock`, `deny.toml`, privileged dependency declaration, or source qualification ledger change.

## Current self-security qualification

On canonical `main` `a68f722e7113ebb8694c7eefdcf2810bc9af5349`, GitHub Actions `Self Security` run `#1205` completed with `success`.

The current `Dependency security` job is fail-closed and performs all of the following on Sentrdel's trusted workspace:

1. installs Rust `1.98.0` and checksum-pinned `cargo-audit 0.22.2` / `cargo-deny 0.20.2`;
2. generates `cargo metadata --locked`;
3. runs `scripts/validate_dependency_governance.py`;
4. validates release dependency policy and the frozen gix authority surface;
5. runs `cargo audit --file Cargo.lock`;
6. runs `cargo deny check advisories bans licenses sources`.

The dependency-governance validator additionally requires exact direct workspace versions, crates.io-only locked third-party sources, deny-on-unknown registry/Git source policy, and complete declarations for every observed third-party `build-script`, `proc-macro`, or `native-link` surface. Missing declarations or qualification references fail closed.

## Source-reuse boundary

The source qualification ledger is unchanged across R2. Therefore R2 did not admit copied or ported donor implementation source through this slice. Existing qualified or pending donor records remain exactly as governed before R2 and receive no new authority from R2-T030.

## Authority and non-claims

- This qualification applies to Sentrdel's own trusted workspace only; Cargo/self-security tooling is not authorized as an analysis primitive against untrusted target repositories.
- No live Supabase access, provider credential use, target build/package execution, or network access by the R2 analyzer is authorized.
- `SSQ-001` and related qualification records prove registration and governance of the locked closure; they are not a claim of line-by-line behavioral proof for every transitive crate.
- Future Cargo manifest/lock changes, feature changes, new privileged surfaces, donor-source imports, or qualification-ledger changes require their own exact qualification delta before merge.

## T030 result

`PASS` for the no-new-dependency/no-new-donor-source branch of R2-T030, subject to canonical merge qualification of this evidence record and the separate task closeout gate.
