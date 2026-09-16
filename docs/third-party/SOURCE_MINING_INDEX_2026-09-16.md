# Sentrdel Source Mining Index — 2026-09-16

**Status:** NAVIGATION_ONLY  
**Implementation authority:** NONE  

This index makes the current source-research and qualification corpus discoverable without changing the authority of any underlying record.

## Controlling rule

When multiple records mention the same source, use this precedence:

```text
Sentrdel canonical source/dependency qualification
  > Sentrdel source assessment
  > cross-repository research pin
  > unpinned reference
```

## Current source-mining records

### OpenCTI

- `docs/third-party/opencti-source-assessment-2026-09-16.md`
- `docs/third-party/opencti-source-reuse-map-2026-09-16.md`
- `docs/third-party/founder-source-reuse-attestation-2026-09-16-opencti.md`
- `specs/000-sentrdel-roadmap/opencti-intelligence-interoperability-2026-09-16.md`

Research pin:

```text
OpenCTI-Platform/opencti@c22668461981ac9602e8e16527ef613428c34c3c
```

### OpenCodeReview

- `docs/third-party/open-code-review-source-assessment-2026-09-16.md`
- `specs/000-sentrdel-roadmap/full-project-review-and-plan-strengthening-2026-09-16.md`

Research pin:

```text
alibaba/open-code-review@a694be568d9b9a935b2ba11a867d5a91d7ffd833
```

Primary value: deterministic review selection, run/completeness manifest, safe resume/checkpoint identity, bounded grouping/fallback, rule-routing explanation, host-agent delegation, and forge publication mechanics. The model loop is not a Sentrdel judgment-authority candidate.

### Founder GitHub source universe

- `docs/third-party/founder-source-reuse-attestation-2026-09-16-github-source-universe.md`
- `docs/third-party/cross-repository-source-mining-2026-09-16.md`
- `docs/third-party/development-assurance-source-mining-2026-09-16.md`

The product/source study mines founder-owned Golam/Kodac/Ascout/Signthos/Himsat/WePLD material plus external source pins already researched there. The development-assurance study separately records Diffcipline, SpecGrain and HarnessMind patterns that can improve how Sentrdel changes are bounded and proven without making those projects runtime dependencies.

### Existing Sentrdel source/dependency qualifications that control over cross-repository pins

- `docs/third-party/graphify-source-qualification.md`
  - `Graphify-Labs/graphify@b2cd36267456c166788c95be6e68574064a92a42`
  - `QUALIFIED_FOR_SELECTIVE_RUST_PORT`
- `docs/third-party/ast-grep-tree-sitter-qualification.md`
  - `ast-grep-core =0.45.2`
  - `tree-sitter =0.26.13`
  - `tree-sitter-javascript =0.25.0`
  - `QUALIFIED_FOR_T039_ADMISSION_PENDING_LOCK_CLOSURE`
- `docs/third-party/engine-adapter-dependency-qualification.md`
  - strict bounded JSON/SARIF adaptation using the existing exact-pinned serde closure

### Existing Sentrdel source assessments

- `docs/third-party/source-candidate-assessment-2026-09-08.md`
  - Tencent AI-Infra-Guard
  - Google Magika
  - Tencent AICGSecEval
  - Tencent Secure Coding Guide
  - Tencent TscanCode
- `docs/third-party/source-candidate-assessment-2026-09-12.md`
  - GlitchTip
  - HackerAI
  - HackAgent
  - HexStrike AI
  - Shannon
  - HackBot
  - Strix

## Highest-priority founder-owned code to qualify for future Sentrdel slices

```text
TheHalfMoon/Golam
  authority_security_v2.rs
  sandbox_enforcement.rs
  capability_lease_effect.rs

TheHalfMoon/Kodac
  p5-evidence-provenance.ts
  p5-evidence-relation.ts
  p6-deterministic-security-finding.ts
  sandbox backend/admission/attestation/lifecycle family

TheHalfMoon/Ascout
  src/receipt/model.ts
  security evidence / no-green-by-omission research
```

These are source-mining priorities only. Their owning Sentrdel implementation slices still require dependency-eligible Spec Kit authority and exact selected-path qualification.

## Development-assurance references

```text
TheHalfMoon/Diffcipline
  proof-before-done / exact-diff / explicit verification evidence

TheHalfMoon/SpecGrain
  bounded independently verifiable work units / packet-attempt-verifier separation

TheHalfMoon/HarnessMind
  evidence semantics / projection-not-truth / standards-first trajectory and telemetry choices
```

These improve Sentrdel engineering discipline. They are not product/runtime source priorities.

## External producer/adaptor candidates discovered through founder repositories

Research-only until refreshed and qualified by Sentrdel:

```text
OSV-Scanner
Syft
Grype
Trivy
Gitleaks
OpenGrep / Semgrep
CodeQL user-supplied results
Scorecard
Joern / Infer
SCIP
OpenSandbox / gVisor / Firecracker / Wasmtime
OpenTelemetry
in-toto / SLSA
AI-Infra-Guard
AICGSecEval
OSS-CRS / Atlantis / FuzzingBrain / Vulnhuntr
```

## Authority reminder

```text
Founder permission != source admission
Source qualification != implementation authorization
External result != canonical Finding
External confidence != Sentrdel Evidence authority
Sandbox backend != authorization authority
Model review comment != canonical Finding
Research pin != release pin
```
