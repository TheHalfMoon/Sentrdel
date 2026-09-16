# Cross-Repository Source Mining for Sentrdel — 2026-09-16

**Status:** RESEARCH / SOURCE-QUALIFICATION INPUT ONLY  
**Planning branch:** `docs/security-control-plane-2026-09-12`  
**Active implementation authority:** `specs/004-security-invariant-regression/` only  
**Founder permission context:** `docs/third-party/founder-source-reuse-attestation-2026-09-16-github-source-universe.md`  

## 1. Purpose

This study mines the founder's connected GitHub source universe for implementation, contract, benchmark, and interoperability material that can strengthen Sentrdel.

It does not authorize implementation or reorder the active S1 program. Sentrdel-owned qualification records always outrank research pins discovered in another founder repository.

The target architecture remains:

> Sentrdel owns deterministic Evidence/Coverage, security-invariant regression, canonical Finding judgment, bounded verification, and provenance. External tools, intelligence platforms, models, graphs, sandboxes, and scanners remain qualified producers or constrained execution backends.

## 2. Qualification precedence

Use this precedence when the same upstream appears in multiple founder repositories:

```text
Sentrdel canonical source/dependency qualification
  > Sentrdel source assessment
  > exact research pin from another founder repository
  > unpinned reference
```

Examples already proven by this pass:

- `Graphify-Labs/graphify` is **already Sentrdel-qualified** at `b2cd36267456c166788c95be6e68574064a92a42` for a bounded selective Rust port. The WePLD pin is research history only.
- `ast-grep-core 0.45.2`, `tree-sitter 0.26.13`, and `tree-sitter-javascript 0.25.0` already have a Sentrdel dependency qualification for the bounded native structural-producer path, subject to the recorded lock/privileged-dependency closure.
- Sentrdel already owns a strict JSON/SARIF engine-adapter dependency boundary using its existing exact-pinned `serde` / `serde_json` closure.
- `Tencent/AI-Infra-Guard`, `google/magika`, and `Tencent/AICGSecEval` already have Sentrdel research assessments and must not be downgraded to a weaker cross-repository classification.

## 3. Reuse dispositions

- `QUALIFIED_EXISTING` — Sentrdel already has a controlling qualification.
- `PORT_CANDIDATE` — founder-owned implementation is close enough to justify selective porting after exact-path qualification.
- `ADAPT_IN_RUST` — retain semantics/tests but implement inside Sentrdel-owned Rust contracts.
- `OUT_OF_PROCESS_ADAPTER` — keep the producer outside the trusted core and import bounded evidence.
- `PROTOCOL_REFERENCE` — use the protocol/interchange contract without adopting a full runtime.
- `BENCHMARK_REFERENCE` — use methodology/data shape only after rights/provenance qualification.
- `RESEARCH_REFERENCE` — useful ideas, no current code-intake case.

## 4. Highest-value founder-owned implementation sources

### 4.1 `TheHalfMoon/Golam` — authenticated authority-state integrity

Primary implementation:

```text
crates/golam-ledger/src/authority_security_v2.rs
```

Observed properties:

- `#![forbid(unsafe_code)]`;
- protected snapshots for principals, policy, capability leases/revocations, approvals, taint, verifier rules, secrets, egress, sandbox admissions, and authorization decisions;
- canonical payload encoding;
- BLAKE3 payload and chained-record integrity;
- contiguous audit sequencing;
- exact reconciliation between latest authenticated snapshots and current protected state;
- missing protected-state coverage fails visible.

Sentrdel use:

```text
VerificationAuthorization validation history
IntegrationServiceIdentity changes
Security Pack activation
marking / policy / automation authority mutations
control-plane protected-state audit
```

Disposition: `PORT_CANDIDATE / P0`.

Port the authenticated-state integrity pattern behind Sentrdel-owned types; do not import Golam's whole authority schema.

### 4.2 `TheHalfMoon/Golam` — sandbox rights narrowing

Primary implementation:

```text
crates/golam-ledger/src/sandbox_enforcement.rs
```

Observed properties:

- deny-all request shape;
- exact-subset filesystem, environment, device, IPC, and inherited-handle rules;
- network and process-spawn authority cannot widen;
- requested resource limits can only narrow;
- deterministic enforcement-descriptor hash bound to the source launch plan;
- a rights descriptor explicitly does not claim actual platform containment.

Sentrdel use:

```text
ToolCapabilityManifest
VerificationRunManifest
bounded verification worker launch
sandbox adapter conformance
```

Disposition: `PORT_CANDIDATE / P0`.

### 4.3 `TheHalfMoon/Golam` — capability leases and one-shot approvals

Primary implementation/reference:

```text
crates/golam-kernel/src/capability_lease_effect.rs
specs/003-identity-policy-secrets-sandbox/contracts/egress-sandbox-contract.md
```

High-value semantics:

- authorization precedes authority mutation;
- exact payload/effect binding;
- proposed -> authorized transition;
- at-most-once effect semantics;
- one-shot approval bound to exact effect/action/resource;
- explicit egress instead of ambient network authority.

Sentrdel use: short-lived verification authority, service identities, one-shot mutation approval, connector egress.

Disposition: `ADAPT_IN_RUST / P0-P1`.

### 4.4 `TheHalfMoon/Kodac` — exact evidence provenance

Primary implementation:

```text
packages/kodac-runtime/src/verification/p5-evidence-provenance.ts
schema/p5-evidence-provenance.schema.json
```

The contract binds:

```text
source kind / source ref / source digest / evidence identity
repository identity / canonical base / candidate head
producer identity / version / configuration identity
policy / scope / input / environment identities
freshness state + basis
canonical semantic binding identity
```

Sentrdel use:

```text
ExternalEvidenceEnvelope
ProofArtifactReference
runtime evidence
CTI import provenance
verification artifacts
freshness without trust promotion
```

Disposition: `ADAPT_IN_RUST / P0`.

### 4.5 `TheHalfMoon/Kodac` — evidence relationship edges

Primary implementation:

```text
packages/kodac-runtime/src/verification/p5-evidence-relation.ts
schema/p5-evidence-relation.schema.json
```

Sentrdel use: provenance-rich `DerivedRelationshipRecord` and SSG evidence lineage without collapsing source identities.

Disposition: `ADAPT_IN_RUST / P0-P1`.

### 4.6 `TheHalfMoon/Kodac` — deterministic analyzer normalization

Primary implementation:

```text
packages/kodac-runtime/src/security/p6-deterministic-security-finding.ts
schema/p6-deterministic-security-finding.schema.json
```

Observed strengths:

- deterministic analyzer origin;
- static/dependency/secret/supply-chain/CI lanes;
- mandatory provenance binding;
- repository-relative safe locations;
- native record digest and fingerprint retained;
- defensive bounded JSON graph validation.

Required Sentrdel semantic correction:

```text
Kodac deterministic security finding
  -> Sentrdel ImportedSecurityObservation
  != Sentrdel canonical Finding
```

Only Sentrdel's reconciler owns canonical Finding creation.

Disposition: `ADAPT_IN_RUST / P0`.

### 4.7 `TheHalfMoon/Kodac` — sandbox backend evidence

Relevant family:

```text
packages/kodac-runtime/src/trust/sandbox-backend-evidence.ts
packages/kodac-runtime/src/trust/sandbox-workload.ts
packages/kodac-runtime/src/trust/sandbox-execution-approval-binding.ts
packages/kodac-runtime/src/trust/sandbox-admission-permit.ts
packages/kodac-runtime/src/trust/sandbox-lifecycle-gvisor-ttl-recovery.ts
packages/kodac-runtime/src/trust/sandbox-observer-gvisor-network-runtime.ts
packages/kodac-runtime/src/trust/sandbox-output-gvisor.ts
```

Kodac is especially useful for separating declared backend capability from observed containment, workload identity, approval binding, TTL recovery, and network/output evidence.

Preferred convergence: Golam supplies the cleaner Rust rights-narrowing core; Kodac supplies backend-attestation/lifecycle patterns.

Disposition: `PORT/ADAPT CANDIDATE / P1 for verification`.

### 4.8 `TheHalfMoon/Ascout` — verification receipt and no-green-by-omission

Primary implementation:

```text
src/receipt/model.ts
specs/001-changed-code-verification-receipt/data-model.md
```

Observed strengths:

- source start/end identities;
- exact changed surface;
- task authorization source, argv, tool/version, admission state;
- distinct `PASS`, `FAIL`, `FLAKY`, `BLOCKED`, `ERROR`, `NOT_APPLICABLE`, `NOT_RUN`;
- evidence/artifact hashes plus redaction/truncation facts;
- explicit stability and completeness;
- blocked/not-run/unresolved coverage cannot become green.

Sentrdel use:

```text
VerificationRunManifest
VerificationReceipt
external analyzer receipt
benchmark/conformance receipt
```

Disposition: `ADAPT_IN_RUST / P0`.

### 4.9 `TheHalfMoon/Signthos` — immutable input/content admission

High-value planning source:

```text
specs/004-local-pdf-core/source-informed-security-plan-amendment.md
```

Transferable rules:

- digest exact bytes before producer execution;
- declared identity and observed identity remain separate;
- prevent mutable-path/TOCTOU substitution;
- downstream providers must consume the same immutable bytes;
- derived artifacts receive new identities and never inherit parent trust;
- configured/executed/applicable/parsed/complete scanner states remain separate.

Sentrdel use: analyzer artifact admission, proof artifacts, CTI attachments, downloaded samples.

Disposition: `ADAPT_IN_RUST / P1`.

### 4.10 `TheHalfMoon/Himsat` — revisioned derived artifacts

Himsat planning repeatedly preserves provenance to source objects and revision history rather than destructively replacing derived state.

Sentrdel use: workbench revisions, analyst-edited intelligence projections, cases/investigations, derived relationship history.

Disposition: `RESEARCH_REFERENCE / P2`.

## 5. Existing Sentrdel-qualified source surfaces

### 5.1 Graphify — controlling Sentrdel qualification

Controlling record:

```text
docs/third-party/graphify-source-qualification.md
```

Qualified upstream:

```text
Graphify-Labs/graphify@b2cd36267456c166788c95be6e68574064a92a42
status = QUALIFIED_FOR_SELECTIVE_RUST_PORT
```

Exact qualified donor surfaces include:

- `graphify/analyze.py` for graph-diff semantics;
- `graphify/affected.py` for bounded reverse impact traversal;
- `graphify/validate.py` for validation/confidence vocabulary as concept-only;
- upstream tests as behavioral references.

Important existing Sentrdel corrections already frozen:

- provenance/confidence changes must not disappear inside endpoint-only graph identity;
- ambiguous/fuzzy seed selection cannot mint canonical identity;
- graph confidence cannot create FACT/VERIFIED;
- no Python/NetworkX/LLM/MCP/database runtime is admitted;
- the port stays inside `sentrdel-graph` and `UNIVERSAL_CPG = false` remains unchanged.

Disposition: `QUALIFIED_EXISTING / P0 where owning task is dependency-eligible`.

### 5.2 ast-grep-core / Tree-sitter — controlling Sentrdel dependency qualification

Controlling record:

```text
docs/third-party/ast-grep-tree-sitter-qualification.md
```

Qualified exact packages:

```text
ast-grep-core =0.45.2
tree-sitter =0.26.13
tree-sitter-javascript =0.25.0
```

Status:

```text
QUALIFIED_FOR_T039_ADMISSION_PENDING_LOCK_CLOSURE
```

The qualification admits only the bounded in-process Rust parser/matcher substrate and explicitly rejects broad grammar bundles, CLI execution, dynamic loading, remote grammar fetch, repository-selected executable behavior, or direct Finding authority.

Disposition: `QUALIFIED_EXISTING`; do not replace this with a weaker external research pin.

### 5.3 Strict JSON / SARIF adaptation substrate

Controlling record:

```text
docs/third-party/engine-adapter-dependency-qualification.md
```

Sentrdel already has an exact-pinned `serde` / `serde_json` boundary for bounded native JSON and SARIF decoding after a Sentrdel-owned structural preflight. Producer identity and trusted provenance remain runtime-owned rather than decoded from the untrusted engine output.

This means future SARIF work should extend the existing strict adapter philosophy rather than introduce an unrelated parser authority.

## 6. Existing Sentrdel-assessed external sources

### 6.1 OpenCTI

Current research pin:

```text
OpenCTI-Platform/opencti@c22668461981ac9602e8e16527ef613428c34c3c
```

Existing Sentrdel studies:

```text
docs/third-party/opencti-source-assessment-2026-09-16.md
docs/third-party/opencti-source-reuse-map-2026-09-16.md
specs/000-sentrdel-roadmap/opencti-intelligence-interoperability-2026-09-16.md
```

Preferred use:

- STIX 2.1/TAXII protocol handling;
- connector lifecycle and service identity patterns;
- Intake Workbench;
- Investigation Workspace / Security Case patterns;
- markings/access filtering;
- filtered streaming/data sharing;
- selective Community Edition source reuse after exact file qualification.

Do not adopt the entire OpenCTI Node/Python/server topology into Sentrdel's local Rust core.

Disposition: `PROTOCOL_REFERENCE + SELECTIVE_SOURCE_CANDIDATE / P1`.

### 6.2 Tencent AI-Infra-Guard

Controlling Sentrdel assessment:

```text
docs/third-party/source-candidate-assessment-2026-09-08.md
Tencent/AI-Infra-Guard@e4e622af3ad2b8228ce82dd62b01415dd8ce2b9c
```

Use for Agent/MCP/Skill threat taxonomy, deterministic pre-scan, smuggling/hidden executable cases, tool poisoning/shadowing, SARIF fixtures, and conformance.

Disposition: `HIGH_PRIORITY_TAXONOMY_AND_CONFORMANCE_REFERENCE` now; optional external producer only after the appropriate import/verification contracts exist.

### 6.3 Tencent AICGSecEval

Controlling Sentrdel assessment pin:

```text
Tencent/AICGSecEval@94428ebf45141bf4ecd365a51d596dcd51caa690
```

Use for SentrdelBench methodology around known vulnerable/fixed repository pairs, functional controls, static/dynamic security evidence separation, CVE/CWE metadata, checkpoints, and evaluator independence.

Disposition: `HIGH_PRIORITY_BENCHMARK_METHODOLOGY_REFERENCE`.

### 6.4 Google Magika

Controlling Sentrdel assessment pin:

```text
google/magika@26b6a9ba7e92f2b0a3745970a9190ec0dde9bf83
```

Use only as an optional content/routing inference signal if benchmarks prove incremental value. Model output remains INFERENCE and may not suppress an otherwise applicable analyzer.

Disposition: `HIGH_PRIORITY_OPTIONAL_ARTIFACT_CLASSIFIER_CANDIDATE`, but lower priority than deterministic authority/evidence work.

## 7. Source discoveries imported from other founder repositories

The following are valuable because another founder repository already performed source reconnaissance. These pins are **research inputs only** until Sentrdel re-pins and qualifies them.

### 7.1 WePLD source acquisition registry

WePLD recorded exact research pins for:

```text
vitali87/code-graph-rag@79abdb5fdbcde6d138db071efbe61e9afc16f63d
microsoft/agent-governance-toolkit@b5705588883fac48b88cbe6fd0bd7d48c798453e
cedar-policy/cedar@ba579ee7e9d63afa73a5b59be0d338a404c6108b
openai/codex@339751715c64496cb86246bfb3935f40e309dd3d
deepseek-ai/deepseek-harness@b150a551b8d465e31e418e1b2eaf5e79bbb7d28e
bytedance/trae-agent@e839e559ac61bdd0e057c375dd1dee391fee797d
```

It also queues SCIP, Joern, OpenGrep, OPA, OpenSandbox, E2B, gVisor, Firecracker, in-toto, SLSA and OpenTelemetry.

Note: WePLD also recorded a Graphify pin, but Sentrdel's existing GQ-001 qualification controls instead.

### 7.2 Golam donor/source research

Golam's donor register identifies additional candidates including Cedar, Wasmtime, Graphify/code-graph-rag, Restate/Temporal and governed-memory systems. Golam's Tencent study also records:

```text
Tencent/WeKnora@647848f3954dae34473b8a8d0e0eef5e0fb3a58e
Tencent/RoMem@39ac1417b4db41ea729e5c3be71ac20de54da993
Tencent/SkillHone@7d565839fb4dc74f9c77f09ace660e1c0484e048
Tencent/LoopForge@09c765286f549624dd95434e1e6ef2249657cbeb
```

Most are not priority Sentrdel code donors. Their strongest Sentrdel value is workbench/revision UX, resumable execution, evaluation separation, and non-destructive provenance patterns.

### 7.3 Kodac analyzer and Cyber-method research

Kodac recorded research pins for:

```text
Team-Atlanta/atlantis-java@943c07bd08db5b3eeed6dace3a7c0ee1659ceab7
o2lab/FuzzingBrain-V2@0281e0bc5348dddb6e4cdb4824f79ae5a60d1de3
protectai/vulnhuntr@ead88c5adba4279dae5c56d65124c530a9a1c5ae
ossf/oss-crs@0061473c1afd37c93a00483e0aebc704b4897609
github/codeql@05c40eafe6fb4cc88c764703a855714c281bf1e1
semgrep/semgrep@3f58c662ec05a8dbb67d4779cfbca1be8396d738
google/osv-scanner@c84fa4568f2526d0333e9a914ea8a0a5f74ad68b
aquasecurity/trivy@dcbadb7b15076c405ce7d59f04cde9991b90da22
anchore/syft@360dbc04aa20b74a3f3ac19d30ee85bda0c076cc
anchore/grype@ffbca561d576c584b621f5421616337cad013d90
gitleaks/gitleaks@b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b
ossf/scorecard@d1fab88f54636ff366076edfc5c239f97b3c8e66
facebook/infer@e327d4468c5d5e0984043096ee844944320e9ca1
```

These are not Sentrdel admission pins. Their value is to avoid reinventing mature evidence producers.

## 8. Recommended external analyzer fabric

Future External Evidence Import work should preserve native evidence and add Sentrdel-owned provenance/coverage rather than flattening tools into a generic severity object.

Target shape:

```text
native producer artifact
+ exact producer/version/config
+ exact target identity
+ raw artifact digest
+ invocation/environment receipt
+ parse/schema validity
+ applicability + coverage
        -> bounded Sentrdel normalization
        -> imported Evidence/Coverage
        -> reconciler-controlled canonical Finding semantics
```

Suggested technical evaluation order after the owning Spec Kit becomes eligible:

1. SARIF transport/profile using the existing strict engine-adapter philosophy;
2. OSV-compatible advisories/vulnerability records;
3. Syft CycloneDX/SPDX SBOM;
4. Grype/Trivy dependency vulnerability output;
5. Gitleaks secret-candidate output;
6. OpenGrep/Semgrep structured static/taint output;
7. user-supplied CodeQL output;
8. Scorecard supply-chain posture as context;
9. Joern/Infer deep analysis only when measured value justifies heavier execution.

## 9. Graph and semantic enrichment

Existing Sentrdel state changes the priority substantially:

- Graphify selective Rust-port qualification already exists — use it when its owning task is eligible.
- Tree-sitter/ast-grep-core qualification already exists for the native structural producer path.
- SCIP remains a useful future symbol/reference evidence candidate.
- `code-graph-rag` can be evaluated for additional dataflow/context behavior, but only if it proves value beyond Sentrdel's already-qualified native/Graphify substrate.
- Joern is best treated as an out-of-process deep dataflow/taint/reachability producer, not as the SSG authority.

Hard rule:

```text
external graph confidence
  != stable semantic identity authority
  != canonical Finding authority
```

## 10. Verification containment candidates

Use a Sentrdel-owned authorization/rights contract above any backend:

```text
VerificationAuthorization
  -> ToolCapabilityManifest
  -> Sentrdel rights descriptor
  -> qualified backend adapter
  -> observed containment evidence
  -> VerificationReceipt
```

Candidate backends from founder research include OpenSandbox, gVisor, Firecracker and Wasmtime. E2B may remain optional where a remote sandbox is explicitly allowed, but local-first core verification must not depend on it.

No sandbox backend becomes an authority root.

## 11. Agent/MCP/extension security

High-value sources:

- AI-Infra-Guard for deterministic/static pre-scan and modern Skill/MCP/agent threat classes;
- AICGSecEval for repository-level security-evaluation methodology;
- HackAgent for generator/judge/target role separation;
- synthetic Sentrdel-authored adversarial fixtures for stable conformance.

Dynamic attacks remain a later bounded verification profile. An LLM judge remains inference unless deterministic or execution-grounded evidence separately upgrades the claim.

## 12. Standards-first runtime and provenance bridge

Prefer mature protocols instead of inventing Sentrdel-only transport formats:

- OpenTelemetry/OTLP for runtime traces/logs/metrics where applicable;
- in-toto/SLSA for build/deployment provenance and attestations;
- Sentry-compatible/GlitchTip patterns for error/release/environment correlation where useful;
- STIX/TAXII for external threat intelligence interoperability.

Imported protocol records remain observations until Sentrdel-owned validation/reconciliation gives them a permitted role.

## 13. Convergence packages

These are planning packages, not implementation authority.

### SM-1 — Evidence and provenance kernel — P0

Mine/adapt:

- Kodac evidence provenance + relation;
- Ascout receipt/completeness semantics;
- Golam authenticated protected-state audit.

Target:

```text
ExternalEvidenceEnvelope
ProofArtifactReference
DerivedRelationshipRecord
VerificationReceipt
AuthorityStateAuditRecord
```

### SM-2 — Verification authority and containment — P0/P1

Mine/adapt:

- Golam leases/approvals and sandbox rights narrowing;
- Kodac backend-attestation/lifecycle patterns;
- Cedar/agent-governance conformance concepts;
- qualified sandbox adapters.

Target:

```text
VerificationAuthorization
ToolCapabilityManifest
VerificationRunManifest
SandboxEnforcementDescriptor
IntegrationServiceIdentity
EgressPermit
```

### SM-3 — Intelligence interoperability and analyst workspace — P1

Mine/adapt:

- OpenCTI STIX/TAXII/connectors/workbench/investigations/markings/streams;
- Himsat revisioned derived-artifact provenance.

Target:

```text
ExternalIntelligenceEnvelope
IntakeWorkbench
InvestigationWorkspace
SecurityCase
DataHandlingMarking
SecurityEventStreamSubscription
```

### SM-4 — External analyzer fabric — P1/P2

Use bounded adapters around OSV/Syft/Grype/Trivy/Gitleaks/OpenGrep/Semgrep/CodeQL and later heavier analyzers.

### SM-5 — SSG enrichment — existing qualifications first

Use existing Graphify + Tree-sitter/ast-grep qualification before adding a second graph/parser stack. Evaluate SCIP/Joern/code-graph-rag only for measured incremental value.

### SM-6 — Agent/MCP security conformance — P2

Use AI-Infra-Guard, AICGSecEval, HackAgent and Sentrdel-owned fixtures without importing a mandatory model runtime.

### SM-7 — Runtime evidence and attestations — P2

Use OpenTelemetry, in-toto/SLSA and deployment/release identity after the core static/import contracts stabilize.

## 14. What should not be copied wholesale

Permission to reuse code does not make whole-platform adoption technically desirable.

Do not wholesale import:

- OpenCTI's complete server/dependency topology;
- Golam's whole agent OS;
- Kodac's complete TypeScript runtime;
- Ascout's complete verification CLI;
- autonomous exploitation loops from pentest/CRS systems;
- a mandatory graph database;
- a mandatory LLM/provider runtime;
- a mandatory hosted sandbox/control plane;
- a second Finding authority;
- a second policy authority able to bypass Sentrdel hard guards.

Prefer exact validators, contracts, algorithms, adapters and adversarial tests.

## 15. Non-negotiable authority rules

```text
External scanner result != canonical Finding
External graph relationship != semantic identity authority
CTI confidence != Evidence authority
LLM judge != VERIFIED
Sandbox success != authorization
Policy-engine ALLOW != hard-guard bypass
Zero findings != clean when execution/applicability/coverage is incomplete
Process exit 0 != sufficient proof artifact
Founder permission != source admitted
Research pin != current admission pin
Planning source map != implementation authority
```

## 16. Priority order

```text
P0  Use Sentrdel's existing qualifications first:
    Graphify selective Rust port
    ast-grep-core / Tree-sitter substrate
    strict bounded JSON/SARIF adapter philosophy

P0  Mine founder-owned primitives:
    Golam authority/sandbox
    Kodac evidence provenance/relation/analyzer normalization
    Ascout receipt/completeness semantics

P1  Interoperability:
    OpenCTI Community-qualified paths
    STIX/TAXII
    later OpenTelemetry + in-toto/SLSA

P1  External evidence producers:
    OSV/Syft/Grype/Trivy/Gitleaks/OpenGrep-Semgrep

P2  Deep semantics:
    SCIP/Joern
    code-graph-rag only if incremental value is proven

P2  Verification/conformance:
    AI-Infra-Guard/AICGSecEval/HackAgent
    OSS-CRS/Atlantis/FuzzingBrain/Vulnhuntr as method/lifecycle references

P3  Optional probabilistic observations:
    Magika and similar classifiers
```

## 17. Immediate repository action

While S1 remains active:

1. keep PR #330 / S1-T011 isolated;
2. keep this source-mining work docs/research-only in PR #332;
3. do not import donor code into the active S1 branch because of this study;
4. when a successor slice becomes dependency-eligible, start with the smallest exact source paths needed;
5. refresh external research pins at admission time;
6. preserve all applicable license/NOTICE/attribution/third-party obligations even where founder permission is recorded;
7. benchmark every added engine or semantic layer against Sentrdel's deterministic Evidence/Coverage/invariant-regression moat before keeping it.
