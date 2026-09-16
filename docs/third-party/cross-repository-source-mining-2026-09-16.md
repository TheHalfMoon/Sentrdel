# Cross-Repository Source Mining for Sentrdel — 2026-09-16

**Status:** RESEARCH / SOURCE-QUALIFICATION INPUT ONLY  
**Planning branch:** `docs/security-control-plane-2026-09-12`  
**Active implementation authority:** `specs/004-security-invariant-regression/` only  
**Founder permission context:** `docs/third-party/founder-source-reuse-attestation-2026-09-16-github-source-universe.md`  
**OpenCTI study:** `docs/third-party/opencti-source-assessment-2026-09-16.md` and `opencti-source-reuse-map-2026-09-16.md`  

## 1. Purpose

This study mines the founder's connected GitHub source universe for code, contracts, benchmarks, and architecture patterns that can materially improve Sentrdel.

The objective is **not** to merge projects or copy complete applications into Sentrdel. The objective is to identify the smallest proven mechanisms that strengthen Sentrdel's durable moat:

> deterministic security-invariant regression + bounded Evidence/Coverage + provenance + controlled verification + external intelligence context + runtime evidence, while Sentrdel remains the judgment authority.

The current S1 task order is unchanged. Nothing in this document authorizes implementation ahead of the active Spec Kit frontier.

## 2. Headline conclusion

The most valuable source material is already distributed across the founder's repositories:

```text
Golam
  -> authority integrity, capability leases, approvals, taint, egress and sandbox rights narrowing

Kodac
  -> exact evidence provenance, evidence relations, deterministic analyzer normalization,
     sandbox attestation/admission, verification receipts

Ascout
  -> source-bound verification receipts, completeness/no-green-by-omission,
     security evidence adapter semantics and benchmark methodology

OpenCTI
  -> STIX/TAXII interoperability, connectors, workbench, investigations/cases,
     markings, service identities and filtered streams

Signthos
  -> immutable-byte/content-identity admission, TOCTOU resistance,
     derived-artifact quarantine and scanner-state separation

WePLD
  -> a high-quality source acquisition registry for graph, policy, sandbox,
     attestation, agent-runtime and security-oracle candidates

Himsat
  -> revisioned derived artifacts and non-destructive provenance/history patterns
```

The strongest Sentrdel direction is therefore **selective convergence**, not another greenfield rewrite.

## 3. Reuse classification

This study uses the following dispositions:

- `PORT_CANDIDATE` — existing founder-owned implementation is close enough to justify selective code porting after exact source qualification.
- `ADAPT_IN_RUST` — preserve semantics/tests but implement inside Sentrdel's Rust contracts rather than importing the original runtime stack.
- `OUT_OF_PROCESS_ADAPTER` — keep the producer/tool outside Sentrdel's trusted core and import bounded evidence.
- `PROTOCOL_REFERENCE` — use the protocol/interchange design while Sentrdel owns implementation and authority.
- `BENCHMARK_REFERENCE` — use test/evaluation methodology or fixtures only after provenance qualification.
- `RESEARCH_REFERENCE` — valuable ideas; no current code-intake case.

## 4. Tier 0 — founder-owned code with direct Sentrdel reuse value

### 4.1 `TheHalfMoon/Golam` — authority-security ledger

High-value implementation:

```text
crates/golam-ledger/src/authority_security_v2.rs
```

Observed properties:

- `#![forbid(unsafe_code)]`;
- protected source kinds include principals, policy bundles, active policy, capability leases/revocations, approvals/consumption, taint attestations, verifier rules, secrets, egress permits, sandbox profiles/admissions and authorization decisions;
- deterministic canonical payload encoding;
- BLAKE3 payload and hash-chain integrity;
- contiguous audit sequence validation;
- latest authenticated snapshot must exactly match every current protected source;
- missing authenticated coverage fails visible;
- stale authenticated records with no current source fail integrity validation.

Sentrdel fit:

- future control-plane integrity ledger;
- `VerificationAuthorization` validation provenance;
- `IntegrationServiceIdentity` / policy / marking / automation authority mutation audit;
- signed/versioned Security Pack activation history;
- tamper-evident operational authority state.

Disposition:

```text
PORT_CANDIDATE / VERY_HIGH_PRIORITY
```

Do not port the Golam schema wholesale. Port the **authenticated protected-state snapshot + chain verification pattern** behind Sentrdel-owned types.

### 4.2 `TheHalfMoon/Golam` — sandbox rights narrowing

High-value implementation:

```text
crates/golam-ledger/src/sandbox_enforcement.rs
```

Observed properties:

- deny-all request constructor;
- exact allowlisted filesystem read/write roots;
- explicit environment allowlist with cleared-environment semantics;
- monotonic network authority (`None`, loopback, permit-bound external);
- monotonic process spawn authority;
- resource limits only narrow, never widen;
- device, IPC and inherited-handle allowlists;
- bounded request cardinality;
- deterministic descriptor hash bound to source launch-plan hash;
- explicit non-claim that a rights descriptor alone proves platform containment.

Sentrdel fit:

- R6 verification isolation;
- `ToolCapabilityManifest` enforcement;
- exact `VerificationRunManifest` launch authority;
- separate authorization from actual platform containment proof;
- fail-closed sandbox provider adapters.

Disposition:

```text
PORT_CANDIDATE / VERY_HIGH_PRIORITY
```

### 4.3 `TheHalfMoon/Golam` — capability leases and one-shot approvals

High-value implementation:

```text
crates/golam-kernel/src/capability_lease_effect.rs
specs/003-identity-policy-secrets-sandbox/contracts/egress-sandbox-contract.md
```

Observed properties:

- authorization required before capability-lease mutation;
- effect payload hash binding;
- explicit proposed -> authorized state transition;
- at-most-once execution semantics;
- one-shot approval scope bound to exact effect/action/resource;
- parent authority and expiry concepts;
- egress authority is explicit rather than ambient.

Sentrdel fit:

- verification authorization delegation;
- short-lived service identities/connectors;
- one-shot mutation/verification approvals;
- explicit egress permits for optional external producers;
- preventing a connector or automation rule from minting broader authority.

Disposition:

```text
ADAPT_IN_RUST / HIGH_PRIORITY
```

Sentrdel should preserve the semantics but use its own authority names and lifecycle.

### 4.4 `TheHalfMoon/Kodac` — exact evidence provenance binding

High-value implementation:

```text
packages/kodac-runtime/src/verification/p5-evidence-provenance.ts
schema/p5-evidence-provenance.schema.json
```

Observed binding dimensions:

```text
source kind / evidence identity / source ref / source digest
repository identity / canonical base / candidate head
producer identity / version / configuration identity
policy identity
scope identity
input identity
environment identity
freshness state + basis identity
canonical semantic binding identity
```

Validation is strict about object shape, bounded text, Unicode scalars, immutable revision identities and digest formats.

Sentrdel fit:

- future `ExternalEvidenceEnvelope`;
- runtime evidence bridge;
- CTI import provenance;
- verification proof artifacts;
- preserving freshness independently of producer confidence/severity;
- preventing stale producer output from silently supporting a current verdict.

Disposition:

```text
ADAPT_IN_RUST / VERY_HIGH_PRIORITY
```

The semantic field set is highly reusable even though the TypeScript implementation should not become a required runtime dependency.

### 4.5 `TheHalfMoon/Kodac` — evidence relation edges

High-value implementation:

```text
packages/kodac-runtime/src/verification/p5-evidence-relation.ts
schema/p5-evidence-relation.schema.json
```

Sentrdel fit:

- `DerivedRelationshipRecord`;
- SSG evidence lineage;
- imported CTI relationship derivation;
- explicit `supports`, `contradicts`, `derived-from`, `reproduces`, or equivalent typed edges without collapsing underlying evidence identities.

Disposition:

```text
ADAPT_IN_RUST / HIGH_PRIORITY
```

### 4.6 `TheHalfMoon/Kodac` — deterministic analyzer finding normalization

High-value implementation:

```text
packages/kodac-runtime/src/security/p6-deterministic-security-finding.ts
schema/p6-deterministic-security-finding.schema.json
```

Observed strengths:

- explicit deterministic analyzer origin;
- lanes for static analysis, dependency analysis, secret detection, supply-chain provenance and CI workflow integrity;
- provenance binding is mandatory;
- repository-relative path validation;
- bounded/canonical references;
- native record digest and fingerprint are retained;
- defensive JSON-data validation rejects proxies, accessors, cycles, sparse/extra-property arrays, unbounded depth/container counts and non-finite values.

Sentrdel fit:

- External Evidence Import Protocol;
- safe normalization of SARIF/native analyzer records;
- preserving native artifacts/fingerprints without granting them Finding authority.

Critical correction for Sentrdel:

```text
KODAC_DETERMINISTIC_SECURITY_FINDING
  -> SENTRDEL_IMPORTED_SECURITY_OBSERVATION
  != SENTRDEL_CANONICAL_FINDING
```

Only the Sentrdel reconciler may create canonical Findings.

Disposition:

```text
ADAPT_IN_RUST / VERY_HIGH_PRIORITY
```

### 4.7 `TheHalfMoon/Kodac` — sandbox attestation and approval binding

High-value implementation family:

```text
packages/kodac-runtime/src/trust/sandbox-backend-evidence.ts
packages/kodac-runtime/src/trust/sandbox-workload.ts
packages/kodac-runtime/src/trust/sandbox-execution-approval-binding.ts
packages/kodac-runtime/src/trust/sandbox-admission-permit.ts
packages/kodac-runtime/src/trust/sandbox-lifecycle-gvisor-ttl-recovery.ts
packages/kodac-runtime/src/trust/sandbox-observer-gvisor-network-runtime.ts
packages/kodac-runtime/src/trust/sandbox-output-gvisor.ts
```

Sentrdel fit:

- separate declared sandbox capability from observed containment evidence;
- workload identity/attestation;
- approval binding to exact runtime requirement;
- lifecycle/TTL cleanup and recovery;
- network/output containment evidence.

Disposition:

```text
PATTERN_PORT_CANDIDATE / HIGH_PRIORITY_FOR_R6
```

Golam supplies the cleaner Rust rights-narrowing core; Kodac supplies broader backend-attestation and lifecycle evidence patterns. They should be combined, not duplicated.

### 4.8 `TheHalfMoon/Ascout` — verification receipt model

High-value implementation:

```text
src/receipt/model.ts
specs/001-changed-code-verification-receipt/data-model.md
```

Observed strengths:

- source start/end identity;
- exact changed surface;
- task authorization source;
- argv/tool/version and admission state;
- execution status distinguishes PASS/FAIL/FLAKY/BLOCKED/ERROR/NOT_APPLICABLE/NOT_RUN;
- evidence and artifact identities with hashes/redaction/truncation facts;
- explicit stability and completeness;
- no-green-by-omission: blocked/not-run/unresolved exercise can make the receipt materially incomplete;
- errors/tree drift have distinct exit semantics.

Sentrdel fit:

- `VerificationRunManifest` + final verification receipt;
- external analyzer execution receipts;
- runtime/benchmark/conformance evidence;
- explicit distinction between `NO_FINDINGS`, `NOT_RUN`, `ERROR`, `BLOCKED`, `NOT_APPLICABLE`, and incomplete coverage.

Disposition:

```text
ADAPT_IN_RUST / VERY_HIGH_PRIORITY
```

### 4.9 `TheHalfMoon/Ascout` — security evidence research

High-value research artifact:

```text
docs/strategy/SECURITY_VERIFICATION_SOURCE_STUDY.md
```

It already identifies three high-value upstreams:

- `Tencent/AICGSecEval`;
- `Tencent/AI-Infra-Guard`;
- `google/magika`.

It also freezes a useful security-adapter rule:

```text
ZERO_FINDINGS != CLEAN
```

unless execution, output parse/schema, applicability and scope are all proven.

Disposition:

```text
RESEARCH_REFERENCE / VERY_HIGH_PRIORITY
```

### 4.10 `TheHalfMoon/Signthos` — immutable content identity/admission

High-value research artifact:

```text
specs/004-local-pdf-core/source-informed-security-plan-amendment.md
```

Transferable patterns:

- digest exact bytes before producer execution;
- preserve declared identity separately from observed identity;
- prevent TOCTOU path substitution;
- downstream providers must inspect the same immutable bytes;
- derived/extracted artifacts receive new identities and do not inherit parent trust;
- parser/classifier/scanner success is one evidence component, never universal safety;
- scanner configured/executed/applicable/parsed/complete states remain separate.

Sentrdel fit:

- imported analyzer artifact admission;
- downloaded CTI attachments/samples;
- verification proof artifacts;
- future file/content evidence before external engines consume data.

Disposition:

```text
ADAPT_IN_RUST / MEDIUM_HIGH_PRIORITY
```

### 4.11 `TheHalfMoon/wepld` — source acquisition registry

High-value artifact:

```text
specs/003-agent-control-plane-architecture-enrichment/source-acquisition.md
```

This repository already recorded reproducible research pins for several sources highly relevant to Sentrdel:

```text
vitali87/code-graph-rag@79abdb5fdbcde6d138db071efbe61e9afc16f63d
Graphify-Labs/graphify@91f4d120b630ee35c79bf3c75ccd186870a808f9
microsoft/agent-governance-toolkit@b5705588883fac48b88cbe6fd0bd7d48c798453e
cedar-policy/cedar@ba579ee7e9d63afa73a5b59be0d338a404c6108b
openai/codex@339751715c64496cb86246bfb3935f40e309dd3d
deepseek-ai/deepseek-harness@b150a551b8d465e31e418e1b2eaf5e79bbb7d28e
bytedance/trae-agent@e839e559ac61bdd0e057c375dd1dee391fee797d
```

The same source registry queues Tree-sitter, SCIP, ast-grep, Joern, OpenGrep, OPA, OpenSandbox, E2B, gVisor, Firecracker, in-toto, SLSA and OpenTelemetry for capability-triggered mining.

Disposition:

```text
SOURCE_DISCOVERY_AUTHORITY=HIGH_VALUE_RESEARCH_INPUT
```

Pins remain research identities and must be refreshed before Sentrdel admission.

### 4.12 `TheHalfMoon/Himsat` — revisioned derived-artifact provenance

Useful planning patterns in Himsat require derived objects to retain provenance to source objects and preserve revision history rather than destructively replacing materialized state.

Sentrdel fit:

- Intake Workbench revisions;
- analyst-edited CTI projections;
- derived intelligence relationships;
- case/investigation notes;
- imported/normalized artifact lineage.

Disposition:

```text
RESEARCH_REFERENCE / MEDIUM_PRIORITY
```

## 5. Tier 1 — external sources already present in the founder's GitHub research universe

### 5.1 OpenCTI — intelligence interoperability and analyst workflow

Research pin already established in the Sentrdel study:

```text
OpenCTI-Platform/opencti@c22668461981ac9602e8e16527ef613428c34c3c
```

Use for:

- STIX 2.1/TAXII;
- connector lifecycle;
- workbench staging;
- investigations/cases;
- markings/access filtering;
- streaming/data sharing;
- service identities;
- selective Community Edition source reuse after exact file qualification.

Do **not** adopt OpenCTI's entire Node/Python/Elastic/Redis/RabbitMQ stack into Sentrdel core.

### 5.2 Tencent AI-Infra-Guard — agent/MCP/Skill security evidence

Existing research pin:

```text
Tencent/AI-Infra-Guard@e4e622af3ad2b8228ce82dd62b01415dd8ce2b9c
```

Use for:

- deterministic pre-scan before model-mediated audit;
- Skill/MCP/agent threat taxonomy;
- encoding/smuggling and hidden-executable checks;
- tool poisoning/shadowing/rug-pull risk;
- SARIF 2.1.0 transport;
- agent-security conformance fixtures.

Preferred Sentrdel role:

```text
OUT_OF_PROCESS_ADAPTER + BENCHMARK_REFERENCE
```

### 5.3 Tencent AICGSecEval — security regression benchmark methodology

Existing research pin:

```text
Tencent/AICGSecEval@94428ebf45141bf4ecd365a51d596dcd51caa690
```

Use for SentrdelBench methodology:

```text
known vulnerable base
known fixed/patch revision
functional control
static security signal
dynamic/PoC oracle where separately authorized
CVE/CWE metadata
build/container/environment evidence
```

This is a strong candidate for proving that Sentrdel's regression engine detects a weakening/fix without conflating build failure, scanner failure and security truth.

Preferred role:

```text
BENCHMARK_REFERENCE
```

### 5.4 Google Magika — optional content-identity evidence

Existing research pin:

```text
google/magika@26b6a9ba7e92f2b0a3745970a9190ec0dde9bf83
```

Use only where content identity materially improves artifact admission. A classifier label/confidence is producer metadata, not security truth.

Preferred role:

```text
OPTIONAL_OUT_OF_PROCESS_OR_LIBRARY_OBSERVER / LOWER_PRIORITY
```

### 5.5 Graphify + code-graph-rag — optional SSG enrichment

Existing research pins from WePLD:

```text
Graphify-Labs/graphify@91f4d120b630ee35c79bf3c75ccd186870a808f9
vitali87/code-graph-rag@79abdb5fdbcde6d138db071efbe61e9afc16f63d
```

Use for:

- deeper source relationship extraction;
- graph/dataflow exploration;
- context retrieval;
- candidate SSG enrichment and analyst investigation.

Guardrail:

```text
EXTERNAL_GRAPH_CONFIDENCE != IDENTITY_AUTHORITY != FINDING_AUTHORITY
```

Preferred role:

```text
OPTIONAL_ADAPTER / SELECTIVE_PORT_AFTER_BENCHMARK
```

### 5.6 Microsoft Agent Governance Toolkit + Cedar

Research pins from WePLD:

```text
microsoft/agent-governance-toolkit@b5705588883fac48b88cbe6fd0bd7d48c798453e
cedar-policy/cedar@ba579ee7e9d63afa73a5b59be0d338a404c6108b
```

Potential use:

- agent/action policy schema and conformance ideas;
- authorization evaluation;
- policy-bundle versioning;
- deny-by-default policy errors;
- test/conformance corpus for `VerificationAuthorization`, connectors and automation rules.

Preferred role:

```text
PROTOCOL_REFERENCE first
CEDAR_OPTIONAL_EVALUATOR only after measured need
```

Sentrdel hard guards must remain owned by Sentrdel; a policy engine cannot authorize its own activation or widen immutable safety constraints.

### 5.7 OpenSandbox / gVisor / Firecracker / Wasmtime — containment backends

Existing founder-repo research already identifies these as candidates for isolated execution.

Use for:

- separately authorized verification workers;
- disposable analyzer execution;
- deterministic workload/rights descriptors;
- platform containment qualification;
- synthetic credentials and denied production secrets.

Preferred architecture:

```text
Sentrdel Verification Authorization
        -> Sentrdel-owned rights descriptor
        -> qualified sandbox adapter
        -> observed containment evidence
        -> verification receipt
```

No sandbox provider becomes an authority root.

### 5.8 Tree-sitter / SCIP / ast-grep / Joern / OpenGrep

Use for layered SSG/analyzer enrichment:

- Tree-sitter: bounded syntax extraction;
- SCIP: symbol/reference identity when available;
- ast-grep: structured pattern extraction;
- Joern: CPG/dataflow/taint/reachability evidence;
- OpenGrep: pattern/taint analyzer evidence.

Preferred role:

```text
native/lightweight parsers where justified
heavy analyzers out-of-process
```

No external analyzer can independently mint canonical Findings.

### 5.9 in-toto / SLSA / OpenTelemetry

Use for:

- evidence/attestation export;
- build/deployment provenance;
- runtime trace/log/metric correlation;
- interoperable operational evidence bridge.

Preferred role:

```text
PROTOCOL_REFERENCE + OPTIONAL ADAPTERS
```

This is stronger than inventing a Sentrdel-only telemetry or supply-chain envelope when mature standards already exist.

## 6. Tier 2 — mature analyzer/provider fabric discovered in Kodac research

Kodac's cyber/analyzer study records exact research pins for a strong external evidence fabric:

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

These are **research pins**, not Sentrdel admission pins.

### Analyzer fabric rule

Sentrdel should prefer mature producers over rebuilding every scanner:

```text
Native analyzer result
  + exact producer/version/config
  + exact target identity
  + raw artifact digest
  + invocation/environment receipt
  + applicability/coverage state
        -> bounded Sentrdel normalization
        -> imported Evidence/Coverage
        -> reconciler-controlled canonical Finding semantics
```

Native evidence must remain attached. Normalization is never evidence promotion.

### High-priority producer order

For early External Evidence Import work, evaluate in roughly this technical order after the owning Spec Kit activates:

1. SARIF transport contract;
2. OSV-compatible vulnerability/advisory records;
3. Syft CycloneDX/SPDX SBOM;
4. Grype/Trivy dependency vulnerability output;
5. Gitleaks secret-candidate output;
6. OpenGrep/Semgrep static/taint findings;
7. user-supplied CodeQL SARIF/database-derived result import;
8. Scorecard supply-chain posture as context;
9. Joern/Infer deep analysis where measured value justifies heavier execution.

## 7. Tier 3 — future high-assurance verification method providers

### 7.1 OSS-CRS

Best reference for provider-neutral isolated Cyber Reasoning System execution and artifact exchange.

Useful pattern:

```text
method provider submits artifact
provider cannot directly mutate trusted evidence state
closed Sentrdel validator verifies artifact
```

### 7.2 Atlantis-Java

Useful for shared target/sink state across multiple methods: static/dataflow, concolic, fuzzing, semantic generation and PoV stages.

Sentrdel adaptation should route method artifacts without allowing an external method to promote its own reachability/verdict state.

### 7.3 FuzzingBrain V2

Most useful as a **negative architecture oracle**: experiment lifetime must not be owned by the requesting model worker. Long-running verification/fuzzing needs an independent durable experiment lifecycle and artifact finalization before cleanup.

### 7.4 Vulnhuntr

Useful for progressive context retrieval:

```text
small suspicious surface
  -> hypothesis
  -> explicit symbol/context request
  -> deterministic resolver
  -> next analysis turn
```

Model output remains candidate analysis. Required library/framework semantics must come from qualified source/docs/analyzers rather than model memory.

## 8. Recommended Sentrdel convergence packages

These packages are **planning groupings**, not implementation authorization.

### SM-1 — Evidence and provenance kernel

Mine/adapt:

- Kodac P5 provenance + evidence relation;
- Ascout receipt completeness/artifact identity;
- Golam authenticated authority-state audit pattern.

Target Sentrdel concepts:

```text
ExternalEvidenceEnvelope
ProofArtifactReference
DerivedRelationshipRecord
VerificationReceipt
AuthorityStateAuditRecord
```

Priority: **P0**.

### SM-2 — Verification authority and containment

Mine/adapt:

- Golam capability leases/one-shot approvals;
- Golam sandbox rights narrowing;
- Kodac sandbox backend evidence/admission/TTL;
- Cedar/agent-governance conformance ideas;
- OpenSandbox/gVisor/Firecracker/Wasmtime adapters.

Target concepts:

```text
VerificationAuthorization
ToolCapabilityManifest
VerificationRunManifest
SandboxEnforcementDescriptor
IntegrationServiceIdentity
EgressPermit
```

Priority: **P0 after dependency-eligible verification planning**.

### SM-3 — Intelligence interoperability and analyst workspace

Mine/adapt:

- OpenCTI STIX/TAXII conversion and connector patterns;
- OpenCTI Workbench/Investigation/stream/marking patterns;
- Himsat revisioned derived-artifact provenance.

Target concepts:

```text
ExternalIntelligenceEnvelope
IntakeWorkbench
InvestigationWorkspace
SecurityCase
DataHandlingMarking
SecurityEventStreamSubscription
```

Priority: **P1 after current regression/productization sequence permits it**.

### SM-4 — External analyzer fabric

Use adapters for:

- OSV/Syft/Grype/Trivy;
- Gitleaks;
- OpenGrep/Semgrep;
- CodeQL;
- Scorecard;
- Joern/Infer where useful.

Target:

```text
External Evidence Import Protocol
```

Priority: **P1/P2**, source by source, measured against SentrdelBench.

### SM-5 — SSG semantic enrichment

Evaluate:

- Tree-sitter;
- SCIP;
- ast-grep;
- Joern;
- Graphify;
- code-graph-rag.

Priority: **benchmark-driven only**. Do not create a second mandatory graph runtime.

### SM-6 — Agent/MCP/extension security

Use:

- AI-Infra-Guard;
- AICGSecEval;
- HackAgent;
- SentrdelBench synthetic adversarial fixtures.

Target:

```text
Agent Security Verification Profile
Extension Security Admission
Conformance suites
```

Priority: **later verification/conformance phase**.

### SM-7 — Runtime evidence and attestations

Use:

- OpenTelemetry;
- in-toto;
- SLSA;
- Sentry-compatible/GlitchTip patterns;
- deployment/release identity.

Target:

```text
Operational Evidence Bridge
DeploymentIdentity
RuntimeObservation
Build/Deployment Attestation Import
```

Priority: **after static regression semantics and external evidence contracts stabilize**.

## 9. What should NOT be copied wholesale

Do not copy complete donor platforms merely because permission exists.

Reject wholesale adoption of:

- OpenCTI's complete server/dependency topology;
- Golam's whole agent operating system;
- Kodac's complete TypeScript runtime;
- Ascout's complete verification CLI;
- autonomous exploitation loops from Strix/Shannon/HexStrike/CRS systems;
- a mandatory graph database;
- a mandatory LLM/provider runtime;
- a mandatory cloud sandbox/control plane;
- a second Finding authority;
- a second policy/authorization authority that can bypass Sentrdel hard guards.

Prefer small contracts, validators, parsers, adapters and test corpora.

## 10. Canonical authority boundaries

The following rules remain non-negotiable:

```text
External scanner result != canonical Finding
External graph relationship != semantic identity authority
CTI confidence != Evidence authority
LLM judge != VERIFIED
Sandbox provider success != authorization
Policy engine ALLOW != hard-guard bypass
Zero findings != clean when execution/applicability/coverage is incomplete
Successful process exit != sufficient proof artifact
Permission to copy != source admitted
Planning source map != implementation authorization
```

## 11. Recommended immediate repository action

This source-mining pass should change **planning and source qualification only** while S1 remains active.

Immediate actions:

1. keep PR #330 / S1-T011 isolated from this planning work;
2. preserve PR #332 as docs/research-only;
3. record the founder GitHub-source permission statement separately;
4. add this cross-repository source map to PR #332;
5. do not start any new donor integration until the active Spec Kit makes the relevant successor slice dependency-eligible;
6. when a successor slice activates, qualify the **smallest exact source paths** needed instead of approving an entire repository.

## 12. Final source priority

If Sentrdel eventually qualifies only a small subset of this universe, the highest-value order is:

```text
P0  Founder-owned:
    Golam authority/sandbox primitives
    Kodac evidence provenance + relation + analyzer normalization
    Ascout receipt/completeness semantics

P1  Interoperability:
    OpenCTI Community STIX/TAXII/connectors/workbench/stream patterns
    OpenTelemetry + in-toto/SLSA protocol surfaces

P1  Evidence producers:
    OSV/Syft/Grype/Trivy/Gitleaks/OpenGrep-Semgrep

P2  Deep semantics:
    Tree-sitter/SCIP/Joern
    Graphify/code-graph-rag only if benchmark evidence proves incremental value

P2  Verification/conformance:
    AI-Infra-Guard/AICGSecEval
    OSS-CRS/Atlantis/FuzzingBrain/Vulnhuntr as method/lifecycle references

P3  Optional observations:
    Magika and other content classifiers
```

This order maximizes Sentrdel-owned deterministic authority before adding heavier or more dynamic external systems.
