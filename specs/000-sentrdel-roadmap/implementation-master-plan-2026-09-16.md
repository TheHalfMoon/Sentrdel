# Sentrdel Implementation Master Plan — 2026-09-16

**Status:** `IMPLEMENTATION_READY_PLAN_CANDIDATE / NO CURRENT IMPLEMENTATION AUTHORITY`  
**Planning head lineage:** PR #332  
**Canonical implementation authority:** active Spec Kit only  
**Protected-main baseline at creation:** `13d0a068ea1df5480adc38373b34a6650d782885`  
**Live implementation frontier at creation:** `S1-T012` in `specs/004-security-invariant-regression/tasks.md`  
**Primary strategy inputs:** full-project review, post-R3 execution blueprint, security-control-plane expansion, OpenCTI interoperability study, OpenCodeReview assessment, and founder source-mining records  
**Purpose:** convert the strategic roadmap into a dependency-ordered implementation program that a future implementation agent can execute without inventing architecture, authority, lifecycle, or qualification semantics.

> This document is implementation-ready planning, not implementation permission. It does not authorize work outside the active Spec Kit. A future slice becomes executable only after its predecessor gate is canonical and that slice completes the repository's normal Spec Kit lifecycle.

---

## 1. Program objective

Sentrdel must become the trusted security-review system that can answer, for one exact change:

> **What was in scope, what was actually reviewed, what security property changed, what evidence supports the conclusion, what remains unknown, what stronger claim was independently verified, what was delivered to the developer, and can any prior work be safely reused for this exact revision?**

The implementation program optimizes for five properties in this order:

1. **Authority correctness** — no source, model, scanner, forge, runtime observation, or automation layer can silently acquire stronger authority than its contract permits.
2. **No-green-by-omission** — missing, skipped, failed, unsupported, timed-out, budget-exhausted, or stale mandatory work remains visible and cannot collapse into a clean result.
3. **Determinism and replayability** — equal admitted inputs produce equal canonical identities, plans, ordering, and judgment outputs.
4. **Local-first developer usefulness** — the primary product path works without a hosted control plane, cloud model, external scanner, dynamic target execution, or proprietary service.
5. **Extensibility through bounded protocols** — forges, models, scanners, sandboxes, CTI systems, telemetry and later control-plane services project over stable local contracts rather than reimplementing judgment.

---

## 2. Authority hierarchy and adoption rule

Use this order whenever documents disagree:

```text
Constitution
  > protected-main live truth
  > active Spec Kit spec/contracts/plan/tasks
  > canonical roadmap
  > this implementation master plan once adopted
  > active supporting strategic supplements
  > research/source assessments
  > historical/superseded plans
```

This plan becomes the post-S1 implementation Plan of Record only after PR #332 is qualified and merged. Even then, it remains planning authority, not task authorization.

### 2.1 Strategic-document lifecycle

Every roadmap document must be classified as exactly one of:

```text
ACTIVE_PLAN_OF_RECORD
ACTIVE_SUPPORTING_SUPPLEMENT
HISTORICAL_SUPERSEDED
RESEARCH_ONLY
REJECTED
```

After this plan is canonical:

- this document should become `ACTIVE_PLAN_OF_RECORD` for post-S1 execution sequencing;
- the full-project review remains `ACTIVE_SUPPORTING_SUPPLEMENT`;
- the security-control-plane and OpenCTI documents remain `ACTIVE_SUPPORTING_SUPPLEMENT` for their bounded later domains;
- the post-R3 execution blueprint becomes `HISTORICAL_SUPERSEDED` for sequencing but remains auditable design history;
- source assessments remain `RESEARCH_ONLY` unless separately promoted through source qualification.

---

## 3. Non-negotiable product invariants

These invariants apply to every future slice and must appear in its checklist/tests where relevant.

```text
Evidence != Finding
Coverage != completeness
review completeness != policy decision
policy ALLOW != secure
external severity != canonical severity
external confidence != FACT or VERIFIED
model output != Evidence unless a separately admitted producer contract says so
model output != Finding authority
LLM reflection/filtering != Finding suppression authority
LLM relocation != canonical source location
LLM grouping != semantic identity
forge publication success != canonical run success
runtime observation != repository fact
inventory discovery != target authorization
sandbox success != verification authorization
checkpoint/reuse != security authority
project config != authority to suppress mandatory security work
zero findings != clean when required work is incomplete
source permission != source qualification
planning inclusion != dependency admission
```

Ordinary review must continue to avoid target build/install/code execution unless a separately authorized verification contract explicitly permits it.

---

## 4. Program dependency graph

```text
ACTIVE NOW
S1  Security Invariant Regression Core
 |
 | canonical closeout required
 v
S2A Review Orchestration Contract
 |
 v
S2B Local Security Regression Developer Contract
 |
 +--------------------+
 |                    |
 v                    v
S3 Forge Delivery    S4 Review + Regression Conformance
 |                    |
 +----------+---------+
            |
            v
S5 Bounded Verification
            |
            +-------------------------------+
            |                               |
            v                               v
S6A Standards-First Import            Gate A Agentic Conformance
            |
            v
S6B External Producer Adapters
            |
     +------+------+------------------+
     |             |                  |
     v             v                  v
S7 Provider     S8 Action Guard    Intelligence Foundation
Expansion                        (STIX/TAXII, later workbench)
     |             |
     +------+------+ 
            |
            v
S9 Runtime Correlation
            |
            v
S10 Project Posture / Optional Control Plane
            |
            v
S11 Controlled Learning / Research Flywheel
```

### 4.1 Parallelism rule

Parallel work is allowed only when:

- both slices have satisfied their explicit entry gates;
- they do not mutate the same authority contract;
- their merge order cannot create a partially upgraded public schema;
- each branch can independently qualify against protected main;
- one slice cannot rely on evidence produced only by an unmerged sibling branch.

S6A research/specification may proceed in parallel with S5 after S2/S4 contracts are canonical. S6A implementation must not delay or weaken S5.

---

## 5. Target code ownership and package boundaries

Use existing crate boundaries before creating new crates.

### `sentrdel-schema`

Own only stable public/wire contracts that genuinely require cross-crate or external compatibility. Do not place internal orchestration types here merely for convenience.

Candidate future public types only after an explicit schema gate:

- versioned review protocol envelope;
- machine-readable review completeness summary;
- stable external import envelope where public interoperability requires it;
- verification receipt/proof references where external consumers require them.

### `sentrdel-review`

Primary owner of local review orchestration and change-relative security review semantics.

Future internal modules should converge toward:

```text
review/change_inventory
review/planner
review/run_manifest
review/reuse
review/risk_profile
review/advisory
review/publication_model   # pure state/identity only, no forge client
review/regression          # existing S1 family
```

Do not create a second Finding or Coverage authority inside orchestration.

### `sentrdel-cli`

Own presentation, command parsing, local invocation and stable exit-code mapping. It consumes review contracts; it does not define security semantics.

### `sentrdel-verify`

Remain execution-disabled until S5 has a canonical Spec Kit and authorization/isolation contracts. Later own verification orchestration only; canonical Evidence/Coverage/Findings remain in their existing authority paths.

### `sentrdel-engine` / producer crates

Own bounded producer execution/normalization according to admitted capabilities. A producer reports observations/Evidence/Coverage; it never directly owns a final review policy decision.

### `sentrdel-policy` and `sentrdel-guard`

Continue to own policy/guard semantics. Review completeness must not be hidden by policy output.

### Forge/adapters

Prefer thin adapters that consume the same local versioned protocol. No GitHub/GitLab-specific judgment model.

### New-crate rule

A new crate is justified only when at least one is proven:

1. a stable public dependency boundary is needed;
2. privileged dependencies must be isolated from the trusted local review path;
3. compile-time dependency direction would otherwise become cyclic;
4. independent conformance/versioning is required.

Aesthetic separation alone is insufficient.

---

## 6. Shared identity model

Every future run-oriented contract must bind identities rather than mutable names wherever possible.

### 6.1 `ReviewRunIdentity`

Conceptual fields:

```text
schema_version
run_id
repository_identity
base_revision_identity
candidate_revision_identity
change_inventory_digest
review_plan_digest
sentrdel_build_identity
policy_identity
rule_pack_identities[]
producer_identities[]
profile_identity
parent_run_id?
created_at
```

`run_id` is derived or collision-resistant according to the future spec, but replay equivalence is determined by admitted identity fields, not wall-clock time.

### 6.2 Canonical digest input rule

All digests used for reuse/identity must be over:

- explicitly versioned canonical serialization;
- deterministic ordering;
- normalized path/enum/value encoding;
- no host pointer width, map iteration order, locale, timezone, filesystem order, or unstable debug formatting;
- target-independent byte accounting where resource decisions depend on size.

### 6.3 Revision mutability rule

Mutable refs may be accepted only as user input that resolves immediately to immutable identities. The resolved immutable base/candidate identities are what enter manifests and reuse proofs.

---

## 7. Review orchestration state machines

These states are planning decisions to remove ambiguity. A future Spec Kit may rename them only with an explicit compatibility rationale.

### 7.1 Review-item selection state

```text
MANDATORY_SELECTED
OPTIONAL_SELECTED
NOT_APPLICABLE
UNSUPPORTED
DEFERRED_RESOURCE_LIMIT
DEFERRED_POLICY
IGNORED_NON_SECURITY
WAIVED_BY_TRUSTED_POLICY
```

Rules:

- every changed item receives exactly one selection state;
- repository-controlled config may narrow optional work but cannot transform mandatory work into ignored work;
- `WAIVED_BY_TRUSTED_POLICY` requires trusted policy provenance and remains visible;
- a waived mandatory security item prevents full review completeness unless the future policy contract explicitly defines a separate accepted-risk completeness class; it never silently becomes `COMPLETE`.

### 7.2 Review-unit execution state

```text
PENDING
RUNNING
COMPLETED
REUSED
FAILED
TIMED_OUT
CANCELLED
DEFERRED
```

`REUSED` requires a valid `ReviewReuseProof`; it is not an operator assertion.

### 7.3 Run completeness state

Keep completeness intentionally small:

```text
COMPLETE
INCOMPLETE
FAILED
CANCELLED
```

Details live in typed reasons and item/unit states rather than multiplying terminal enums.

`COMPLETE` requires every mandatory selected unit to be `COMPLETED` or validly `REUSED`, with no unresolved mandatory item state.

### 7.4 Publication state

```text
NOT_REQUESTED
PENDING
PUBLISHED
PARTIAL
FAILED
SUPERSEDED
```

Publication failure cannot alter canonical analysis truth. A moved candidate head supersedes stale placement/publication identity.

### 7.5 Advisory state

Advisory/model output uses a separate lifecycle such as:

```text
PROPOSED
RETAINED
REJECTED
STALE
SUPERSEDED
```

No advisory state transition can mutate canonical Finding existence or canonical Coverage.

---

## 8. `ChangeReviewManifest` implementation contract

S2A must freeze one canonical local manifest that is sufficient to explain the review run without reading logs.

Required semantic groups:

### Identity

- run identity;
- exact repository/base/candidate identity;
- binary/build identity;
- plan/config/policy/rule/producer identities.

### Scope accounting

- full changed-item inventory count;
- mandatory/optional/not-applicable/unsupported/deferred/waived counts;
- explicit item identities for each class;
- deleted/renamed/binary/generated/oversized/submodule/unsupported items retained in accounting.

### Execution accounting

- selected review units;
- completed/reused/failed/timed-out/cancelled/deferred sets;
- per-unit producer/profile identity;
- per-unit deterministic work counters;
- explicit cap/resource reason codes.

### Judgment references

- canonical Coverage references;
- regression references;
- canonical Finding references where applicable;
- policy decision reference;
- advisory references separately.

### Terminal truth

- completeness state;
- failure/cancellation reasons;
- safe-to-publish indicator derived from policy + completeness contract, not from finding count;
- publication records as external effects.

---

## 9. Deterministic `ReviewPlan`

Planning must occur before expensive producer execution.

### Inputs

- immutable change inventory;
- trusted project/operator policy;
- admitted producer capabilities;
- deterministic artifact classification;
- known security-sensitive path/semantic facts;
- resource budget;
- review profile.

### Outputs

- item selection states;
- mandatory producer/profile assignments;
- optional producer/profile assignments;
- deterministic review-unit partition;
- execution order or dependency DAG;
- explicit unsupported/deferred states;
- plan digest;
- human/machine explanation for each routing decision.

### Planner rules

1. `preview` and execution consume the same plan bytes/digest.
2. Probabilistic/model routing may add optional advisory work but cannot remove deterministic mandatory work.
3. Unknown artifact type cannot become invisible; route conservatively or mark unsupported.
4. Budget exhaustion is planned/recorded explicitly and affects completeness where mandatory work is lost.
5. Input ordering must not change plan identity.
6. Rules are tightening-only relative to hard mandatory security requirements.

---

## 10. Risk profiles

Freeze three conceptual profiles in S2A; exact names may remain `standard`, `heightened`, `critical` unless the Spec Kit proves better naming.

### Standard

Default deterministic producers for ordinary code/documentation changes.

### Heightened

Triggered by deterministic facts such as auth/authorization, credential/config, dependency/lockfile, CI/workflow, data boundary, provider authority, policy/guard, security pack, or sensitive infrastructure changes.

May increase:

- producer set;
- deterministic semantic depth;
- work budget;
- advisory explanation effort.

### Critical

For changes touching authority roots or high-impact execution/security boundaries.

Requires explicit stronger completeness expectations and may require later verification eligibility, but **does not itself grant network, credential, process-spawn, mutation, or target-execution authority**.

### Risk-profile determinism

The selected profile must expose reason codes and input identities. A model may recommend escalation but cannot autonomously downgrade a deterministic profile.

---

## 11. Reuse and checkpoint contract

### 11.1 `ReviewReuseProof`

A reuse proof must bind at least:

```text
source_run_id
source_unit_id
source_result_digest
base_revision_identity
candidate content/input identity for the reused unit
review-plan compatibility identity
producer identity/version
producer config/rules identity
policy/profile identity
relevant dependency/tool identity
schema version
```

### 11.2 Mandatory invalidation

Redispatch rather than reuse on any relevant drift in:

- source bytes/diff identity;
- semantic dependency inputs;
- base revision where the unit depends on base state;
- Sentrdel semantic schema;
- producer version/config/rules;
- policy/risk profile;
- applicable security pack;
- tool/dependency identity;
- authority ceiling;
- prior result marked incomplete/failed/timed out/cancelled;
- explicit freshness expiry.

### 11.3 Reuse safety tests

The future S2A test matrix must include:

- exact valid reuse;
- one-byte source drift;
- rule/config drift;
- producer-version drift;
- base-only drift affecting semantic dependency;
- unrelated-file change that legitimately preserves unit reuse;
- stale run/freshness expiry;
- forged source run ID;
- duplicate reuse binding;
- reordered manifest inputs;
- platform replay.

Reuse errors fail to fresh execution, not to a trusted reused result.

---

## 12. S2A — Review Orchestration Contract

**Entry gate:** S1 canonical completion, protected-main post-merge proof, and a separately created S2 Spec Kit.  
**Exit gate:** deterministic local review plan/run truth exists independently of CLI/forge presentation.

### Implementation packets

#### `IMP-S2A-01` — successor Spec Kit and architecture freeze

Deliver:

- S2 spec/clarifications;
- contract inventory;
- module ownership map;
- explicit non-goals;
- schema/public-API decision;
- conformance fixture plan.

No product code before this packet's planning/checklist analysis is green.

#### `IMP-S2A-02` — exact change inventory

Implement deterministic inventory over exact base/candidate or admitted local snapshot.

Must account for:

- add/modify/delete/rename/copy where exact repository evidence supports it;
- binary;
- generated classification as observation/policy, not disappearance;
- oversized;
- unsupported;
- submodule/symlink/special-path behavior;
- path normalization and hostile path cases.

Tests: ordering, Unicode/path edge cases, duplicate/case behavior, rename ambiguity, caps, malformed revisions, no hidden item.

#### `IMP-S2A-03` — planner and selection reason model

Implement deterministic `ReviewPlan`, selection state, routing reasons and plan digest.

Tests: same input replay, input-order permutation, mandatory rule cannot be suppressed, unknown artifact visible, deterministic risk profile.

#### `IMP-S2A-04` — review-unit partition

Implement bounded deterministic units using Sentrdel-owned semantic relationships when available and deterministic file/item fallback otherwise.

No model grouping in canonical unit identity.

Tests: semantic grouping, fallback completeness, caps, cyclic relationship handling, input-order stability.

#### `IMP-S2A-05` — run manifest and completeness reducer

Implement run/item/unit state machines and exact completeness reduction.

Tests must prove zero false `COMPLETE` under failure, timeout, cancellation, deferred mandatory work, unsupported mandatory work, and invalid reuse.

#### `IMP-S2A-06` — resource/work budget accounting

Implement target-independent counters and typed cap reasons.

Wall-clock time may be telemetry, but deterministic semantic decisions must not depend on scheduler timing unless timeout is explicitly part of the contract.

#### `IMP-S2A-07` — safe reuse/checkpoint

Implement reuse proof and invalidation matrix. Resume is an optimization only.

#### `IMP-S2A-08` — advisory/model context manifest

Freeze lower-authority context provenance even if no model integration ships in S2.

Do not add a mandatory model dependency.

#### `IMP-S2A-09` — orchestration adversarial suite

Include forged manifests, duplicate IDs, hostile metadata, huge counts, malformed digests, cross-repo reuse, policy suppression attempts, configuration drift, partial state and platform replay.

#### `IMP-S2A-10` — S2A closeout

Require exact-head CI, deterministic fixture replay, independent authority review, no unresolved review threads, ledger-only closure commit, fresh qualification of closure head, guarded merge, protected-main post-merge CI.

---

## 13. S2B — Local Security Regression Developer Contract

**Entry gate:** canonical S2A.  
**Exit gate:** one excellent local review experience and stable machine protocol.

### `IMP-S2B-01` — output information architecture

Human output order:

1. review completeness;
2. candidate/base identity;
3. security-property regression summary;
4. policy/guard decision;
5. canonical regressions/findings;
6. coverage loss/unknown work;
7. verification state;
8. evidence/provenance drill-down;
9. advisory guidance.

`ALLOW` must never be rendered as the dominant green signal when completeness is not `COMPLETE`.

### `IMP-S2B-02` — machine protocol

Freeze versioned local output containing separate fields for:

```text
run_completeness
policy_decision
regression_summary
coverage_summary
canonical_findings
advisory_items
publication_state
```

Unknown future fields must follow an explicit compatibility policy.

### `IMP-S2B-03` — exit-code contract

Exit codes must represent the intended automation contract without flattening uncertainty. The Spec Kit must decide whether incomplete mandatory review shares a gate-failure code with policy denial or uses a distinct code; the distinction must remain machine-readable either way.

### `IMP-S2B-04` — preview/explain surfaces

`review --preview` consumes the exact `ReviewPlan` identity used by execution. `explain` must trace canonical result -> Evidence/Coverage/invariant/provenance without requiring logs.

### `IMP-S2B-05` — output truncation and redaction

Truncation must be deterministic and visible. Secret/credential material must not leak through diagnostics, model context, JSON, or terminal output.

### `IMP-S2B-06` — local golden fixtures

Golden fixtures include complete clean, regression, coverage loss, unsupported mandatory item, timeout, failed producer, cancellation, valid reuse, invalid reuse, uncertain annotation source span, and no-findings-but-incomplete.

### `IMP-S2B-07` — local product benchmark

Record cold/warm latency and memory/work counters without weakening correctness gates. Performance regression budgets are baseline-derived and versioned.

### `IMP-S2B-08` — S2B closeout

Same canonical closeout pattern as S2A.

---

## 14. S3 — Forge Delivery

**Entry gate:** canonical S2B plus S4 fixture contract sufficient to validate equivalence.  
**Principle:** forge code is projection/publication, not security judgment.

### `IMP-S3-01` — forge-neutral publication protocol

Define stable publication input independent from GitHub/GitLab APIs.

### `IMP-S3-02` — GitHub reference adapter

Use minimal permissions, immutable/pinned action/tool identities, no execution of PR-controlled scripts, and no inheritance of broad credentials into analysis subprocesses.

### `IMP-S3-03` — exact head/base binding

Before publication, verify the analyzed candidate identity still matches the intended forge revision. Moved head => supersede/recompute, never silently attach stale results.

### `IMP-S3-04` — exact annotation anchoring

Inline annotation requires canonical source-span provenance that maps to the exact candidate diff. Otherwise publish summary-only.

Never use LLM line relocation as canonical placement proof.

### `IMP-S3-05` — idempotent publication

Stable publication identity must prevent duplicate comments/checks across retries. Partial external failure is recorded as `PARTIAL`/`FAILED` and is retryable without mutating canonical run state.

### `IMP-S3-06` — fork/untrusted-metadata hardening

PR title/body/comments/branch names/repository files are untrusted data. They cannot become workflow instructions or credential authority.

### `IMP-S3-07` — cross-push reuse

Consume local `ReviewReuseProof`; forge integration cannot invent broader reuse.

### `IMP-S3-08` — semantic-equivalence suite

For each frozen fixture, local protocol and forge projection must represent identical canonical judgment/completeness.

### `IMP-S3-09` — forge failure suite

Rate limit, permission denial, deleted comment/check, moved head, retry, partial annotations, network failure, API schema change, duplicate delivery and stale publication.

### `IMP-S3-10` — S3 closeout

Require least-privilege evidence and fork-safety proof in addition to ordinary qualification.

---

## 15. S4 — Review and Regression Conformance

**Entry gate:** S1 + S2A contracts; public release gate may depend on S2B/S3 according to profile.

Conformance families:

1. Evidence authority/provenance;
2. Coverage state preservation;
3. invariant state;
4. regression pair semantics;
5. exact change inventory;
6. planner/selection completeness;
7. run completeness;
8. reuse invalidation;
9. local protocol compatibility;
10. publication/annotation projection;
11. importer authority;
12. later verification receipts.

### Required benchmark invariants

- mandatory changed-item omission count: **zero** in frozen fixtures;
- deterministic replay mismatch count: **zero**;
- false `COMPLETE` under mandatory missing work: **zero**;
- invalid reuse accepted: **zero**;
- canonical Finding suppressed by advisory/model filtering: **zero**;
- guessed inline annotations without exact provenance: **zero**;
- local/forge canonical semantic disagreement: **zero**.

Precision/recall/latency metrics may be thresholded per benchmark version, but authority invariants above are hard zero-tolerance properties.

Protected holdouts remain separate from candidate-generation logic.

---

## 16. S5 — Bounded Verification

**Entry gate:** canonical S2 local contracts, sufficient S4 conformance, separately authorized S5 Spec Kit.  
**Default:** no production/third-party exploitation; synthetic/local/owned explicitly authorized targets only.

### Required contracts before any target execution

#### `VerificationAuthorization`

Must bind:

- trusted issuer/operator identity and trust anchor;
- canonical integrity/authenticity verification;
- nonce/run binding or equivalent replay defense;
- not-before/expiry/revocation;
- exact target/environment;
- exact tool/profile/action classes;
- mutation budget;
- network/credential scope;
- immutable validation provenance.

Invalid authorization never falls back to broad interactive permission.

#### `ToolCapabilityManifest`

Bind exact executable/image identity and declared filesystem/network/process/credential/target-mutation/resource/output capabilities.

No generic arbitrary shell-string capability in the trusted interface.

#### `VerificationRunManifest`

Reuse generic run accounting where semantics align, but keep verification-specific authorization, isolation and proof state explicit.

#### `ProofArtifactReference`

Bind exact artifact digest/type/producer/run/input/redaction/truncation/freshness metadata. Prose-only “verified” claims are insufficient.

### S5 implementation order

1. authorization validator and adversarial corpus;
2. tool capability registry;
3. deny-by-default rights descriptor;
4. isolated backend abstraction;
5. one synthetic invariant verifier;
6. proof artifact model;
7. contradiction/timeout/cancellation/resource semantics;
8. point retest;
9. second verifier only after first is conformance-clean;
10. closeout.

Never let number of tools outrun proof quality.

---

## 17. S6A — Standards-First External Evidence Import

**Research/spec entry:** canonical S2A plus initial S4 contracts.  
**Implementation entry:** owning Spec Kit and exact parser/dependency qualification.

Implement standards in this order unless benchmarks prove otherwise:

1. SARIF bounded profile using the existing strict JSON/SARIF philosophy;
2. OSV-compatible vulnerability/advisory records;
3. CycloneDX SBOM;
4. SPDX SBOM.

Every importer preserves:

- native producer/artifact identity;
- producer version/config/rule-pack when available;
- raw artifact digest;
- repository/target/input identity;
- native classification/severity/confidence as external fields;
- parse/validation diagnostics;
- applicability/Coverage state;
- Sentrdel authority ceiling.

Malformed/unbounded input fails visibly. External severity/confidence/reachability never directly becomes canonical severity/FACT/VERIFIED.

---

## 18. S6B — External Producer Adapters

Only after S6A proves the generic boundary.

Preferred initial producer evaluation order:

```text
OSV-Scanner
Syft
Grype / Trivy
Gitleaks
OpenGrep / Semgrep structured output
user-supplied CodeQL result import
Scorecard context
heavier Joern / Infer only if incremental benchmark value is proven
```

For each producer, require a one-page admission decision containing:

- exact version/pin;
- execution model;
- required privileges/network/credentials;
- parser/output surface;
- supply-chain/license obligations;
- evidence classes contributed;
- Coverage semantics;
- authority ceiling;
- benchmark delta;
- reason to keep/remove.

A producer that does not improve measured coverage/precision/invariant leverage should be removable without protocol changes.

---

## 19. S7–S11 later implementation gates

These tracks are intentionally less urgent but now have explicit entry criteria.

### S7 Provider/Framework Expansion

Admit a provider only when it increases supported invariant leverage. Required proposal metrics:

- new actor/auth semantics;
- new guard semantics;
- new resource/data-operation semantics;
- new cross-layer invariant support;
- benchmark delta;
- false-positive/authority risk.

### S8 Dependency/Build Action Guard

Requires a genuinely controllable pre-execution seam. Inputs may include lockfile delta, package/version, scripts/build.rs/proc-macros/native code, vulnerability/malware intelligence and provenance. Guard authority must not be claimed where Sentrdel does not control execution.

### Intelligence Foundation

After stable import identities, introduce `ExternalIntelligenceEnvelope` and standards-first STIX/TAXII adapters. Intelligence remains context until Sentrdel-owned reconciliation permits a stronger bounded role.

OpenCTI-inspired workbench/cases/markings/streams come only after principal/tenant/authz/audit contracts in server mode.

### S9 Runtime Correlation

Prefer OpenTelemetry/OTLP and existing deployment provenance standards. Runtime observations attach to source/revision/build/deployment identities where provable and never rewrite repository facts.

### S10 Project Posture / Optional Control Plane

Server mode projects canonical local protocols. Before sensitive multi-user state, freeze principal/session/token identity, tenant/project isolation, authz, immutable audit and break-glass/admin rules.

Local judgment remains independently useful without the server.

### S11 Controlled Learning

Candidate generation may propose rules/adapters/fixtures/remediation but cannot mutate the evaluator, protected holdouts, authority rules, or promotion state used to judge itself. Promotion remains explicit and independently qualified.

---

## 20. Source-admission workflow

Any source copied, linked, vendored, adapted or executed because of the research corpus must pass this sequence:

```text
research candidate
  -> exact immutable upstream pin
  -> exact file/package boundary
  -> applicable license/NOTICE/third-party obligations
  -> dependency/build/proc-macro/native/unsafe review
  -> privileged surface review
  -> network/credential/runtime review
  -> authority-ceiling statement
  -> Sentrdel-owned tests/adversarial fixtures
  -> benchmark value
  -> owning Spec Kit dependency eligibility
  -> admission record
```

Founder permission context may satisfy a rights question where sufficiently specific, but never replaces technical qualification or provenance.

For OpenCodeReview specifically, prioritize selection/manifest/resume/rule-routing/publication mechanics. Do not import its model loop as judgment authority.

For OpenCTI, Community Edition paths remain selective source candidates pending exact Sentrdel qualification; Enterprise paths require separately sufficient source-specific permission/license evidence.

---

## 21. CI and qualification model for every implementation packet

Every packet must define the smallest applicable set, but the default expectation is:

### Static gates

- pinned Rust format;
- workspace check;
- targeted tests;
- full affected-crate tests;
- clippy with repository policy;
- schema-lock where public schema is touched;
- dependency/self-security when dependency surface changes;
- cross-platform tests for behavior that claims portability.

### Semantic gates

- deterministic replay;
- authority-negative tests;
- cap/resource tests;
- malformed/hostile input;
- input-order permutation;
- no false clean/complete state;
- no public API expansion beyond the packet's authority.

### PR closeout pattern

1. implementation head reaches exact-head CI/review qualification;
2. only then update the active task ledger for the completed task;
3. the ledger commit creates a new exact head;
4. re-run applicable CI and independent exact-head review;
5. require zero unresolved review threads;
6. merge with expected-head guard;
7. prove protected-main post-merge CI;
8. only then authorize the next dependency-ordered task.

Do not reuse old-head qualification for a new head.

---

## 22. PR sizing and branch discipline

Default one packet per PR unless the active Spec Kit proves two packets are inseparable.

A packet PR should normally change one architectural concern plus its tests/docs. Avoid mixed source-admission + feature + public-schema + workflow changes in one PR when they can be independently qualified.

Rules:

- no force-push/rebase of shared reviewed history;
- no branch-protection bypass;
- no merge while applicable exact-head gates are unknown/failing;
- no hidden local-only Plan of Record;
- no generated evidence claimed without a real run;
- no “cleanup” that changes unrelated authority or public semantics.

---

## 23. Failure and reason-code discipline

Every new failure that affects trust/completeness must be typed and machine-readable.

Minimum reason families:

```text
IDENTITY_INVALID
INPUT_MALFORMED
INPUT_UNSUPPORTED
MANDATORY_WORK_UNAVAILABLE
PRODUCER_FAILED
PRODUCER_TIMED_OUT
RESOURCE_CAP_EXHAUSTED
CANCELLED
POLICY_RESTRICTED
REUSE_INVALID
AUTHORIZATION_INVALID
PROOF_INSUFFICIENT
PUBLICATION_FAILED
STALE_REVISION
```

Human strings are explanatory projections, not the compatibility contract.

Never infer a stronger success state from absence of an error record.

---

## 24. Compatibility and migration rules

### Wire/schema compatibility

- every public machine contract is versioned;
- additive optional fields are preferred where semantics stay compatible;
- enum additions require unknown-value handling or a major/protocol compatibility decision;
- authority meaning cannot change silently under the same schema version;
- migration code cannot upgrade lower-authority historical data into stronger authority.

### Stored state

If manifests/checkpoints become durable:

- bind schema version and canonical digest;
- old incompatible records are `STALE/UNUSABLE`, not silently coerced;
- migration preserves original provenance;
- migration itself is deterministic and testable.

### Publication

External comments/checks are projections and may be superseded. Canonical local run records remain the source for republishing.

---

## 25. Security test matrix

Every relevant future slice should select from this shared adversarial corpus:

### Identity/provenance

- forged digest;
- foreign repository identity;
- mutable ref drift;
- base/head role swap;
- duplicate stable IDs;
- conflicting same-ID definitions;
- path traversal/absolute/host-specific path;
- Unicode normalization/case edge cases.

### Authority

- external severity attempts canonical upgrade;
- model attempts Finding suppression;
- project config disables mandatory producer;
- PR text attempts workflow instruction injection;
- runtime observation attempts repository-fact overwrite;
- inventory asset attempts dynamic-target authorization;
- invalid/expired/replayed verification authorization;
- sandbox backend claims broader containment than observed.

### Completeness

- producer crash;
- timeout;
- cancellation;
- cap exhaustion;
- unsupported mandatory item;
- oversized mandatory artifact;
- partial publication;
- invalid reuse;
- stale checkpoint;
- missing required evidence.

### Resource abuse

- huge counts;
- huge strings/metadata;
- deeply nested import structures;
- duplicate-heavy input;
- adversarial ordering;
- decompression/archive bombs where future import formats permit archives;
- pathological graph/relation shape.

---

## 26. Benchmark and product-quality gates

The benchmark system must measure both security judgment and review delivery.

### Hard correctness gates

```text
mandatory omission = 0
false COMPLETE under mandatory missing work = 0
accepted invalid reuse = 0
authority escalation by external/model data = 0
guessed canonical inline locations = 0
local/forge canonical semantic disagreement = 0
nondeterministic canonical replay = 0
```

### Measured metrics

- regression precision/recall by supported invariant family;
- Coverage loss detection;
- clean-case false-positive rate;
- review-item selection recall;
- reuse hit rate and invalidation correctness;
- cold/warm latency;
- peak memory/work counters;
- time to first actionable canonical result;
- annotation accuracy;
- duplicate/superseded publication rate;
- publication failure/recovery rate;
- optional advisory token/cost budget;
- operator comprehension of policy vs completeness vs unknown states.

Performance thresholds must be set from versioned baselines and must never justify weakening authority/correctness gates.

---

## 27. Product UX acceptance scenarios

Before broad control-plane work, Sentrdel must demonstrate these as stable end-to-end acceptance scenarios.

### Scenario A — real regression

A supported security invariant worsens. Sentrdel reports exact base/candidate identity, property transition, canonical evidence, Coverage, policy and completeness separately.

### Scenario B — clean complete change

All mandatory work completes, no regression/finding is introduced, and the result is allowed. The UI may present success because completeness is independently proven.

### Scenario C — no findings but incomplete

A mandatory producer fails or a required item is unsupported. Output must make incompleteness dominant and must not look green merely because findings are empty.

### Scenario D — coverage regression

Previously provable security semantics become unknown/unsupported. `COVERAGE_LOST` is visible and blocks any implicit mitigation claim.

### Scenario E — safe warm rerun

Only exact unchanged eligible units are reused; changed/invalidated work redispatches. Results remain equivalent to a cold run.

### Scenario F — forge moved head

Publication detects candidate drift and supersedes/recomputes instead of posting stale inline conclusions.

### Scenario G — advisory disagreement

A model disagrees with a canonical result. The disagreement can be shown as advisory context but cannot suppress or upgrade canonical judgment.

### Scenario H — bounded verification

A valid explicit authorization permits one isolated synthetic verification. Proof artifact, authorization, tool capability and result are linked; invalid authorization cannot execute.

---

## 28. “Ready to implement” definition for a successor slice

A future slice is `IMPLEMENTATION_READY` only when all are true:

1. predecessor canonical gate is proven on protected main;
2. its Spec Kit exists and is the active authorized slice;
3. spec has no unresolved `[NEEDS CLARIFICATION]` items affecting code shape/authority;
4. data model/contracts are frozen enough to prevent implementer invention;
5. module/crate ownership is explicit;
6. public-schema decision is explicit;
7. dependency/source admission requirements are explicit;
8. task DAG is dependency ordered;
9. each task has objective, allowed files/surfaces, tests and acceptance criteria;
10. resource/security/authority negative cases are enumerated;
11. CI/qualification gates are stated;
12. rollback/compatibility behavior is stated;
13. no task depends on unavailable fabricated external evidence;
14. the first task can be started without asking a product/architecture question already answerable by this plan.

---

## 29. First successor handoff after S1

When S1 is fully canonical, do not begin by coding a GitHub app or model review loop.

The first authorized successor action should be:

```text
Create/activate the S2 Review Orchestration Spec Kit from this plan.
Freeze S2A before S2B implementation.
Start with IMP-S2A-01.
```

The S2 Spec Kit should copy the contracts and invariants from this document into normative `spec.md`, `data-model.md`, `contracts/`, `plan.md`, checklist and dependency-ordered `tasks.md`, removing planning language such as “candidate” where the spec makes a final decision.

No source donor should be admitted merely because it appears in this master plan.

---

## 30. Implementation agent operating contract

A future implementation agent following this plan must:

1. reverify protected-main/live PR/task truth first;
2. read Constitution + active Spec Kit before this plan;
3. execute only dependency-eligible active tasks;
4. preserve English-only repository/GitHub technical content;
5. make the smallest architecture-correct change for one task;
6. run real tests and record only real evidence;
7. never fabricate CI/review/runtime/provider/benchmark evidence;
8. never force-push/rebase shared reviewed history;
9. never merge before exact-head qualification;
10. stop a task expansion when it would create a new public contract, dependency, privilege, target-execution path or authority not authorized by the active spec;
11. create a new clarification/spec decision rather than smuggling architecture through implementation;
12. continue automatically through the next authorized task only after the previous task is canonical.

---

## 31. Program completion definition

Sentrdel is not “finished” because every roadmap idea exists. The project reaches a strong product-completion state when the core category promise is proven:

- S1 invariant regression is deterministic and Coverage-aware;
- S2 review orchestration proves exact scope and completeness;
- S2B local UX makes uncertainty impossible to mistake for security;
- S3 forge delivery is semantically equivalent, fork-safe and idempotent;
- S4 provides open and protected conformance;
- S5 can independently verify selected claims under explicit bounded authority;
- S6 can ingest mature external evidence without surrendering judgment;
- later provider/runtime/intelligence/control-plane work remains modular rather than becoming a prerequisite for local usefulness;
- benchmarks prove no-green-by-omission and authority correctness across the product path.

At that point, additional providers, workbenches, intelligence feeds, runtime views and learning loops are expansion of a proven architecture rather than prerequisites for proving the product thesis.

---

## 32. Final implementation thesis

The implementation program is intentionally not “build every security feature.”

It is:

```text
exact change truth
  -> deterministic review plan
  -> explicit execution/completeness truth
  -> Evidence + Coverage + security-invariant regression
  -> reconciler-owned canonical judgment
  -> bounded verification/import where separately authorized
  -> identical local/forge semantics
  -> durable provenance and safe reuse
  -> later control-plane projection without authority drift
```

If a future feature cannot identify where it fits in this chain, which authority ceiling it has, how incompleteness is represented, and which conformance gate proves it, it is not ready to implement.