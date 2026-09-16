# OpenCodeReview Source Assessment — 2026-09-16

**Status:** `RESEARCH_CANDIDATE_ASSESSMENT / NO SOURCE ADMISSION / NO IMPLEMENTATION AUTHORITY`  
**Sentrdel planning branch:** `docs/security-control-plane-2026-09-12`  
**Upstream:** `alibaba/open-code-review`  
**Research pin:** `a694be568d9b9a935b2ba11a867d5a91d7ffd833`  
**Observed repository license:** Apache-2.0  
**Purpose:** Evaluate OpenCodeReview as a source/pattern reference for Sentrdel's future review orchestration, developer contract, forge delivery, and advisory-agent surfaces without moving canonical security judgment out of the Sentrdel Rust core.

## 1. Executive decision

OpenCodeReview is a high-value source and product reference for **review orchestration and delivery mechanics**, not a replacement for Sentrdel's Evidence/Coverage/SSG/invariant/reconciler architecture.

The strongest transferable ideas are:

1. one deterministic file-selection decision shared by preview and execution;
2. an immutable run manifest with explicit selected/completed/reused/failed/waived sets and terminal state;
3. safe resume/checkpoint identity bound to exact inputs and configuration;
4. semantic grouping as an optimization with complete deterministic fallback;
5. bounded multi-round review for recall without making the model a security authority;
6. deterministic rule targeting with visible source/pattern provenance;
7. delegation where deterministic engineering prepares a review specification and a host agent performs lower-authority reasoning;
8. exact-range incremental review with fail-closed checkpoint invalidation;
9. comment publication mechanics that are idempotent, bounded, and non-destructive;
10. explicit review-session telemetry and operational accounting.

Sentrdel should **not** adopt OpenCodeReview's model-centric judgment path as canonical security judgment. Sentrdel already has a stronger trust split:

```text
OpenCodeReview pattern
  deterministic orchestration -> LLM review -> comments

Sentrdel target
  deterministic orchestration
    -> trusted Evidence/Coverage/invariant/regression/reconciler judgment
    -> optional advisory model/host-agent reasoning
    -> forge/IDE publication projection
```

The model may improve recall, explanation, triage, or candidate hypotheses. It must remain structurally incapable of creating or suppressing canonical Sentrdel Findings, FACT, VERIFIED state, policy authority, or Coverage truth.

## 2. Exact source map

The files below are research candidates only. This assessment does not add them to `docs/third-party/source-qualification-ledger.md` and does not authorize copying, vendoring, linking, execution, or dependency admission.

| Upstream artifact | Blob SHA at research pin | Sentrdel value | Research disposition |
|---|---|---|---|
| `internal/agent/selection.go` | `771c616f9c21f475eb9895aec49fa6d0b1924f13` | one pure deterministic pre-dispatch decision per changed file; preview/execution share the same selector | `HIGH_VALUE_SELECTIVE_PORT_REFERENCE` |
| `internal/agent/grouping.go` | `336202eb56234adcea481b3fe00f7cc565bdbed0` | bounded grouping, complete fallback, unassigned-file preservation, token/group caps | `ALGORITHM_REFERENCE / MODEL_AUTHORITY_REJECTED` |
| `internal/session/manifest.go` | `6a113b246aff438ba881b3112991c0086fd95661` | versioned run manifest, coverage denominator, terminal states, exact input/config identity, sealed/frozen lifecycle | `HIGH_VALUE_SELECTIVE_PORT_REFERENCE` |
| `internal/session/resume_identity.go` | `e318b99dbd0fc31723618def470294add53cedfa` | resume safety and refusal when session identity is not reconstructable | `HIGH_VALUE_SELECTIVE_PORT_REFERENCE` |
| `internal/delegate/rulegroup.go` | `3e7d8ba80ec4f455e95dc91d6e2df4cad6bc8daf` | deterministic review-spec grouping with rule provenance and no model call | `HIGH_VALUE_DESIGN_REFERENCE` |
| `pages/src/content/docs/en/architecture.md` | `a048c12762875af0942743a0d7a92c1b06e28fba` | pipeline, grouping, review rounds, context budgeting, comment-processing design | `ARCHITECTURE_REFERENCE` |
| `pages/src/content/docs/en/review-rules.md` | `d323e7b16205767741625966b347359d1c4dca0d` | explainable rule resolution and `rules check` UX | `UX / POLICY-ROUTING_REFERENCE` |
| `action.yml` | `5be6d93e9b2ec4c34954b29760efd59a313735ec` | checkpoint range, sticky summary, comment batching/routing, trusted-base checkout pattern | `FORGE_DELIVERY_REFERENCE` |
| `ROADMAP.md` | `07d0b380c2466b9d28b8a7984d27304cf333bebb` | delegate/ultra/memory product direction and explicit non-goals | `PRODUCT_REFERENCE` |
| `LICENSE` | `5db038258492ce47a5f3d27d78562c90d3f78331` | Apache-2.0 repository license record | `LICENSE_RECORD` |

A later source qualification must re-pin the selected upstream revision and selected files at authorization time. This research pin is not a future release/admission pin.

## 3. Lessons to adopt

### 3.1 Deterministic selection is a security contract

OpenCodeReview centralizes file selection in a pure pre-dispatch decision so preview and real execution cannot derive different scopes.

Sentrdel should strengthen this pattern into a canonical `ReviewPlan`:

```text
changed item
  -> INCLUDED_REQUIRED
  -> INCLUDED_OPTIONAL
  -> EXCLUDED_NON_ANALYZABLE
  -> EXCLUDED_BY_TRUSTED_POLICY
  -> DEFERRED_BUDGET
  -> UNSUPPORTED
  -> DELETED_CONTEXT_ONLY
  -> BINARY_CONTEXT_ONLY
  -> other future frozen states
```

Every changed item receives exactly one pre-dispatch state. Runtime failures are separate execution outcomes, not retroactive selection decisions.

Critical difference from OpenCodeReview: repository/user exclusions must not silently hide a Sentrdel-mandatory security surface. Target-controlled configuration may narrow optional presentation or request additional analysis; it cannot suppress required Evidence/Coverage work.

### 3.2 Review-run completeness is distinct from security Coverage

OpenCodeReview's manifest explicitly separates selected, completed, reused, failed, and waived work and computes `complete`, `partial`, `failed`, or `skipped` independently from comment count.

Sentrdel needs the same class of run truth, but it must remain separate from canonical `CoverageRecord` semantics.

Required separation:

```text
Change-surface coverage
  Which changed artifacts were admitted into review?

Execution coverage
  Which planned review units actually completed/reused/failed/deferred?

Security producer Coverage
  Which security capabilities/scopes/producers/dimensions were supported?

Invariant/regression coverage
  Was the security property comparable/provable across base and candidate?

Publication coverage
  Which canonical/advisory results were successfully projected to CLI/forge/IDE?
```

No layer implies another.

### 3.3 Resume is an optimization, never security authority

A review may reuse prior work only when the reuse proof binds all security-relevant inputs.

Future Sentrdel `ReviewReuseProof` should bind at least:

- parent run ID/digest;
- exact repository identity;
- exact trusted base and candidate revisions;
- logical review-item identity;
- content/diff fingerprint;
- Sentrdel version;
- producer set and producer versions/digests;
- rule/pack/policy/config identities;
- semantic snapshot/config identity where applicable;
- authority profile;
- relevant model/advisory configuration if an advisory result is reused.

Any mismatch invalidates reuse and redispatches the unit. A checkpoint can save work; it cannot prove security.

### 3.4 Semantic grouping may improve context but cannot reduce coverage

OpenCodeReview's grouping is useful because it preserves every file, bounds group size, and falls back to per-file review on model or parse failure.

Sentrdel should prefer deterministic grouping from existing repository/SSG facts:

- same route/security path;
- caller/callee or import relationship;
- manifest/lockfile pair;
- provider configuration + consuming source;
- migration + affected application path;
- workflow + referenced action/script;
- test/fixture + security invariant target.

Optional model grouping may suggest an advisory grouping, but:

```text
model grouping != semantic identity
model grouping failure != dropped review item
model grouping confidence != Coverage
```

### 3.5 Multi-round reasoning belongs only in the advisory plane

OpenCodeReview's effort modes and repeated rounds are a useful recall technique. Sentrdel may later expose `standard`/`deep`/`maximum` advisory effort profiles, but canonical deterministic security producers remain independent from model rounds.

The model may emit `AdvisoryReviewComment`, candidate hypotheses, remediation ideas, or investigation questions. A second model/reflection pass may reject an advisory comment; it may **not** delete or downgrade a canonical Finding or Coverage gap.

### 3.6 Rule routing must be explainable and tightening-only

The `rules check <path>` UX is worth adapting. Sentrdel should support a future equivalent such as `sentrdel rules explain <path>` or a structured review-plan explanation.

A future `ReviewRuleProfile` should bind:

- rule/profile ID and version/digest;
- source (`builtin`, qualified pack, trusted operator, repository narrowing layer);
- match basis;
- applicable path/artifact/security domain;
- authority ceiling;
- mandatory vs optional status;
- benchmark/conformance state.

Repository rules cannot suppress mandatory security coverage or widen authority.

### 3.7 Delegation is a strong vendor-neutral agent integration pattern

OpenCodeReview's delegation mode separates deterministic scope/rule resolution from the host agent's model call.

Sentrdel should adopt a stricter future `ReviewPacket`:

```text
ReviewPacket
  exact revision-pair identity
  exact selected items
  bounded context manifest
  applicable rule/security-profile identities
  canonical Findings/regressions/Coverage references
  explicit unanswered questions
  advisory tool/capability ceiling
```

The host agent may return `HYPOTHESIS` / `INFERENCE` / advisory text only. It cannot create canonical Finding/FACT/VERIFIED state or alter the packet's authoritative scope.

This gives Sentrdel high-quality Codex/Claude/Cursor/JetBrains integration without requiring a separate model API key or making one provider canonical.

### 3.8 Publication needs its own integrity/idempotency model

OpenCodeReview's incremental/non-destructive comment posting and checkpointed ranges expose a real product requirement: repeated reviews must not spam or silently lose state.

Future Sentrdel `ReviewPublicationRecord` should bind:

- canonical/advisory source record ID;
- exact revision/head;
- forge/provider;
- publication target and type;
- exact source span if inline;
- publication fingerprint;
- prior/superseded publication references;
- success/failure/routing state;
- redaction facts.

A canonical Finding may be rendered inline only when the exact source span is proven from canonical provenance. If line anchoring is uncertain, publish it in a summary with provenance rather than asking a model to manufacture authoritative line placement.

## 4. Patterns to reject or strengthen

### 4.1 Model output is not judgment authority

OpenCodeReview is intentionally an AI review product. Sentrdel must retain its stricter architecture:

```text
LLM comment != Evidence
LLM severity != canonical severity
LLM reflection != Finding suppression
LLM relocation != canonical source location
LLM grouping != semantic identity
```

### 4.2 `too_large` cannot be merely a warning

Any item that cannot be analyzed because of size/budget must appear in review-run completeness and, where it affects a security capability, in canonical Coverage. A zero-finding result with deferred/unreviewed required items is incomplete.

### 4.3 User/project excludes cannot hide mandatory security surfaces

OpenCodeReview permits project-level exclude behavior appropriate for general code review. Sentrdel's Constitution is stricter: untrusted repository configuration cannot disable evidence capture or widen/narrow mandatory security authority silently.

### 4.4 Mutable dependency/install identity is unacceptable for Sentrdel

The inspected GitHub Action defaults `ocr_version` to `latest`. Sentrdel must not adopt a mutable installer/version pattern for security-critical CI. Forge integrations and external engines require exact immutable version/digest/source qualification.

### 4.5 `pull_request_target` requires a Sentrdel-specific threat model

OpenCodeReview demonstrates a useful trusted-base-checkout/fetch-head-as-object pattern. Sentrdel should define an explicit fork-safe S3 profile:

- trusted workflow/base checkout only;
- exact PR head SHA fetched as data/git objects;
- no execution of PR-controlled code with secrets;
- minimal GitHub token permissions;
- no ambient forge credentials in analyzers;
- no PR body/comment treated as instruction;
- pinned action/binary identity;
- exact base/head verification before publication;
- comment-trigger authorization and rate/replay controls.

### 4.6 Review memory must remain context, never suppression authority

OpenCodeReview's roadmap includes domain-specific long-term memory. Sentrdel may later learn project context, but memory requires exact revision/scope/freshness/provenance/expiry and remains lower-authority context. A remembered prior decision cannot suppress new Evidence, Coverage loss, policy, or a canonical Finding.

## 5. New roadmap gaps exposed by OpenCodeReview

This study adds candidate planning gaps after the current OpenCTI G43-G52 register:

- **G53 — Canonical Change Review Manifest missing.** Freeze exact review-run input, selected set, outcomes, terminal completeness, provenance and resource accounting.
- **G54 — Deterministic review preview/scope explanation missing.** One selector must drive preview and execution; every changed artifact receives an explicit disposition.
- **G55 — Review-surface completeness and security Coverage are not separated.** Define independent layers and prohibit implicit equivalence.
- **G56 — Resume/checkpoint reuse proof underspecified.** Reuse must bind exact revision, content, config/rules/packs/producers/authority and fail closed on drift.
- **G57 — Large-change/budget partial progress needs a product contract.** Deterministic bounded partial work plus explicit uncovered/deferred items; no false clean result.
- **G58 — Multi-file review-unit semantics missing.** Prefer Sentrdel-owned deterministic semantic relationships; model grouping remains optional/advisory with complete fallback.
- **G59 — Review-rule targeting/precedence needs an authority-aware contract.** Rules are versioned/digested/explainable and repository configuration cannot suppress mandatory security coverage.
- **G60 — Inline annotation provenance is underspecified.** Inline publication requires exact canonical source-span proof; uncertain placement becomes summary-only.
- **G61 — Advisory comment reflection and canonical Finding authority need explicit separation.** Reflection/dedup may filter advisory text only.
- **G62 — Forge publication lifecycle/idempotency missing.** Stable publication fingerprints, rerun/supersession semantics and exact-head binding are required.
- **G63 — Host-agent delegation contract missing.** Deterministic `ReviewPacket` in; lower-authority advisory output out; no canonical authority transfer.
- **G64 — Model-visible context minimization contract missing.** Explicit context manifest/redaction/digests; secrets and instruction authority stay out by default.
- **G65 — Risk-aware review effort/escalation is underspecified.** Deterministic risk/profile controls budget and producer depth; model preference cannot widen authority.
- **G66 — Review delivery quality metrics are incomplete.** Measure selected-surface recall, location/annotation accuracy, duplicate rate, partial-rate, reuse correctness, publication failures, and actionable-result latency.
- **G67 — Fork-safe forge workflow profile is missing.** Freeze trusted-base checkout, head-as-data, minimal permissions, immutable tooling and comment-trigger boundaries.
- **G68 — Review-session observability needs a standard local contract.** Structured local events plus optional redacted OTLP export; raw source/secrets/prompts stay local by default.
- **G69 — Planning authority is fragmented across overlapping roadmap PRs/documents.** Converge strategic research into one navigation/Plan-of-Record path and mark superseded planning explicitly.

These gaps do not modify or reopen S1. They primarily strengthen S2/S3 and the later verification/control-plane sequence.

## 6. Recommended adoption order

```text
S1 remains unchanged
  Security Invariant Regression Core
        |
        v
S2 strengthened
  ReviewPlan + ChangeReviewManifest + local regression developer contract
        |
        +--> optional ReviewPacket / advisory reasoning contract
        |
        v
S3 strengthened
  fork-safe forge projection + exact annotations + publication lifecycle
        |
        v
S4 conformance
  add review-surface completeness / publication / reuse tests
        |
        v
S5 verification
  reuse generic run-manifest/checkpoint/completeness primitives
```

External evidence import can later reuse the same run/completeness primitives without making OpenCodeReview a runtime dependency.

## 7. Source-admission decision

```text
research_value: HIGH
copy_or_vendor_authorized_by_this_record: NO
runtime_dependency_authorized: NO
Go_runtime_in_trusted_core: NO
Node_action_runtime_in_trusted_core: NO
LLM_as_judgment_authority: NO
selective_Rust_port_candidate: YES, only after exact future qualification
optional_external_advisory_producer_candidate: YES, future only
```

The most valuable future selective-port targets are the **manifest/selection/resume semantics**, not OpenCodeReview's model loop.
