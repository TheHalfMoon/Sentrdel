# S2 Review Orchestration Spec Bootstrap — 2026-09-16

**Status:** `FUTURE_SPEC_SEED / NO IMPLEMENTATION AUTHORITY`  
**Derives from:** `implementation-master-plan-2026-09-16.md` and `implementation-architecture-freeze-2026-09-16.md`  
**Activation condition:** S1 canonical completion plus ordinary successor Spec Kit creation/clarification/readiness  
**Purpose:** provide a nearly mechanical bootstrap for the first post-S1 Spec Kit so architecture and authority decisions do not have to be rediscovered.

> This is not an active `specs/00x-*` feature spec and deliberately does not reserve a numeric Spec Kit ID. When S1 is canonically complete, create the next valid Spec Kit from live repository truth and copy only the still-valid normative decisions from this seed.

---

## 1. Proposed feature title

**Review Orchestration Contract**

Suggested slug:

```text
review-orchestration-contract
```

Do not assume the numeric prefix until the successor spec is created from live repository truth.

---

## 2. Problem statement

Sentrdel can express Evidence, Coverage, canonical Findings, policy and S1 security-invariant regression, but it still needs a deterministic product-level contract for **what a review actually attempted and completed**.

The feature must prevent these unsafe equivalences:

```text
zero findings == clean
ALLOW == secure
producer Coverage == whole review completeness
successful checkpoint lookup == valid reuse
published GitHub Check == successful canonical review
```

The feature owns review-run truth, not a new security judgment authority.

---

## 3. Scope

### In scope

- exact immutable changed-item inventory;
- deterministic review selection/routing;
- deterministic review-unit partition;
- risk profile derivation;
- review item/unit execution states;
- run completeness reduction;
- target-independent resource/work accounting;
- safe reuse proof validation/invalidation;
- lower-authority advisory context provenance contracts;
- pure forge-neutral publication identity/state model;
- optional local persistence adapter for eligible manifests/checkpoints after pure contracts are proven;
- deterministic/adversarial tests;
- no-green-by-omission conformance fixtures.

### Out of scope

- GitHub/GitLab API calls;
- final stable CLI/JSON UX contract;
- target build/install/code execution;
- dynamic verification;
- external scanner execution added solely for S2;
- cloud/model requirement;
- public control plane;
- auto-fix/auto-merge;
- new canonical Finding authority;
- new policy authority;
- broad public schema expansion before explicit S2B gate.

---

## 4. Required architecture decision

The successor spec should adopt this dependency split unless live repository truth proves it invalid:

```text
sentrdel-review = pure deterministic orchestration domain
sentrdel-store  = persistence/redaction adapter
sentrdel-cli    = I/O composition host
sentrdel-schema = public/wire schema only after explicit schema decision
```

`sentrdel-review` MUST NOT gain a `sentrdel-store` dependency merely for checkpoint/resume.

---

## 5. Functional requirements seed

The successor spec should convert these into its normative requirement format.

### Inventory

**S2A-FR-001** — The system MUST resolve user-supplied mutable refs to immutable repository/revision identities before creating review-run identity.

**S2A-FR-002** — The system MUST produce one deterministic changed-item inventory for the exact admitted base/candidate identities.

**S2A-FR-003** — Every changed item MUST remain represented even when binary, generated, oversized, unsupported, deleted, renamed, submodule-like, or otherwise non-analyzable.

**S2A-FR-004** — Rename/copy similarity MUST NOT become stable identity authority without exact admitted repository evidence.

### Planning

**S2A-FR-005** — The system MUST produce one deterministic `ReviewPlan` before expensive review execution.

**S2A-FR-006** — Preview and execution MUST consume the same plan identity rather than independently rediscovering scope.

**S2A-FR-007** — Each review item MUST have an explicit selection state and reason.

**S2A-FR-008** — Repository-controlled configuration MUST NOT suppress hard mandatory security work, widen authority, or convert missing work into clean.

**S2A-FR-009** — Optional probabilistic/model classification MAY add advisory/escalation work but MUST NOT remove deterministic mandatory work.

**S2A-FR-010** — Review-unit grouping MUST use deterministic Sentrdel-owned semantics where available and deterministic complete fallback otherwise.

### Risk profiles

**S2A-FR-011** — The system MUST derive a deterministic review risk profile from admitted facts/policy with explicit reason codes.

**S2A-FR-012** — A model MAY recommend escalation but MUST NOT autonomously downgrade a deterministic profile.

**S2A-FR-013** — Risk profile MUST NOT grant network, credential, process-spawn, mutation or target-execution authority.

### Run truth

**S2A-FR-014** — The system MUST represent review-unit execution states separately from item selection states.

**S2A-FR-015** — The system MUST derive run completeness from explicit mandatory work rather than finding count or policy decision.

**S2A-FR-016** — Mandatory failed, timed-out, cancelled, unsupported, deferred or invalidly reused work MUST prevent a false fully-complete state.

**S2A-FR-017** — Resource/cap exhaustion affecting mandatory work MUST remain visible in machine-readable state.

**S2A-FR-018** — Canonical ordering/identity MUST NOT depend on scheduler order, OS map iteration, locale, timezone, pointer width, filesystem enumeration or debug formatting.

### Reuse

**S2A-FR-019** — Reuse MUST require a `ReviewReuseProof` bound to exact relevant revision/input/config/producer/policy/schema identities.

**S2A-FR-020** — Database/history presence MUST NOT itself make reuse valid.

**S2A-FR-021** — Invalid/stale/corrupt reuse candidates MUST fail to fresh work where permitted, never to a trusted reused result.

**S2A-FR-022** — Cross-repository reuse and foreign-run identity MUST fail closed.

### Persistence

**S2A-FR-023** — Persistence, if added, MUST occur through `sentrdel-store` or an equally bounded adapter rather than inside pure review-domain logic.

**S2A-FR-024** — Persisted review/checkpoint material MUST pass the repository's redaction boundary before storage.

**S2A-FR-025** — Readback MUST validate schema/integrity/identity before records become eligible reuse candidates.

**S2A-FR-026** — Store failure MUST NOT silently rewrite a completed in-memory canonical review result; it affects persistence/reuse availability instead.

### Advisory and publication model

**S2A-FR-027** — Lower-authority model/host-agent context MUST have explicit provenance and authority ceiling.

**S2A-FR-028** — Advisory output MUST NOT suppress, create, upgrade or relocate canonical Findings/Coverage/semantic identity.

**S2A-FR-029** — Forge publication state, if modeled, MUST remain separate from canonical review success/completeness.

---

## 6. Non-functional and security requirements seed

**S2A-NFR-001 Determinism:** identical admitted inputs MUST replay to identical canonical inventory/plan/unit identities and result ordering.

**S2A-NFR-002 Local-first:** S2A MUST work without network, cloud model, forge API or external scanner service.

**S2A-NFR-003 Dependency restraint:** initial S2A SHOULD use zero new third-party dependencies unless the active plan proves a necessary exact qualification.

**S2A-NFR-004 Resource bounds:** all untrusted counts/strings/metadata/relationships MUST be bounded with typed failures.

**S2A-NFR-005 Secret safety:** no secret plaintext may enter persisted checkpoint payloads, model context or diagnostics outside existing explicit safe boundaries.

**S2A-NFR-006 No target execution:** ordinary S2A review MUST NOT build/install/run target repository code.

**S2A-NFR-007 Cross-platform:** any semantics claimed platform-independent MUST qualify on Linux/macOS/Windows or explicitly narrow support.

**S2A-NFR-008 Replay safety:** a prior incomplete/failed/timed-out/cancelled result cannot be upgraded through reuse.

**S2A-NFR-009 No-green-by-omission:** frozen fixtures must prove zero false fully-complete result when mandatory work is absent.

---

## 7. Data model seed

The future `data-model.md` should freeze at least these conceptual types.

### `ReviewItem`

```text
item_id
old_path?
new_path?
change_kind
old_content_identity?
new_content_identity?
content_class
observed_size/work metadata
selection_state
selection_reason
mandatory_security_review
applicable_producer_ids[]
review_unit_id?
execution_state
coverage_refs[]
```

### `ReviewPlan`

```text
plan_schema_version
repository_identity
base_revision_identity
candidate_revision_identity
change_inventory_digest
risk_profile
risk_reason_codes[]
review_items[]
review_units[]
producer_assignments[]
limits
unsupported/deferred item refs[]
plan_digest
```

### `ReviewUnit`

```text
unit_id
item_ids[]
semantic_basis
producer/profile requirements[]
deterministic_work_identity
```

### `ChangeReviewManifest`

```text
manifest_schema_version
run_identity
review_plan_digest
selected/completed/reused/failed/timed_out/cancelled/deferred sets
resource/work counters
coverage_refs[]
regression_refs[]
finding_refs[]
policy_decision_ref?
advisory_refs[]
completeness_state
reason_codes[]
publication_refs[]
```

### `ReviewReuseProof`

```text
source_run_id
source_unit_id
source_result_digest
repository_identity
base/candidate relevant identities
review_plan_compatibility_identity
producer/version/config/rule identities
policy/profile identity
schema version
freshness state
reuse_digest
```

### `ModelContextManifest`

```text
context_manifest_id
run_id
context item ids/digests
redaction/truncation facts
provider/model/template/tool identities
instruction authority class
advisory capability ceiling
```

### `ReviewPublicationRecord`

```text
publication_id
run_id
channel/adapter identity
candidate revision identity
publication state
external object refs[]
created/updated identity or timestamps as non-semantic metadata
supersedes/superseded_by?
```

---

## 8. Enum/state seed

### Selection

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

### Unit execution

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

### Run completeness

```text
COMPLETE
INCOMPLETE
FAILED
CANCELLED
```

### Publication

```text
NOT_REQUESTED
PENDING
PUBLISHED
PARTIAL
FAILED
SUPERSEDED
```

### Advisory

```text
PROPOSED
RETAINED
REJECTED
STALE
SUPERSEDED
```

The successor clarification pass may rename values for consistency, but MUST preserve the authority distinctions.

---

## 9. Reason-code seed

The successor contract should include typed reasons at least for:

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
STALE_REVISION
```

S2A should not claim verification-specific authorization/proof errors as its own unless they are needed by a shared generic contract.

---

## 10. Planned module ownership seed

```text
sentrdel-review/src/orchestration/
  change_inventory.rs
  item.rs
  planner.rs
  review_unit.rs
  risk_profile.rs
  run_manifest.rs
  completeness.rs
  reuse.rs
  advisory.rs
  publication.rs
  limits.rs
  error.rs
```

Add modules only as dependency-ordered tasks require them.

Persistence is a later S2A packet in `sentrdel-store`; CLI composition remains in `sentrdel-cli`.

---

## 11. Task DAG seed

These are seed IDs, not active canonical tasks.

```text
S2A-T001  Bootstrap active successor Spec Kit + Constitution Check
   |
S2A-T002  Exact immutable change inventory + limits/errors
   |
S2A-T003  Selection state/reason model + deterministic planner
   |
S2A-T004  Deterministic review-unit partition
   |
S2A-T005  Deterministic risk-profile derivation
   |
S2A-T006  Run item/unit state model + ChangeReviewManifest
   |
S2A-T007  Completeness reducer + no-green-by-omission tests
   |
S2A-T008  Target-independent work/resource accounting
   |
S2A-T009  Pure ReviewReuseProof validation/invalidation
   |
S2A-T010  Advisory/model context provenance + publication state model
   |
S2A-T011  Store persistence/readback adapter + redaction/integrity
   |
S2A-T012  CLI composition of inventory -> plan -> review -> completeness -> checkpoint
   |
S2A-T013  Full adversarial/determinism/cross-platform conformance
   |
S2A-T014  Exact-head qualification + ledger closeout + protected-main proof
```

Possible safe parallelism after T003:

- T004 and T005 MAY proceed independently only if their shared selection/planner contracts are frozen and they touch separable modules;
- persistence T011 MUST NOT precede pure reuse semantics T009;
- CLI composition T012 MUST wait for the pure domain and store adapter contracts it consumes.

---

## 12. Per-task acceptance seed

### T002 inventory

Pass only if:

- every fixture changed item appears exactly once;
- ordering is deterministic;
- hostile/malformed paths fail safely;
- deleted/binary/oversized/unsupported items remain visible;
- rename ambiguity is not silently joined;
- caps fail visibly;
- no target execution/network is introduced.

### T003 planner

Pass only if:

- same admitted input => same plan digest;
- permutation => same canonical plan;
- mandatory work cannot be disabled by repo config;
- unknown content stays visible;
- preview and execution can consume the same plan object/identity.

### T006/T007 manifest + completeness

Pass only if failed/timed-out/cancelled/deferred/unsupported mandatory work cannot yield `COMPLETE`, including zero-finding cases.

### T009 reuse

Pass only if exact reuse succeeds and each relevant drift class invalidates reuse deterministically.

### T011 persistence

Pass only if corrupt/foreign/future-schema/stale data never becomes reuse authority, redaction applies before persistence, and readback identity is validated.

### T012 composition

Pass only if CLI/application code coordinates components without duplicating planner/completeness semantics.

---

## 13. Required adversarial fixtures seed

At minimum:

- mutable ref resolves then moves;
- same path different bytes;
- Unicode/case/path edge cases;
- ambiguous rename;
- huge item count;
- oversized metadata;
- duplicate stable item IDs;
- mandatory producer failure;
- timeout;
- cancellation;
- cap exhaustion;
- unsupported mandatory item;
- repo config suppression attempt;
- valid reuse;
- one-byte source drift invalidation;
- producer-version drift;
- rule/config drift;
- policy/profile drift;
- foreign repo reuse;
- forged source run ID;
- stale checkpoint;
- corrupted persisted manifest;
- advisory/model suppression attempt;
- scheduler-order permutation;
- Linux/macOS/Windows deterministic equivalence where claimed.

---

## 14. Implementation-readiness checklist seed

The active successor checklist should include at least:

### Authority

- [ ] no new Finding authority;
- [ ] no new policy authority;
- [ ] no verification authority;
- [ ] no target execution/network/model requirement;
- [ ] repository config cannot widen core permissions or disable mandatory evidence/review accounting.

### Architecture

- [ ] `sentrdel-review` remains persistence-agnostic;
- [ ] store adapter owns persistence only;
- [ ] CLI/application owns composition/I/O only;
- [ ] no premature public schema expansion;
- [ ] no unnecessary new crate;
- [ ] new dependency count is zero or every addition is separately qualified.

### Determinism

- [ ] canonical serialization defined;
- [ ] item/plan/unit/run identity inputs defined;
- [ ] canonical ordering defined;
- [ ] target-independent resource accounting defined;
- [ ] scheduler timing cannot alter semantic result.

### Completeness

- [ ] mandatory work definition frozen;
- [ ] completeness reducer frozen;
- [ ] waiver behavior frozen;
- [ ] failure/timeout/cancel/cap/unsupported semantics frozen;
- [ ] no-green-by-omission tests enumerated.

### Reuse

- [ ] compatibility/invalidation key frozen;
- [ ] stale/invalid/corrupt behavior frozen;
- [ ] persistence lookup is not reuse authority;
- [ ] fresh-work fallback behavior defined.

### Qualification

- [ ] targeted tests listed;
- [ ] cross-platform claims listed;
- [ ] full affected-crate tests listed;
- [ ] self-security/schema-lock/dependency gates selected as applicable;
- [ ] exact-head independent review required;
- [ ] ledger-closeout second-head requalification required;
- [ ] protected-main post-merge proof required.

---

## 15. Constitution Check seed

The successor `plan.md` should explicitly record:

- **Principle I:** orchestration remains Rust trusted core; external/model code is not required.
- **Principle II:** completeness is separate from Evidence/Coverage/Finding and missing work is visible.
- **Principle III:** local-first; no proprietary service requirement.
- **Principle IV:** repo config cannot weaken hard mandatory work.
- **Principle V:** S2 does not activate verification/target execution.
- **Principle VI:** provider-specific breadth is not part of S2A.
- **Principle VII:** mature external mechanics may inform design but judgment remains Sentrdel-owned.
- **Principle VIII:** latency/memory/completeness correctness enter benchmarks.
- **Principle IX:** paths/config/model/output/checkpoints are untrusted and bounded/redacted.
- **Principle X:** implementation begins only after the full active Spec Kit lifecycle is internally consistent.

Any exception must use the Constitution's Complexity/Exception mechanism.

---

## 16. Stop-and-escalate conditions

An implementation task must stop expanding and return to spec/clarification if it discovers a need for:

- a new public schema not already authorized;
- a new third-party dependency;
- a new crate;
- network access;
- model/provider requirement;
- target code/process execution;
- credential access;
- new policy/Finding/verification authority;
- review->store dependency;
- compatibility-breaking enum/identity semantics;
- a rule that would let repo config suppress mandatory review;
- a persistence format that cannot satisfy redaction/integrity/readback validation.

Do not smuggle any of these through an implementation PR.

---

## 17. Success definition

S2A is complete only when Sentrdel can prove, locally and deterministically, for an exact admitted change:

1. every changed item is accounted for;
2. one review plan explains what will run and why;
3. mandatory work is explicit;
4. run execution state is explicit;
5. run completeness cannot be inferred from finding count;
6. failed/missing mandatory work cannot become green;
7. reuse is exact and independently validated;
8. optional persistence cannot create semantic authority;
9. advisory/model context remains lower-authority;
10. the resulting pure contract is ready for S2B to expose through stable developer/machine output.

That is the gate that makes GitHub/forge delivery safe to build next.