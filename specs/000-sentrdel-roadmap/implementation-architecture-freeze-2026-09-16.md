# Sentrdel Post-S1 Implementation Architecture Freeze — 2026-09-16

**Status:** `ARCHITECTURE_FREEZE_CANDIDATE / NO CURRENT IMPLEMENTATION AUTHORITY`  
**Companion to:** `implementation-master-plan-2026-09-16.md`  
**Protected-main architecture inspected at:** `13d0a068ea1df5480adc38373b34a6650d782885`  
**Purpose:** remove implementation ambiguity for the first post-S1 product path without widening the active S1 Spec Kit.

This document freezes the default architecture that future S2A/S2B/S3 Spec Kits should adopt unless a concrete repository constraint proves a different design is necessary.

---

## 1. Existing workspace facts

The current workspace already provides the correct major ownership boundaries:

```text
sentrdel-schema   public canonical/wire data contracts
sentrdel-store    local SQLite persistence + redaction boundary
sentrdel-engine   producer/engine execution
sentrdel-graph    bounded semantic graph projection
sentrdel-policy   policy semantics
sentrdel-guard    controllable guard semantics
sentrdel-review   local evidence-first review + S1 regression
sentrdel-verify   reserved verification boundary; execution disabled until authorized
sentrdel-cli      composition host + presentation; already depends on review/store/etc.
```

At the inspected main, `sentrdel-review` depends on `sentrdel-schema` but **does not depend on `sentrdel-store`**. `sentrdel-cli` already depends on both.

That dependency shape is intentional and should be preserved through S2 unless an active Spec Kit proves otherwise.

---

## 2. Frozen dependency direction for S2

```text
sentrdel-schema
      ^
      |
sentrdel-review      sentrdel-store
      ^                  ^
      |                  |
      +-------- sentrdel-cli --------+
                                   other existing core crates
```

### Hard rule

**Do not add `sentrdel-review -> sentrdel-store` merely to implement checkpoint/resume.**

The review crate owns deterministic domain semantics. Persistence is an adapter concern composed by the CLI/application host.

This prevents:

- SQLite/I/O errors from becoming hidden review semantics;
- persistence schema from dictating canonical review identity;
- cyclic dependency pressure;
- unit tests requiring persistent I/O for pure planner/completeness logic;
- future alternate hosts from inheriting SQLite as a mandatory review dependency.

---

## 3. S2A module layout

The preferred future layout inside `sentrdel-review` is:

```text
crates/sentrdel-review/src/orchestration/
  mod.rs
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

Do not create all files in one bootstrap PR. Add them dependency-order as the active task requires.

### Ownership

`change_inventory.rs`
: Exact immutable changed-surface inventory and normalized item identity.

`item.rs`
: Review-item classification/selection/execution states and typed reason codes.

`planner.rs`
: Pure deterministic `ReviewPlan` builder.

`review_unit.rs`
: Deterministic unit partition and stable unit identity.

`risk_profile.rs`
: Deterministic risk profile derivation plus reason codes.

`run_manifest.rs`
: Domain manifest state; no database code.

`completeness.rs`
: Pure reducer from item/unit states to run completeness.

`reuse.rs`
: `ReviewReuseProof` validation/invalidation semantics; no persistence lookup.

`advisory.rs`
: Lower-authority advisory/model provenance contracts.

`publication.rs`
: Forge-neutral publication identity/state only; no GitHub client.

`limits.rs`
: Target-independent count/byte/work limits used by orchestration.

`error.rs`
: Structured domain errors/reasons.

---

## 4. Persistence seam

Persistence belongs in `sentrdel-store` only after the pure S2A contracts are proven.

Preferred future store boundary:

```text
crates/sentrdel-store/src/migrations/review_run_store.rs
```

or an equivalent migration-owned module consistent with the repository's then-current store architecture.

### Persistence rules

1. Store semantics are downstream of the review-domain types.
2. A database row is never the canonical source of review identity merely because it exists.
3. Persist exact schema/version + canonical payload digest + repository/run identity.
4. Readback must validate stored identity/digest before a record can be considered for reuse.
5. Corrupt, foreign, future-schema, inconsistent or stale records fail visibly and cannot become reuse authority.
6. Redaction boundary applies before any potentially secret-bearing payload is persisted.
7. Migration preserves original provenance and cannot upgrade epistemic/authorization authority.
8. Store write failure may make checkpointing unavailable but must not rewrite an otherwise completed in-memory canonical review result.

### Preferred record shape

Keep canonical review-domain serialization separate from database indexing.

Conceptually:

```text
review_runs
  run_id
  repository_identity
  base_revision_identity
  candidate_revision_identity
  plan_digest
  manifest_schema_version
  manifest_digest
  manifest_payload
  completeness_state
  created_at

review_reuse_entries
  source_run_id
  unit_id
  result_digest
  compatibility_digest
  freshness_state
```

Exact SQL/table names are future migration decisions, but the semantic split above is frozen: indexed lookup fields are not substitutes for validating the canonical stored payload.

---

## 5. Composition host

`sentrdel-cli` is the first composition host for S2.

Preferred flow:

```text
CLI input
  -> resolve immutable repository/base/candidate identity
  -> build exact change inventory via sentrdel-review
  -> derive deterministic ReviewPlan via sentrdel-review
  -> optionally query sentrdel-store for candidate reuse records
  -> validate reuse proofs via sentrdel-review
  -> execute required existing producers/semantic review
  -> reduce run completeness via sentrdel-review
  -> persist eligible manifest/checkpoint through sentrdel-store
  -> render human/machine output via sentrdel-cli
```

The CLI may coordinate I/O. It must not duplicate planner, completeness, regression or authority semantics.

---

## 6. Public-schema boundary

### S2A default

Keep orchestration types crate-private or Rust-internal until the local semantics are stable.

Do **not** move `ReviewPlan`, `ReviewItem`, `ReviewUnit`, or internal completeness machinery into `sentrdel-schema` just because they cross modules inside `sentrdel-review`.

### S2B schema gate

Only S2B may propose the first stable machine-readable external review protocol.

The schema decision must explicitly answer:

- which fields are public compatibility commitments;
- whether internal plan details are exposed or projected;
- enum forward-compatibility behavior;
- unknown-field handling;
- version negotiation/migration expectations;
- whether local JSON is derived from public schema types or a dedicated projection.

A public schema cannot expose lower-level internal IDs as stable API unless their compatibility is intentionally frozen.

---

## 7. Serialization and identity freeze

Canonical identity serialization used for digests must be independent from display JSON.

Rules:

- canonical serialization is explicitly versioned;
- map/set data is sorted before serialization;
- enum encoding is stable and explicit;
- paths use the repository's canonical normalized representation;
- no debug formatting;
- no pointer-width-dependent accounting;
- no wall-clock fields in compatibility digests unless freshness is intentionally part of the identity;
- elapsed timing/telemetry never changes semantic plan identity;
- host OS differences cannot change identity for logically equivalent admitted inputs.

Display JSON may evolve separately behind its own protocol compatibility rules.

---

## 8. Configuration authority merge

S2 must not treat every configuration source as equally authoritative.

Preferred merge model:

```text
hard Sentrdel safety requirements
  + trusted operator/admin policy
  + repository project preferences where permitted
  + command invocation options where permitted
  -> effective review policy
```

### Repository-controlled configuration may

- request additional optional analysis;
- provide non-authoritative labels/grouping hints;
- tighten selected security work;
- configure presentation where it cannot hide mandatory state.

### Repository-controlled configuration may not

- disable hard mandatory security analysis;
- turn unsupported/failed/timed-out work into clean;
- grant model/network/credential/process/target authority;
- change canonical Finding authority;
- widen verification authorization;
- mark an invalid reuse proof valid;
- hide Coverage loss from machine output.

Every effective-policy decision that affects planning must have a reason/provenance path.

---

## 9. Concurrency model

S2 may execute independent review units concurrently, but concurrency is an optimization only.

Requirements:

1. ReviewPlan and review-unit identities are built before scheduling.
2. Scheduler order cannot affect canonical output ordering.
3. Final item/unit/result ordering is deterministic.
4. Aggregate resource counters are defined independently from race timing where they affect semantics.
5. Cancellation is explicit and leaves unfinished mandatory units incomplete.
6. A crashed worker cannot be mistaken for an empty successful producer result.
7. Partial results may be retained only with exact state/provenance and cannot make the run `COMPLETE`.
8. Replaying with one worker versus many must produce equivalent canonical result identities for the same admitted outcomes.

Do not introduce an async runtime or worker framework solely because parallelism may be useful later. Add concurrency infrastructure only when measured work justifies the dependency/capability cost.

---

## 10. Review-item inventory freeze

The future exact change inventory must represent every candidate change item, including non-analyzable items.

Minimum conceptual fields:

```text
item_id
old_path?
new_path?
change_kind
old_content_identity?
new_content_identity?
content_class
size/work observations
selection_state
selection_reason
mandatory_security_review
applicable_producer_ids[]
review_unit_id?
execution_state
coverage_refs[]
```

Required change-kind handling includes at least:

```text
ADD
MODIFY
DELETE
RENAME
COPY     # only where exact repository evidence admits it
TYPE_CHANGE
SUBMODULE_CHANGE
```

Binary/generated/oversized/unsupported are not change kinds by themselves; they are content/routing observations that must remain visible.

Rename/copy heuristic guesses cannot become stable identity authority.

---

## 11. Planner freeze

`ReviewPlan` is a pure function of admitted deterministic inputs.

Conceptually:

```text
ReviewPlan = plan(
  immutable_change_inventory,
  admitted_security_semantics,
  effective_trusted_policy,
  admitted_producer_capabilities,
  deterministic_artifact_observations,
  review_limits
)
```

Optional probabilistic/model observations may propose **additional** advisory/escalation work but cannot remove deterministic mandatory work.

`review --preview` and actual execution must consume the same plan bytes/digest. Execution must not independently rediscover scope using a second code path.

---

## 12. Completeness reducer freeze

Completeness is derived from explicit mandatory work, not findings.

Conceptual rule:

```text
COMPLETE iff
  every mandatory review item has an allowed terminal selection state
  AND every mandatory selected unit is COMPLETED or validly REUSED
  AND no mandatory prerequisite is invalid/stale/failed/timed-out/cancelled/deferred
```

If the future spec admits a trusted mandatory waiver, it must either:

- remain `INCOMPLETE` with accepted-risk metadata; or
- define a separately named completeness class that cannot be mistaken for fully executed coverage.

Do not silently count a waived mandatory item as executed.

---

## 13. Reuse persistence flow

Safe reuse is split into two authorities:

```text
sentrdel-store
  finds candidate historical records

sentrdel-review::orchestration::reuse
  validates whether one exact prior unit result is reusable
```

The store cannot declare reuse valid.

Invalid/corrupt/stale candidate records are ignored with typed diagnostics and fresh work is scheduled when permitted. They never downgrade required work to optional.

---

## 14. Forge architecture freeze

S3 must not make GitHub Actions, GitHub Checks, or a GitHub App the semantic core.

Preferred structure:

```text
canonical local review protocol
  -> forge-neutral publication projection
     -> GitHub adapter
     -> later GitLab/other adapter
```

The GitHub adapter owns API mechanics only:

- authentication/permissions;
- check lifecycle;
- annotations/comments;
- pagination/rate limits/retries;
- head/base verification;
- idempotency/supersession.

It does not own Finding severity, review completeness, Coverage, risk profile, or regression semantics.

---

## 15. Verification architecture freeze

`sentrdel-verify` stays dormant until S5 authorization.

When activated, dependency direction should preserve:

```text
trusted authorization/capability/proof contracts
  -> verify orchestration
  -> qualified isolation backend adapter
```

Backends such as gVisor/Firecracker/Wasmtime/OpenSandbox are implementation candidates, not authority roots.

Generic shell strings remain outside the trusted verification interface.

---

## 16. First post-S1 PR sequence

Once S1 is canonically complete and S2 is separately authorized, the preferred first sequence is:

### PR S2A-P1 — domain skeleton + exact inventory

Allowed scope:

- `sentrdel-review` orchestration module skeleton;
- exact change inventory types/normalization;
- limits/errors required by inventory;
- focused deterministic/adversarial tests;
- no store migration;
- no public schema;
- no CLI user-facing contract freeze.

### PR S2A-P2 — deterministic planner + risk profile

Allowed scope:

- planner;
- selection states/reasons;
- review-unit partition;
- risk-profile derivation;
- replay/order/config-authority tests.

### PR S2A-P3 — run manifest + completeness

Allowed scope:

- item/unit execution state;
- manifest;
- completeness reducer;
- no persistence yet;
- failure/timeout/cancel/cap tests.

### PR S2A-P4 — reuse proof

Allowed scope:

- pure reuse proof validation/invalidation;
- historical candidate fixture inputs only;
- no database dependency in `sentrdel-review`.

### PR S2A-P5 — store adapter/checkpoint persistence

Allowed scope:

- store migration/API;
- redaction/readback/integrity tests;
- CLI/application composition for storing/loading candidates;
- `sentrdel-review` remains persistence-agnostic.

### PR S2A-P6 — orchestration integration + adversarial closeout

Allowed scope:

- compose inventory -> plan -> run -> completeness -> persistence candidate flow;
- no S2B stable public output contract yet;
- full deterministic/cross-platform/adversarial qualification.

The active Spec Kit may split a PR further. It should not combine these packets into one mega-PR unless a concrete technical dependency proves independent qualification impossible.

---

## 17. Dependency-admission expectation

The first S2A implementation should prefer **zero new third-party dependencies**.

Existing `gix`, `serde_json`, schema types, standard library, and current workspace primitives should be sufficient for the first inventory/planner/run semantics unless the Spec Kit proves otherwise.

Any new dependency requires the ordinary exact dependency qualification and must explain why an existing workspace primitive is insufficient.

---

## 18. Implementation-ready architecture checklist

A future S2 implementation PR is architecturally conformant only if all applicable statements are true:

- [ ] `sentrdel-review` domain logic remains deterministic and persistence-agnostic.
- [ ] `sentrdel-store` persists/retrieves but does not decide semantic reuse validity.
- [ ] `sentrdel-cli` composes I/O without duplicating security semantics.
- [ ] no new public schema is introduced before the explicit S2B schema gate.
- [ ] no target execution/network/model requirement is introduced by S2.
- [ ] every changed item remains scope-accounted even if unsupported.
- [ ] planner preview and execution use one plan identity.
- [ ] repository configuration cannot suppress mandatory hard requirements.
- [ ] scheduler/concurrency order cannot affect canonical ordering/identity.
- [ ] failure/timeout/cancel/resource exhaustion cannot produce `COMPLETE`.
- [ ] reuse validation is pure, exact and fail-closed to fresh work.
- [ ] persistent checkpoints pass redaction, integrity and schema checks.
- [ ] forge delivery remains a projection over the local protocol.
- [ ] verification remains dormant until S5 authorization.

---

## 19. Architecture change control

A future agent may deviate from this freeze only when it records all of:

1. the exact repository constraint that makes the frozen design unsuitable;
2. the alternative dependency/authority shape;
3. why the alternative is smaller or safer;
4. compatibility/migration impact;
5. new dependency/privilege/public-schema effects;
6. tests proving no authority/completeness regression;
7. an active Spec Kit decision authorizing the deviation.

Convenience, preference, or framework familiarity is not sufficient justification.

---

## 20. Final architecture rule

The first post-S1 product must preserve this separation:

```text
PURE REVIEW DOMAIN
  exact inventory
  deterministic plan
  run/completeness truth
  reuse validity
  canonical security judgment references

ADAPTER / HOST LAYER
  repository I/O
  checkpoint persistence
  CLI
  forge APIs
  later server/IDE/agent transports
```

This is what allows Sentrdel to add resumability, GitHub delivery, models, scanners, verification and later control-plane services without turning any of those integrations into a second security authority.