# S2B Developer Review Experience Spec Bootstrap — 2026-09-16

**Status:** `FUTURE_SPEC_SEED / NO IMPLEMENTATION AUTHORITY`  
**Derives from:** `implementation-master-plan-2026-09-16.md`, `developer-adoption-and-trust-plan-2026-09-16.md`, and the future canonical S2A contracts  
**Activation condition:** S2A canonical completion plus ordinary successor Spec Kit creation/clarification/readiness  
**Purpose:** make the first developer-facing Sentrdel product slice nearly mechanical to specify and implement without inventing CLI, trust, outcome, remediation, redaction, or product-quality semantics.

> This is not an active numeric Spec Kit and deliberately reserves no future spec number. When S2B becomes eligible, create the next valid Spec Kit from live protected-main truth and copy only still-valid normative decisions from this seed.

---

## 1. Proposed feature title

**Developer Security Review Experience**

Suggested slug:

```text
developer-security-review-experience
```

---

## 2. Product objective

Expose Sentrdel's canonical review truth through one local developer experience that is:

```text
fast
quiet
explainable
machine-readable
agent-compatible
local-first
explicit about incompleteness
```

The feature must not create a second security judgment path.

Primary promise:

> **A developer can run one local review, understand whether the exact change may proceed, see what is blocking or unknown, inspect why, and hand bounded remediation context to a human or coding agent without giving the remediation actor authority over the verdict.**

---

## 3. Scope

### In scope

- deterministic developer-facing outcome projection over canonical S2A review truth;
- terminal information architecture;
- stable versioned machine output;
- exit-code contract;
- local `review`, `preview`, and `explain` behavior;
- zero/minimal-configuration defaults;
- setup/environment diagnostics;
- optional `init` helper behavior;
- deterministic redaction/truncation;
- structured remediation/agent handoff packets;
- non-semantic progress events;
- local product-quality telemetry/benchmark fields;
- golden developer UX fixtures;
- onboarding/reference documentation;
- compatibility policy for the external local review protocol.

### Out of scope

- GitHub/GitLab API calls;
- IDE extension implementation;
- hosted account requirement;
- hosted control plane;
- mandatory cloud/model provider;
- target repository build/install/code execution;
- dynamic verification implementation;
- autonomous merge;
- autonomous Finding dismissal;
- organization billing/seat management;
- broad new scanner admission solely for UX;
- CTI workbench/cases/runtime response.

---

## 4. Required architecture decision

S2B should preserve:

```text
sentrdel-review = canonical review/completeness/judgment projection inputs
sentrdel-schema = stable external machine protocol only if the schema gate requires it
sentrdel-cli    = command parsing, rendering, local I/O, exit-code projection
sentrdel-store  = optional eligible history/checkpoint retrieval only through S2A contracts
```

The CLI MUST NOT duplicate completeness, Finding, policy, risk-profile, or reuse semantics.

Human and machine output MUST be projections over the same canonical review record.

---

## 5. Developer outcome projection seed

S2B should freeze a pure derived state equivalent to:

```text
READY_COMPLETE
READY_WITH_ADVISORIES
BLOCKED
INCOMPLETE
FAILED
CANCELLED
```

The exact enum names may change during clarification, but the distinctions may not collapse.

### Projection inputs

At minimum:

```text
run_completeness
policy_decision
canonical blocking findings/regressions
retained advisory presence
```

### Required precedence

```text
FAILED/CANCELLED terminal truth
  > mandatory INCOMPLETE truth
  > BLOCKED policy/canonical blocking truth
  > READY_* presentation
```

`READY_*` MUST NOT exist when mandatory review is incomplete.

A separate verification field carries stronger proof state and cannot be inferred from readiness.

---

## 6. Functional requirements seed

### Core local review

**S2B-FR-001** — A supported developer MUST be able to invoke a meaningful local review without a hosted account.

**S2B-FR-002** — Core local review MUST NOT require a cloud model, remote forge, hosted database, or network service.

**S2B-FR-003** — Default review MUST consume canonical S2A inventory/plan/run truth rather than rediscovering scope independently.

**S2B-FR-004** — Human and machine output for the same run MUST bind the same immutable run/candidate identity.

**S2B-FR-005** — The first human-readable block MUST show outcome, completeness, exact change identity, blocking/actionable summary, unknown/missing work, and verification state before deep provenance detail.

### Developer outcome

**S2B-FR-006** — The developer-facing outcome MUST be a deterministic projection over canonical review truth and MUST NOT create new Finding/policy/completeness authority.

**S2B-FR-007** — `INCOMPLETE` MUST visually and machine-readably dominate any otherwise-permissive policy result.

**S2B-FR-008** — Zero findings MUST NOT produce a ready/clean presentation when mandatory review is incomplete.

**S2B-FR-009** — Verified status MUST be represented separately and only from admitted verification proof state.

### Machine protocol

**S2B-FR-010** — The local machine protocol MUST be explicitly versioned.

**S2B-FR-011** — Machine output MUST expose separate fields for at least run identity, completeness, developer outcome, policy decision, regression summary, Coverage summary, canonical findings, unknown/missing work, advisories, verification state, and protocol version.

**S2B-FR-012** — Unknown future fields and enum values MUST follow an explicit forward/backward compatibility policy.

**S2B-FR-013** — Human rendering changes MUST NOT silently change machine semantics.

### Exit codes

**S2B-FR-014** — Exit codes MUST distinguish successful execution from merge-readiness/security outcome.

**S2B-FR-015** — Incomplete mandatory review MUST be machine-distinguishable from policy blocking even if the active spec chooses to share a process exit class.

**S2B-FR-016** — Internal execution failure/cancellation MUST remain distinguishable from a valid completed blocked review.

### Preview and explain

**S2B-FR-017** — Preview MUST consume the exact canonical `ReviewPlan` identity intended for execution.

**S2B-FR-018** — Explain MUST trace a developer-visible result to canonical Finding/regression/policy/completeness and then to Evidence/Coverage/invariant/provenance references without requiring log parsing.

**S2B-FR-019** — Explain MUST expose authority level and known uncertainty/unsupported state.

**S2B-FR-020** — Explain MUST distinguish external/native severity/confidence from Sentrdel canonical judgment.

### Setup and diagnostics

**S2B-FR-021** — A diagnostic command or equivalent MUST classify setup problems by installation/toolchain, repository state, configuration, optional integration, producer, storage, and policy categories.

**S2B-FR-022** — Diagnostics MUST NOT silently modify repository security policy, install privileged dependencies, widen permissions, or enable target execution.

**S2B-FR-023** — An initialization helper MAY create optional configuration but ordinary supported review MUST remain useful without mandatory generated config where safe defaults exist.

**S2B-FR-024** — Repository configuration MUST be tightening-only relative to mandatory review/security accounting.

### Redaction and truncation

**S2B-FR-025** — Secret/credential plaintext MUST NOT leak through human output, machine protocol, explain output, diagnostics, progress events, remediation packets, or persisted presentation caches.

**S2B-FR-026** — Truncation MUST be deterministic where output compatibility depends on it and MUST be visibly declared.

**S2B-FR-027** — Truncation MUST NOT hide the existence/count/identity of canonical blocking or incomplete states.

### Remediation and agent handoff

**S2B-FR-028** — Every eligible actionable result SHOULD be able to produce a structured `RemediationPacket` bound to exact run/candidate/result identity.

**S2B-FR-029** — A remediation packet MUST contain constraints and authority ceiling and MUST NOT claim a suggested patch is correct or verified.

**S2B-FR-030** — Any changed candidate after remediation MUST trigger fresh review/reuse validation under ordinary S2A rules.

**S2B-FR-031** — A coding-agent integration MUST NOT dismiss canonical Findings, grant verification authorization, expand tool/network/credential authority, or mark its own remediation verified.

### Progress

**S2B-FR-032** — Progress events MAY expose non-semantic execution progress such as plan frozen, units complete, producer progress, and remaining mandatory work.

**S2B-FR-033** — Progress event timing/order MUST NOT enter canonical review identity or alter canonical result ordering.

**S2B-FR-034** — Early actionable output before terminal completion MUST remain explicitly provisional/partial and MUST NOT display terminal ready/green state.

### Product-quality telemetry

**S2B-FR-035** — The benchmark path MUST record cold/warm latency, time to first actionable result, time to terminal completeness, peak memory/work counters, output size, and reuse metrics with exact build/fixture/profile identity.

**S2B-FR-036** — Product-quality telemetry MUST NOT contain source secrets/credential plaintext.

**S2B-FR-037** — Performance optimization MUST NOT skip mandatory work without changing completeness state.

### Documentation/onboarding

**S2B-FR-038** — Reference documentation MUST show first review, incomplete review, blocking review, explain, remediation rerun, and machine-output examples.

**S2B-FR-039** — Known unsupported/partial semantics MUST be documented without implying clean coverage.

**S2B-FR-040** — The first supported local journey MUST be executable from published documentation without requiring undocumented architecture knowledge.

---

## 7. Non-functional/security requirements seed

**S2B-NFR-001 Determinism:** equal canonical run truth MUST produce semantically equal machine output; deterministic human sections must replay where explicitly claimed.

**S2B-NFR-002 Local-first:** supported core review/explain MUST work offline from hosted Sentrdel services after installation and required local dependencies are available.

**S2B-NFR-003 No target execution:** S2B MUST NOT introduce build/install/run of target repository code.

**S2B-NFR-004 Dependency restraint:** new third-party dependencies require exact justification/qualification; presentation convenience is not sufficient reason for privileged/native dependency growth.

**S2B-NFR-005 Secret safety:** all developer-facing channels inherit existing redaction and untrusted-input handling requirements.

**S2B-NFR-006 Bounded output:** untrusted strings/counts/nesting and generated output MUST be bounded.

**S2B-NFR-007 Accessibility:** terminal text and later UI semantics MUST not rely on color alone to communicate blocking/incomplete/verified state.

**S2B-NFR-008 Cross-platform:** CLI behavior claimed portable MUST qualify on Linux/macOS/Windows or explicitly narrow support.

**S2B-NFR-009 Compatibility:** protocol meaning cannot silently change under the same version.

**S2B-NFR-010 No popularity authority:** user/adoption/feedback telemetry cannot change security judgment in the active run.

---

## 8. Data-model seed

### `DeveloperReviewSummary`

```text
protocol_version
run_identity
candidate_revision_identity
outcome
run_completeness
policy_decision
regression_summary
coverage_summary
canonical_finding_summary
unknown_work_summary
verification_summary
advisory_summary
reuse_summary
explain_refs[]
render_metadata
```

### `DeveloperReviewOutcome`

Conceptual values:

```text
READY_COMPLETE
READY_WITH_ADVISORIES
BLOCKED
INCOMPLETE
FAILED
CANCELLED
```

### `UnknownWorkSummary`

```text
mandatory_missing_count
unsupported_count
failed_count
timed_out_count
deferred_count
cancelled_count
reason_codes[]
item_or_unit_refs[]
```

### `RemediationPacket`

```text
packet_version
run_identity
candidate_revision_identity
canonical_result_id
result_kind
summary
why_it_matters
exact_evidence_refs[]
affected_scope_refs[]
source_span_refs[]
constraints[]
prohibited_actions[]
suggested_remediation_goals[]
verification_requirement?
packet_digest
```

### `ProgressEvent`

```text
run_identity
event_kind
nonsemantic_sequence_or_timestamp
completed_units?
remaining_mandatory_units?
producer_ref?
message_code
redacted_display_fields
```

Progress events are explicitly excluded from canonical semantic identity.

### `ProductBenchmarkRecord`

```text
benchmark_schema_version
sentrdel_build_identity
fixture_identity
profile_identity
platform_identity
cold_or_warm
latency_metrics
work_counters
memory_metrics
output_metrics
reuse_metrics
result_digest
```

---

## 9. Presentation reason-code seed

In addition to canonical security/run reason codes, S2B may need presentation/diagnostic reasons such as:

```text
SETUP_REPOSITORY_NOT_FOUND
SETUP_UNSUPPORTED_REPOSITORY_STATE
SETUP_OPTIONAL_INTEGRATION_UNAVAILABLE
CONFIG_INVALID
CONFIG_REJECTED_AUTHORITY_WIDENING
OUTPUT_REDACTED
OUTPUT_TRUNCATED
EXPLAIN_REFERENCE_NOT_FOUND
REMEDIATION_PACKET_STALE
PROTOCOL_VERSION_UNSUPPORTED
```

These do not replace underlying canonical reason codes.

---

## 10. Planned ownership seed

Prefer existing crates/modules.

```text
sentrdel-review
  developer_projection.rs   # pure derived outcome/summary inputs if domain-owned
  remediation.rs            # pure packet construction/validation if appropriate

sentrdel-cli
  commands/review.rs
  commands/explain.rs
  commands/doctor.rs
  commands/init.rs
  render/human.rs
  render/json.rs
  progress.rs
  exit_codes.rs

sentrdel-schema
  only stable public/machine protocol types approved by the S2B schema gate
```

Exact module names are seeds. The active Spec Kit must inspect live crate layout before freezing paths.

Do not create a new crate unless the canonical new-crate rule is proven.

---

## 11. Task DAG seed

These are future seed IDs, not active tasks.

```text
S2B-T001  Bootstrap active S2B Spec Kit + Constitution/product checks
   |
S2B-T002  Freeze DeveloperReviewOutcome projection + summary model
   |
   +-----------------------------+
   |                             |
   v                             v
S2B-T003  Human output IA       S2B-T004  Versioned machine protocol
   |                             |
   +---------------+-------------+
                   |
                   v
S2B-T005  Exit-code contract + automation semantics
                   |
        +----------+-----------+
        |                      |
        v                      v
S2B-T006 Preview/explain     S2B-T007 Setup/doctor/init + config diagnostics
        |                      |
        +----------+-----------+
                   |
                   v
S2B-T008 Redaction/truncation/output bounds
                   |
        +----------+-----------+
        |                      |
        v                      v
S2B-T009 Remediation packet  S2B-T010 Progress/benchmark telemetry
        |                      |
        +----------+-----------+
                   |
                   v
S2B-T011 Golden UX/adversarial fixtures
                   |
                   v
S2B-T012 Cross-platform + compatibility + performance baseline
                   |
                   v
S2B-T013 Onboarding/reference docs + first-run journey proof
                   |
                   v
S2B-T014 Exact-head qualification + ledger closeout + protected-main proof
```

### Dependency notes

- T003 and T004 may proceed in parallel after T002 only if the summary/outcome contract is frozen.
- T006/T007 may proceed after T005 with separable modules.
- T009 cannot precede exact result identity/protocol semantics required to bind remediation packets.
- T011 must exercise every public developer state before performance baseline closeout.
- T013 documentation examples must be generated/verified against real supported behavior, not aspirational commands.

---

## 12. Per-task acceptance seed

### T002 outcome projection

Pass only if:

- every canonical completeness/policy/blocking combination maps deterministically;
- incomplete mandatory work cannot map to `READY_*`;
- verification is separate;
- advisory presence cannot override blocking/incomplete truth;
- projection has authority-negative tests.

### T003 human output

Pass only if:

- first block exposes outcome/completeness/blockers/unknowns/verification;
- no color-only critical state;
- no dominant green `ALLOW` under incompleteness;
- canonical counts match manifest truth;
- secret fixtures remain redacted.

### T004 machine protocol

Pass only if:

- schema is versioned;
- semantic compatibility policy exists;
- equal run truth replays equal semantic output;
- unknown/missing work is first-class;
- protocol can represent future forge/IDE projection without log scraping.

### T005 exit codes

Pass only if automation can distinguish:

- command/execution success;
- review incomplete;
- review blocked;
- internal failure;
- cancellation;

according to the final active contract.

### T006 preview/explain

Pass only if preview binds the exact plan identity and explain reaches underlying canonical references without heuristic reconstruction.

### T007 setup diagnostics

Pass only if supported first-run failure modes are typed and no diagnostic action silently widens security authority.

### T008 redaction/truncation

Pass only if secret/credential fixtures cannot appear in any public output channel and truncation cannot hide state existence/count.

### T009 remediation

Pass only if packet identity becomes stale on candidate/result drift and an agent cannot convert remediation proposal into verified/dismissed state.

### T010 telemetry

Pass only if telemetry does not alter semantics, bind secrets, or make scheduler timing part of canonical identity.

### T011 fixtures

Must include all journeys in Section 14 and the adversarial cases below.

### T012 baseline

Pass only if Linux/macOS/Windows claimed behavior qualifies and product metrics are bound to exact build/fixture/profile identity.

### T013 onboarding

Pass only if a clean reference environment can follow published steps to first review and explain without undocumented manual repair.

---

## 13. Required adversarial fixtures seed

At minimum:

- policy `ALLOW` + incomplete run;
- zero findings + timeout;
- blocking finding + many advisories;
- unsupported mandatory item;
- failed producer;
- cancelled run;
- malformed machine-protocol consumer input where applicable;
- unknown future enum/field compatibility fixture;
- secret in path/content/producer diagnostic;
- huge diagnostic/advisory strings;
- truncation at boundary;
- stale explain ID;
- stale remediation packet after one-byte candidate change;
- agent claims issue fixed without rerun;
- agent attempts Finding dismissal;
- repo config attempts mandatory suppression;
- repo config attempts authority widening;
- no network;
- no hosted account;
- optional model unavailable;
- invalid local storage/history record;
- progress events reordered;
- scheduler-order permutation;
- platform path/Unicode cases;
- cold vs valid warm semantic equivalence.

---

## 14. Golden developer journeys seed

### J1 — zero-config complete review

A supported repository receives a meaningful complete local review without hosted authentication or project config.

### J2 — incomplete review

Mandatory work fails/times out/is unsupported. `INCOMPLETE` is dominant in human/machine output.

### J3 — blocking regression

The developer sees exact blocking security-property change plus explain path to evidence/provenance.

### J4 — advisory-only change

Review is complete/permitted with retained advisories. Advisories cannot masquerade as canonical Findings.

### J5 — explain drill-down

A developer can trace the top-level result to the exact canonical data without reading logs.

### J6 — agent remediation

A `RemediationPacket` is generated, an external agent changes code, the packet becomes stale for the new revision, and fresh review/reuse validation determines the new result.

### J7 — secret-safe output

Inputs contain credential-like material; all public output remains safe while still identifying that redaction occurred.

### J8 — warm rerun

Valid units reuse; invalidated units rerun; final semantic output matches a cold equivalent.

### J9 — offline local path

Core review/explain works without hosted Sentrdel services/network after installation and local prerequisites.

### J10 — first-run diagnosis

Broken environment/setup produces actionable typed `doctor` output without automatically weakening controls.

---

## 15. Product benchmark seed

Hard correctness remains inherited from the canonical master plan.

Record these product dimensions:

```text
setup_to_first_review
cold_review_latency
warm_review_latency
time_to_first_actionable
time_to_terminal_completeness
peak_memory
work_counters
machine_output_bytes
human_output_lines_or_bytes
reuse_hit_rate
explain_lookup_latency
```

Do not freeze arbitrary performance thresholds until a reproducible baseline exists. The active S2B plan must define how the first baseline becomes canonical and how regressions are judged.

---

## 16. Implementation-readiness checklist seed

### Authority

- [ ] outcome projection is derived only;
- [ ] no new Finding/policy/verification authority;
- [ ] no target execution/network/model requirement;
- [ ] incomplete review cannot become ready;
- [ ] remediation actor cannot self-verify.

### Local product

- [ ] no hosted account required for claimed core path;
- [ ] review/preview/explain behaviors frozen;
- [ ] setup diagnostics frozen;
- [ ] config authority rules frozen;
- [ ] offline behavior stated.

### Protocol

- [ ] version frozen;
- [ ] fields/enums frozen;
- [ ] compatibility rules frozen;
- [ ] exit-code contract frozen;
- [ ] deterministic projection rules frozen.

### Safety

- [ ] redaction sources/outputs enumerated;
- [ ] truncation rules frozen;
- [ ] output/resource caps frozen;
- [ ] hostile strings/path/config cases enumerated.

### Remediation

- [ ] packet identity fields frozen;
- [ ] staleness rules frozen;
- [ ] authority ceiling frozen;
- [ ] agent re-review loop frozen.

### Quality

- [ ] golden journeys frozen;
- [ ] adversarial fixtures frozen;
- [ ] benchmark fields frozen;
- [ ] baseline procedure frozen;
- [ ] cross-platform claims frozen;
- [ ] onboarding journey has an executable test/check plan.

### Governance

- [ ] task DAG internally consistent;
- [ ] crate ownership explicit;
- [ ] public schema decision explicit;
- [ ] dependency changes zero or separately qualified;
- [ ] CI/review/ledger/post-main closeout gates stated.

---

## 17. Constitution/product check seed

The future active plan must explicitly confirm:

- local-first behavior remains real, not a marketing mode requiring cloud services;
- human/machine projections preserve Evidence/Coverage/completeness distinctions;
- developer convenience does not activate verification/target execution;
- repo config cannot weaken mandatory work;
- model/agent output remains lower-authority;
- external integrations remain optional projections;
- product metrics cannot rewrite evaluator truth;
- secrets/untrusted inputs remain bounded/redacted;
- no public protocol ships without compatibility/version decisions.

---

## 18. Stop-and-escalate conditions

Return to spec/clarification if implementation discovers a need for:

- new canonical security authority;
- a new public schema field with unresolved compatibility meaning;
- a new crate;
- new third-party dependency not already qualified;
- mandatory network/cloud/account requirement;
- target code execution;
- credential access;
- hidden state not representable in machine output;
- a performance optimization that would skip mandatory work without incompleteness;
- a UX requirement that would hide a canonical blocking/incomplete state;
- remediation behavior that would let an agent self-approve;
- platform-specific semantics that break claimed cross-platform behavior.

Do not smuggle these decisions through a rendering/CLI PR.

---

## 19. S2B success definition

S2B is complete only when Sentrdel can prove, on protected main with real qualification, that:

1. a developer can run the supported core review locally without a hosted account;
2. one top-level output makes policy, completeness, blockers, unknowns, and verification impossible to confuse;
3. the same truth is available in a stable versioned machine protocol;
4. preview/explain bind exact canonical identities;
5. secret-safe redaction/truncation is proven;
6. automation exit semantics are unambiguous;
7. agent remediation context is structured but lower-authority;
8. changed remediation revisions require fresh review/reuse validation;
9. progress/telemetry cannot alter canonical semantics;
10. golden developer journeys and adversarial cases pass across claimed platforms;
11. performance/product-quality baselines are reproducible;
12. published onboarding can reach first useful review without undocumented architecture knowledge.

That is the gate required before Sentrdel should make GitHub the reference external developer experience.