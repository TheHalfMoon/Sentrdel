# Sentrdel Developer Adoption and Trust Plan — 2026-09-16

**Status:** `ACTIVE_SUPPORTING_SUPPLEMENT_CANDIDATE / NO CURRENT IMPLEMENTATION AUTHORITY`  
**Planning base:** `main@52b33b11eef3bde42c2d3da127a2a94a86cd51f8`  
**Active implementation frontier at creation:** `S1-T012` under `specs/004-security-invariant-regression/`  
**Primary inputs:** canonical Implementation Master Plan, S2A Review Orchestration bootstrap, full-project review, OpenCodeReview study, and `docs/third-party/developer-review-distribution-study-2026-09-16.md`  
**Purpose:** make developer adoption, trust, usability, distribution, explainability, low noise, remediation loops, and transparent product-quality gates first-class implementation requirements without weakening Sentrdel's security authority model.

> This document is product/implementation planning. It does not authorize S2, forge work, IDE work, agent integration, network access, hosted services, new dependencies, or any work outside the active Spec Kit.

---

## 1. Product North Star

Sentrdel should become:

> **The security reviewer every developer installs and every team can trust.**

The short product promise is:

> **Security review for every change.**

The category Sentrdel should aim to define is:

> **Agentic Software Security Review**

This is intentionally not the claim that Sentrdel replaces all cybersecurity products. The product is the trusted security-review and judgment layer for software change, from human-written code through AI-generated changes and later bounded runtime/verification evidence.

### 1.1 Developer-facing question

A developer should be able to understand, without reading logs or knowing Sentrdel internals:

> **Can this exact change proceed, what security-relevant thing changed, what evidence supports that conclusion, and what remains unknown?**

### 1.2 Security-facing question

A security engineer should be able to drill down and answer:

> **What exact inventory, Evidence, Coverage, invariant transition, Finding, policy, reuse proof, verification proof, and publication record produced this developer-facing result?**

The developer view is a projection over the same canonical truth. It is never a second judgment system.

---

## 2. Product principles

The following are cross-cutting product invariants for every future developer-facing slice.

### P1 — Correct before convenient

No UX simplification may:

- hide mandatory missing work;
- relabel `INCOMPLETE` as success;
- convert advisory/model output into Finding authority;
- let publication state rewrite analysis truth;
- treat zero findings as proof of safety;
- turn a remediation suggestion into verified remediation.

### P2 — Local-first before hosted convenience

A developer must be able to run the core review locally without:

- creating a hosted account;
- sending source code to a cloud model;
- connecting a forge;
- provisioning a database/server;
- enabling dynamic target execution.

Hosted services may add collaboration, fleet management, or expensive optional capabilities later. They must not become prerequisites for local security judgment.

### P3 — One security brain, many surfaces

CLI, GitHub, GitLab, IDEs, coding agents, and future control-plane views consume the same versioned local review protocol.

```text
one canonical review run
 -> local terminal projection
 -> machine protocol projection
 -> GitHub projection
 -> IDE projection
 -> agent remediation projection
 -> later organization projection
```

A surface may display less detail, but it cannot invent stronger semantics.

### P4 — Quiet by design, never silent by omission

Sentrdel should minimize noisy inline comments while preserving every canonical result in machine-readable and summary form.

```text
canonical result existence
!= inline comment eligibility
!= summary prominence
!= notification policy
```

No comment budget can delete or downgrade a canonical blocking result.

### P5 — Explain first, score last

Do not make an opaque numeric security score the primary trust signal.

Prefer explicit state:

- what completed;
- what did not;
- what changed;
- what is blocking;
- what is advisory;
- what is independently verified.

If any aggregate score is introduced later, it must be a derived navigation aid with inspectable inputs and must never replace canonical states.

### P6 — The writer is not the verifier

A human or AI agent may write a change or remediation. That author does not become the final authority that the new revision is safe.

Every remediation creates a new candidate identity and requires fresh review/reuse validation and, where applicable, fresh verification.

### P7 — Developer time is a security resource

Excessive noise, slow feedback, ambiguous output, and configuration friction cause developers to bypass security systems. Product-quality gates therefore belong in the implementation plan, but they never justify weakening correctness/authority gates.

---

## 3. Target developer loop

The preferred product loop is:

```text
install Sentrdel
  -> run review locally with zero or minimal config
  -> understand top-level result in seconds
  -> inspect only actionable/security-relevant detail
  -> hand a bounded remediation packet to a human or coding agent
  -> modify code
  -> rerun against the new exact revision
  -> reuse only still-valid work
  -> optionally perform separately authorized verification
  -> publish the same truth to the PR
  -> merge only under explicit policy + complete review
```

The workflow should feel simple even though the internal architecture remains strict.

---

## 4. Developer-facing result model

Sentrdel must not display `ALLOW` as a synonym for "secure."

S2B should freeze a pure presentation projection derived from canonical fields. A planning seed is:

```text
DeveloperReviewOutcome
  READY_COMPLETE
  READY_WITH_ADVISORIES
  BLOCKED
  INCOMPLETE
  FAILED
  CANCELLED
```

This is **not** a new security authority. It is a deterministic projection over at least:

```text
run_completeness
policy_decision
blocking canonical findings/regressions
advisory presence
```

### Projection rules

`READY_COMPLETE` requires:

- `run_completeness == COMPLETE`;
- applicable policy/guard decision permits the change;
- no canonical blocking result remains.

`READY_WITH_ADVISORIES` has the same security prerequisites but has retained non-blocking advisory items.

`BLOCKED` means policy/guard/canonical blocking semantics reject progression even if review is otherwise complete.

`INCOMPLETE` dominates `READY_*` whenever mandatory review truth is incomplete.

`FAILED` and `CANCELLED` remain distinct from `INCOMPLETE` where the run terminal state requires it.

### Verification presentation

Verification is a separate dimension, for example:

```text
verification: NOT_REQUESTED | NOT_ELIGIBLE | PENDING | VERIFIED | CONTRADICTED | INSUFFICIENT
```

A `VERIFIED` badge may appear only when backed by the canonical future verification contract and proof artifacts. It cannot be inferred from static review success.

---

## 5. Ten-second comprehension contract

The product should optimize for a developer understanding the security state quickly, without collapsing nuance.

The first screen/terminal block should answer, in this order:

1. **Can this change proceed under current policy?**
2. **Was mandatory review complete?**
3. **What security property changed?**
4. **What is blocking/actionable?**
5. **What remains unknown or unsupported?**
6. **Was anything independently verified?**

Only then show deep Evidence/Coverage/provenance details.

Example shape:

```text
Sentrdel Review

Outcome: READY_WITH_ADVISORIES
Review completeness: COMPLETE
Change: <base> -> <candidate>

Security regressions: 0 blocking
Canonical findings: 0 blocking / 2 non-blocking
Coverage loss: none
Mandatory review units: 12/12 completed
Verification: NOT_REQUESTED

2 advisory improvements

Explain: sentrdel explain <run-or-result-id>
```

For incomplete review:

```text
Outcome: INCOMPLETE
Review completeness: INCOMPLETE

Mandatory review units: 10/12 completed
Missing:
- dependency reachability producer timed out
- one generated artifact type unsupported

Policy result is shown separately and MUST NOT make this screen green.
```

---

## 6. Local command surface seed

S2B should clarify exact names, but the product must support equivalent capabilities.

### Core review

```text
sentrdel review
sentrdel review --preview
sentrdel review --format json
```

### Explainability

```text
sentrdel explain <run-id|finding-id|regression-id>
```

The explain surface should trace:

```text
developer result
 -> canonical Finding/regression/policy/completeness
 -> Evidence/Coverage/invariant/reuse/verification references
 -> exact provenance/input identities
```

### Setup

```text
sentrdel doctor
sentrdel init
```

`doctor` diagnoses environment/config/integration readiness. It must not silently repair security policy or widen privileges.

`init` is optional convenience. Zero-config local review should remain useful where repository truth is sufficient.

### Future agent mode

```text
sentrdel review --agent
```

or an equivalent stable machine protocol may expose structured remediation context. The exact CLI name is not frozen by this planning supplement; the S2B Spec Kit must decide it.

---

## 7. Zero-friction onboarding contract

The reference local path should target:

- no mandatory hosted account;
- no mandatory API key;
- no mandatory model/provider configuration;
- no mandatory server/database setup;
- one command to obtain the first meaningful local review after installation;
- useful defaults that do not weaken mandatory security requirements;
- typed diagnostics when repository state or environment prevents review;
- `doctor` output that distinguishes installation, repository, configuration, producer, and policy problems;
- optional configuration generated by `init`, never required merely to make ordinary review run.

### Configuration authority

Repository configuration is untrusted/tightening-only relative to hard mandatory requirements. Configuration may:

- add project-specific rules;
- increase review depth;
- add paths/owners/context;
- tune permitted presentation preferences;
- select admitted optional integrations.

Repository configuration must not:

- suppress mandatory security accounting;
- downgrade deterministic risk profiles;
- grant target execution/network/credential authority;
- redefine canonical Finding/Coverage semantics;
- hide incomplete review from machine output.

---

## 8. Quiet-review contract

Sentrdel must be useful enough that developers leave it enabled.

### 8.1 Canonical truth vs delivery

Every canonical result remains present in the manifest/protocol.

Inline delivery should use deterministic eligibility such as:

- exact source location exists;
- item is actionable at that location;
- result is not a duplicate/superseded representation;
- comment adds information beyond the summary;
- severity/blocking/novelty criteria meet the active presentation policy.

### 8.2 Comment budget

S3 should implement a bounded inline-comment budget to prevent review spam.

Rules:

- the budget affects inline delivery only;
- all canonical blocking results remain visible in the top-level summary/protocol;
- a budget cannot convert a blocking result into advisory;
- omitted inline comments must be countable and explainable;
- exact budget thresholds must be benchmark-derived and versioned, not arbitrary hidden constants.

### 8.3 Deduplication and supersession

Across pushes/retries:

- update/supersede stable review objects instead of reposting duplicates where the forge permits it;
- bind comments/checks to exact candidate identity;
- moved/resolved/stale results must have explicit lifecycle state;
- deleted external comments do not delete canonical local results.

---

## 9. Actionability and remediation contract

Every developer-visible actionable result should support structured remediation context.

### `RemediationPacket` conceptual seed

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

The packet is instruction/context, not proof that a proposed fix is correct.

### Agent handoff rule

A coding agent may consume a `RemediationPacket` and propose a patch. After any patch:

```text
old candidate identity != new candidate identity
```

Sentrdel must re-review the new candidate. Prior results may be reused only through ordinary `ReviewReuseProof` validation.

### No autonomous authority escalation

Agent integration cannot:

- dismiss a canonical Finding merely because it changed code;
- mark remediation verified;
- grant verification authorization;
- expand network/credential/tool permissions;
- merge a blocked/incomplete change through a Sentrdel authority shortcut.

---

## 10. Explainability contract

For every canonical blocking result, the developer should be able to inspect:

```text
WHAT changed
WHY it matters
WHERE the evidence came from
WHICH security property/invariant is affected
WHAT scope/blast radius is supported
WHAT is uncertain/unsupported
WHAT authority level the claim has
HOW to reproduce/explain locally
WHAT remediation would satisfy the contract
WHETHER stronger verification is required/available
```

Explain output must distinguish:

- external/native severity from canonical severity;
- observation from inference;
- Evidence from Finding;
- Coverage from completeness;
- policy decision from security state;
- static support from verified support;
- advisory/model suggestion from canonical judgment.

---

## 11. Progress and latency without semantic races

Developers need responsive feedback, but asynchronous progress must not change canonical semantics.

### Progress events

A future non-semantic progress stream may show:

- inventory complete;
- plan frozen;
- unit counts;
- producer started/completed;
- reuse accepted/rejected;
- remaining mandatory work;
- publication progress.

Progress events are telemetry only. Final canonical identity/order/completeness cannot depend on event timing or scheduler order.

### Early useful output

Sentrdel may display proven early information before the full run ends, but it must label provisional/partial state explicitly.

Example:

```text
3 actionable findings found so far
review still running: 8/12 mandatory units complete
```

It must never display a terminal ready/green state before completeness is proven.

---

## 12. Product performance gates

Performance is a release-quality property after correctness.

### Hard rules

- no performance optimization may skip mandatory work without changing completeness;
- warm reuse must remain semantically equivalent to valid cold execution for reused units;
- performance metrics must bind exact build/profile/fixture identities;
- wall-clock time is telemetry, not canonical result identity.

### Required measured metrics

For S2B/S3/S4 benchmarks record at least:

- install/setup to first successful review in the reference environment;
- cold review latency;
- warm review latency;
- time to first actionable result;
- time to terminal completeness;
- peak memory;
- deterministic work counters;
- reuse hit rate;
- invalidation rate;
- inline annotation count;
- duplicate/superseded publication count;
- machine-output size;
- explain lookup latency where meaningful.

Hard latency budgets should be set only after a versioned baseline exists. Lack of an arbitrary early threshold is not permission to ignore performance.

---

## 13. Distribution sequence

Do not build every integration at once.

### D0 — Local core

Prerequisites: S2A/S2B.

Deliver one excellent local CLI and stable machine protocol.

### D1 — GitHub reference experience

Prerequisites: canonical S2B and applicable S4 fixtures.

Deliver:

- least-privilege GitHub integration;
- top-level check/summary;
- exact inline annotations where provenance permits;
- push-aware supersession/re-review;
- stable commands/interactions only where they do not create authority ambiguity;
- no execution of PR-controlled code solely to perform ordinary review.

GitHub is the reference forge, not a special judgment implementation.

### D2 — Coding-agent handoff

Prerequisite: stable `RemediationPacket`/machine protocol.

Deliver adapters/instructions for coding agents without granting them review authority.

Initial targets may include popular local coding-agent workflows, but each adapter remains replaceable and thin.

### D3 — IDE reference integration

Prerequisites: stable S2B protocol and product-quality benchmarks.

The IDE should support pre-commit review of local changes and reuse the same explain/remediation semantics.

Do not embed a second analysis engine in the extension.

### D4 — GitLab and additional forges

Only after GitHub semantic equivalence and publication lifecycle are conformance-clean.

### D5 — Optional organization/control-plane experience

Only after local and forge workflows are independently useful. The hosted/self-hosted control plane may add portfolio policy, audit, lifecycle, teams, dashboards, fleet configuration, and expensive optional compute, but local review remains a first-class product.

---

## 14. Open-source adoption contract

Wide developer adoption should be an explicit product goal.

### Core expectations

- security judgment core remains inspectable/open according to project licensing decisions;
- local review should have a useful no-hosted-account path;
- public examples/fixtures explain why results exist;
- integration protocols are documented enough for community adapters;
- deterministic conformance fixtures make third-party adapter correctness testable;
- security reporting process and threat model are easy to find;
- release provenance/SBOM/signature strategy is planned before claiming high trust.

### Ecosystem strategy

Prefer an ecosystem where external tools contribute Evidence/Coverage through bounded protocols rather than requiring Sentrdel to own every scanner.

Future community contributions should cluster around:

- producers/adapters;
- provider/framework semantics;
- conformance fixtures;
- policy/rule packs with explicit provenance;
- forge/IDE adapters;
- documentation and reproducible benchmark cases.

Community breadth must not dilute authority rules.

---

## 15. Trust and transparency program

Sentrdel should earn trust through evidence visible to users and contributors.

Before broad adoption claims, plan for:

1. **Open conformance corpus** — public fixtures for supported security properties and no-green-by-omission cases.
2. **Protected holdouts** — prevent benchmark overfitting where appropriate.
3. **Reproducible releases** where practical, with version/build identity.
4. **SBOM and release provenance** for distributed binaries/artifacts.
5. **Signed release artifacts** or equivalent verified distribution provenance.
6. **Published security model/threat model** for the review pipeline itself.
7. **Documented source qualification** for privileged dependencies and copied/ported source.
8. **Public known-limitations matrix** — supported/partial/unsupported semantics must be explicit.
9. **Determinism evidence** for canonical outputs.
10. **Independent review/qualification** for authority-sensitive changes.

Do not claim trust from popularity alone.

---

## 16. Product-quality metrics

### 16.1 Hard trust gates

These remain zero-tolerance where applicable:

```text
false terminal READY while mandatory review incomplete = 0
canonical blocking result hidden from machine/summary output = 0
invalid reuse accepted = 0
advisory/model suppression of canonical Finding = 0
stale candidate result published as current = 0
guessed canonical inline location = 0
local/forge/IDE canonical semantic divergence = 0
agent remediation marked verified without proof = 0
```

### 16.2 Measured review-quality metrics

Measure by frozen benchmark version:

- precision of canonical actionable results;
- recall by supported invariant/finding family;
- coverage-loss recall;
- unsupported/unknown visibility;
- annotation location accuracy;
- duplicate result rate;
- supersession correctness;
- remediation recurrence rate;
- remediation re-review success rate;
- advisory usefulness where human feedback exists;
- time to explain/reproduce a result.

### 16.3 Developer adoption metrics

These are product metrics, not security authority:

- install -> first successful review conversion;
- repeat local review rate;
- repositories with recurring weekly review activity;
- PRs reviewed / eligible PRs in opted-in repositories;
- fraction of findings opened/explained;
- accepted/resolved/disputed result rates;
- median/P95 inline comment count;
- summary-only result fraction;
- time from actionable result to remediation commit;
- rerun frequency after remediation;
- integration setup failures by category;
- uninstall/disable reason where voluntarily reported.

Never optimize adoption metrics by weakening mandatory review or hiding failures.

---

## 17. Developer feedback as lower-authority evidence

Future feedback such as:

- helpful/not helpful;
- accepted fix;
- disputed finding;
- duplicate;
- intentional behavior;
- false-positive report;

may become research/training/evaluation input only through explicit provenance and governance.

Developer feedback cannot directly:

- delete canonical historical Evidence;
- mutate a protected benchmark answer;
- auto-promote a rule;
- suppress a future Finding without a qualified rule/policy change;
- become FACT/VERIFIED.

This preserves a learning loop without creating self-fulfilling evaluation.

---

## 18. S2B implementation expansion

The canonical Implementation Master Plan's S2B should be interpreted with this stronger product contract.

S2B must freeze:

1. developer-facing outcome projection;
2. terminal information architecture;
3. stable versioned machine protocol;
4. exit codes;
5. preview/explain;
6. deterministic truncation/redaction;
7. zero-config/default behavior;
8. `doctor`/setup diagnostics;
9. trusted configuration merge rules;
10. remediation/agent handoff packet;
11. progress telemetry separation;
12. local history/reuse presentation as allowed by S2A persistence contracts;
13. golden UX fixtures;
14. performance/product-quality benchmark harness;
15. onboarding/reference documentation.

The companion seed is:

`specs/000-sentrdel-roadmap/s2b-developer-review-experience-spec-bootstrap-2026-09-16.md`

---

## 19. S3 implementation expansion

S3 remains forge delivery, but the product objective becomes explicit:

> Build one reference GitHub experience that proves Sentrdel can feel native to a developer workflow without moving security judgment into GitHub-specific code.

Required S3 capabilities include:

- exact candidate/base binding;
- one concise top-level review summary/check;
- deterministic inline annotation eligibility;
- bounded comment budget;
- all blocking/incomplete states visible even when not inline;
- idempotent update/supersession across pushes;
- least-privilege/fork-safe execution;
- stable linkage back to local explain/result identities;
- re-review on changed candidate identity;
- no PR-controlled instructions gaining workflow authority;
- same canonical result semantics as local CLI.

Broader forge/IDE proliferation should wait until S4 proves semantic equivalence and product-quality fixtures.

---

## 20. S4 product conformance expansion

In addition to existing authority and semantic conformance, S4 should test:

### Presentation equivalence

- same canonical result across local JSON and GitHub projection;
- no missing canonical blocking result;
- incomplete review remains visually dominant;
- verified state appears only with real proof;
- summary counts equal canonical manifest counts.

### Noise fixtures

- repeated same finding across pushes;
- 1 blocking + many advisories;
- many canonical findings with bounded inline budget;
- stale/resolved/superseded findings;
- exact source span absent;
- duplicate external producer observations mapping to one canonical result.

### Remediation fixtures

- human fix;
- coding-agent fix;
- partial fix;
- fix introducing new regression;
- stale remediation packet;
- changed revision after packet generation;
- verification-required remediation.

### Onboarding fixtures

- clean zero-config repository;
- unsupported repository state;
- malformed configuration;
- unavailable optional integration;
- no network;
- no account/authentication;
- `doctor` diagnosis consistency.

---

## 21. Reference acceptance journeys

### Journey A — first local review

A developer installs Sentrdel in a supported environment and obtains a meaningful local review without creating an account or writing configuration.

Pass only if setup failure modes are typed and diagnosable.

### Journey B — AI-generated vulnerable change

A coding agent creates a security regression. Sentrdel identifies the supported regression, explains evidence and affected scope, produces a bounded remediation packet, the agent proposes a fix, and Sentrdel independently re-reviews the new candidate.

Pass only if the authoring agent cannot mark its own fix verified.

### Journey C — no findings, incomplete work

A producer times out. The developer-facing state is `INCOMPLETE`; the UI cannot be mistaken for a clean security result.

### Journey D — noisy change

Many low-priority/advisory results exist with a small number of canonical blocking results. The summary remains complete while inline output stays bounded and actionable.

### Journey E — push updates PR

The candidate changes after initial review. Old publication is superseded, valid reuse is preserved, invalidated units rerun, and GitHub does not accumulate misleading duplicate comments.

### Journey F — local to GitHub equivalence

A developer sees the same canonical judgment locally and in GitHub for the same immutable candidate identity.

### Journey G — offline/local privacy

Core review and explain work without a hosted account or cloud model. Optional hosted/model capability absence is explicit but does not break the supported local path.

### Journey H — stronger verified claim

A future eligible case receives separately authorized bounded verification. Developer output clearly distinguishes static support from proof-backed verification.

---

## 22. Non-goals

Do not make these prerequisites for the first excellent developer product:

- a large hosted dashboard;
- every forge;
- every IDE;
- every scanner;
- a proprietary model;
- dynamic pentesting by default;
- autonomous fixing/merging;
- organization billing/seat management;
- CTI workbench/cases;
- runtime response automation;
- a numeric security score;
- replacing mature external tools whose outputs can be safely imported.

The first product win is a trusted local + GitHub security-review loop.

---

## 23. Implementation-ready gate for developer-facing slices

A developer-facing slice is not `IMPLEMENTATION_READY` until its active Spec Kit states:

1. canonical inputs and authority ceiling;
2. exact developer-facing states and projection rules;
3. stable machine fields and compatibility behavior;
4. CLI/API/surface ownership;
5. redaction and secret-safety rules;
6. incomplete/failure/cancel behavior;
7. deterministic rendering where compatibility requires it;
8. comment/noise policy if publication exists;
9. remediation handoff semantics if agent integration exists;
10. tests for stale candidate/reuse/publication;
11. zero-account/offline behavior for claimed local paths;
12. performance metrics to record and baseline identity;
13. product-quality fixtures;
14. accessibility/readability requirements for UI surfaces where applicable;
15. rollback/disable behavior;
16. security/CI/conformance gates;
17. no unresolved product decision that would force the implementer to invent workflow semantics.

---

## 24. Product completion gate

Sentrdel has proven the initial developer product thesis only when real evidence shows:

- a developer can obtain a useful local security review with minimal setup;
- the same canonical truth reaches GitHub without semantic divergence;
- incomplete work cannot look safe;
- findings are sufficiently precise/actionable to remain enabled in normal development;
- explanations connect to inspectable Evidence/Coverage/provenance;
- remediation loops work for humans and coding agents while keeping review authority independent;
- valid warm reuse makes repeat reviews materially cheaper without weakening trust;
- product-quality benchmarks track noise, latency, actionability, and adoption alongside security correctness;
- the local core remains useful without a hosted service.

Only after this loop is excellent should breadth of forges, IDEs, providers, scanners, hosted control-plane features, and enterprise workflow become the primary growth axis.

---

## 25. Final product thesis

Sentrdel should feel simple because the architecture is strict, not because the product hides uncertainty.

The target experience is:

```text
Fast enough to run on every change.
Quiet enough to leave enabled.
Clear enough for every developer.
Deep enough for security engineers.
Explainable enough to challenge.
Deterministic enough to reproduce.
Independent enough to review AI-written code.
Provable enough to earn trust.
```

That is the standard required before describing Sentrdel as the default security reviewer for developers.