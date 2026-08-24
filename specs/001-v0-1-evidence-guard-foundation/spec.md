# Feature Specification: Sentrdel v0.1 Evidence + Guard Foundation

**Feature Branch:** `spec/001-v0-1-evidence-guard-foundation`  
**Created:** 2026-08-24  
**Status:** SPECIFIED  
**Roadmap:** R1 in `specs/000-sentrdel-roadmap/roadmap.md`

## Overview

Sentrdel v0.1 establishes the smallest trustworthy foundation that is already useful in real AI-assisted development workflows. It provides a Rust-first local CLI that reviews git changes, turns heterogeneous security signals into a canonical evidence model, explains findings in plain language, records coverage gaps honestly, and enforces monotonic policy at vendor-neutral seams Sentrdel can actually control.

This slice does **not** attempt to secure every provider or build a universal CPG. It creates the contracts and runtime foundation required for later A-to-Z security packs, including Supabase as the first P0 provider pack in roadmap R3.

## User Scenarios & Testing

### User Story 1 — Review an AI-generated change before merge (Priority: P1)

A developer has used Codex, Cursor, Claude Code, Junie, Windsurf, Copilot, or another coding agent to modify a repository. They run `sentrdel review` and receive a concise security judgment focused on the changed code and its blast radius.

The output must explain the real-world impact first, show exact locations and evidence underneath, and distinguish proven/observed facts from hypotheses.

**Why this priority:** This works with every coding agent today and creates immediate value without relying on vendor hook APIs.

**Independent Test:** Given a fixture git repository containing a changed secret, a vulnerable high-signal code pattern, a dependency delta with a known advisory fixture, and a changed CI workflow, `sentrdel review` emits deterministic evidence-backed findings with exact locations, producer identities, proof status, and a non-zero exit decision when policy requires blocking.

**Acceptance Scenarios:**

1. **Given** a clean changed diff, **When** the developer runs `sentrdel review`, **Then** Sentrdel reports no finding for unsupported checks and separately reports any coverage gaps.
2. **Given** a changed file containing a high-signal security pattern, **When** review runs, **Then** the finding includes the changed location, evidence producer, epistemic class, and plain-language impact.
3. **Given** two independent producers that support the same claim, **When** evidence is reconciled, **Then** Sentrdel correlates them into one finding rather than duplicating alerts.
4. **Given** contradictory evidence, **When** reconciliation runs, **Then** the finding is marked contested/unproven and MUST NOT be presented as verified.

---

### User Story 2 — Guard controllable agent actions (Priority: P1)

A developer wants Sentrdel active while an AI coding agent works. They enable the vendor-neutral guard surfaces available in v0.1: MCP gateway and git hooks, with an architecture that can later add PATH shims and vendor-native hooks.

Sentrdel evaluates actions using monotonic policy and records an append-only Agent Security Event Log (ASEL). The UI clearly says whether a control is **enforced** or **advisory**.

**Why this priority:** Agent security is a core product differentiator, but Sentrdel must not falsely claim it can intercept actions in vendors that expose no hook.

**Independent Test:** A fixture MCP client attempts an allowed tool call, an approval-required call, and a kernel-invariant-denied call through `sentrdel guard mcp`. The gateway returns the correct verdicts, records tamper-evident ASEL events, and proves that a later plugin/rule cannot downgrade DENY.

**Acceptance Scenarios:**

1. **Given** an explicitly allowed action and no stricter rule, **When** it passes the MCP gateway, **Then** the verdict is ALLOW and the action proceeds.
2. **Given** an action requiring human approval, **When** it reaches an enforcement seam, **Then** Sentrdel blocks pending a scoped ASK decision.
3. **Given** a kernel-invariant violation, **When** any later policy/plugin attempts to allow it, **Then** the final verdict remains DENY.
4. **Given** an engine/policy failure at an enforcement seam, **When** a decision cannot be made, **Then** Sentrdel records `UNDECIDABLE` and behaves fail-closed into ASK/deny-by-policy rather than silently allowing.
5. **Given** a git hook that a user can bypass, **When** Sentrdel reports its state, **Then** it is labeled advisory/partial rather than universally enforced.

---

### User Story 3 — Initialize Sentrdel and understand project coverage (Priority: P1)

A developer runs `sentrdel init` in an unfamiliar project. Sentrdel discovers relevant repository characteristics without executing target build/install scripts and creates a local configuration that is safe by default.

It identifies stack/provider signals such as languages, package ecosystems, CI workflows, MCP configuration, and security-provider candidates (for example Supabase), then reports what v0.1 can and cannot currently analyze.

**Why this priority:** A-to-Z security requires Sentrdel to understand the project and expose coverage truth before provider packs mature.

**Independent Test:** Given fixture repositories for Rust, TypeScript/Next.js+Supabase, Python, and a mixed monorepo, `sentrdel init` produces deterministic stack detection, refuses unsafe path traversal/symlinks according to policy, and records unsupported domains as coverage gaps.

**Acceptance Scenarios:**

1. **Given** a Next.js repository with Supabase migrations/config, **When** initialization runs, **Then** Sentrdel identifies `supabase` as a detected provider requiring a future/installed security pack; it MUST NOT claim the provider is secure merely because v0.1 lacks full Supabase analysis.
2. **Given** repository-owned configuration that attempts to weaken a kernel invariant, **When** config loads, **Then** validation rejects the widening change.
3. **Given** malicious repository filenames or oversized inputs, **When** initialization scans, **Then** bounded traversal fails safely and produces a diagnostic rather than executing repository content.

---

### User Story 4 — Explain a finding and its evidence (Priority: P2)

A developer who does not know cybersecurity runs `sentrdel explain <finding-id>` and sees a three-tier explanation: plain-language impact, attacker/security narrative with minimal remediation guidance, and the complete technical evidence/provenance chain.

**Why this priority:** Evidence rigor is useless if developers cannot understand what action to take.

**Independent Test:** For a stored fixture finding, `sentrdel explain` renders the same canonical finding in novice, practitioner, and evidence-detail layers without changing the underlying severity/proof state.

---

### User Story 5 — Optional LLM reasoning without surrendering security authority (Priority: P3)

A developer may opt into `--reason` using a configured local or user-key model provider. The LLM can summarize evidence, draft hypotheses, or translate findings, but cannot create facts, mark verification complete, suppress findings, weaken policy, or independently lower severity.

**Why this priority:** LLM reasoning can improve contextual security analysis later, but v0.1 must prove that deterministic security remains useful without it.

**Independent Test:** A hostile fixture source file contains prompt-injection text instructing the reasoner to mark a finding safe. The reasoner output is stored only as INFERENCE/HYPOTHESIS and cannot alter deterministic evidence or final kernel-policy restrictions.

## Functional Requirements

### Canonical schemas and storage

- **FR-001** Sentrdel MUST define a versioned canonical Evidence schema in Rust and generate machine-readable JSON Schema.
- **FR-002** Evidence MUST include stable identity/content hash, producer identity/version, input digests, claim/category, epistemic class, locations/subjects, optional confidence band, provenance, and reproduction metadata where available.
- **FR-003** Epistemic classes MUST distinguish at least `FACT`, `INFERENCE`, `HYPOTHESIS`, `OBSERVATION`, `VERIFIED`, and `CONTRADICTION`.
- **FR-004** Sentrdel MUST define Findings separately from Evidence; only the reconciler may create/update canonical Findings.
- **FR-005** Finding state MUST separate epistemic state from workflow state.
- **FR-006** Sentrdel MUST persist evidence, findings, coverage records, and event-log metadata locally in an inspectable content-addressed store.
- **FR-007** Secret values MUST be redacted before persistence; evidence may reference a redacted secret identifier/location but MUST NOT persist discovered plaintext secret values by default.

### Review

- **FR-008** `sentrdel review` MUST accept a git working-tree/staged/base diff mode without running target repository hooks or build scripts.
- **FR-009** v0.1 MUST include deterministic high-signal checks for changed secrets, selected structural security patterns, dependency/advisory deltas for supported ecosystems, and security-sensitive CI workflow changes.
- **FR-010** Structural pattern matching MUST run in-process where feasible through Rust-native parsing/matching rather than shelling out for the baseline path.
- **FR-011** External engine integrations MUST implement a versioned Engine boundary; stdout/stderr/JSON/SARIF are untrusted and size/time bounded.
- **FR-012** Missing/failed engines MUST produce an explicit coverage gap, never a clean result.
- **FR-013** Review MUST correlate equivalent evidence from independent producers into a single finding while retaining every producer's provenance.
- **FR-014** Review MUST support changed-symbol/blast-radius infrastructure without requiring a custom universal CPG.

### Guard and ASEL

- **FR-015** Sentrdel MUST define a versioned Agent Security Event Log (ASEL) envelope suitable for append-only JSONL transport and future publication as an open specification.
- **FR-016** ASEL MUST cover actor, event kind, normalized target, parameter/result digests, policy verdict, provenance, sequence, previous-hash linkage, and timestamp/session identity.
- **FR-017** v0.1 MUST support events for MCP discovery/invocation, git operations relevant to installed hooks, approval/denial, and tool results; the schema MUST reserve extensible kinds for file, shell, network, dependency, secret/env, CI/IaC, and model events.
- **FR-018** `sentrdel guard mcp` MUST proxy supported MCP transports without trusting tool descriptions or tool results as instructions.
- **FR-019** Guard verdicts MUST use `ALLOW`, `ASK`, `DENY`, and `UNDECIDABLE` semantics; `UNDECIDABLE` at an enforcement seam MUST fail closed according to policy.
- **FR-020** DENY produced by a kernel invariant MUST be absorbing for that action scope; downstream plugins/policies/LLMs MUST NOT downgrade it.
- **FR-021** Every guard surface MUST declare its enforcement fidelity as `ENFORCED`, `PARTIAL`, or `ADVISORY` in machine-readable state and human output.
- **FR-022** Repository-local policy/config MUST only narrow permissions relative to core/user policy and MUST NOT disable evidence logging.

### Initialization and A-to-Z extensibility

- **FR-023** `sentrdel init` MUST detect project languages, package ecosystems, CI configuration, MCP configuration, and provider/framework signals without executing target install/build scripts.
- **FR-024** Provider/framework detection MUST be separate from provider security verdicts.
- **FR-025** The architecture MUST define a Security Pack evidence contract so future packs—including the P0 Supabase pack—can add deterministic provider-specific evidence without bypassing core reconciliation.
- **FR-026** The base install MUST remain useful without external scanners, cloud services, or LLM providers.

### LLM boundary

- **FR-027** LLM integration MUST be optional and feature/config gated.
- **FR-028** LLM-produced evidence MUST be structurally restricted to `INFERENCE` or `HYPOTHESIS`.
- **FR-029** LLM output MUST NOT directly suppress findings, set `VERIFIED`, weaken policy, or override kernel invariants.
- **FR-030** Raw source/prompt upload to a remote provider MUST require explicit user configuration; local-only operation remains the default.

### Security of Sentrdel

- **FR-031** Sentrdel MUST never construct target commands through a shell string; subprocess execution uses argv arrays only.
- **FR-032** Untrusted repository traversal and engine output MUST have byte, path, process, and time bounds.
- **FR-033** Target repository git hooks MUST NOT run during Sentrdel analysis.
- **FR-034** Event/evidence history MUST be tamper-evident through chained/content hashes.
- **FR-035** Third-party source reuse MUST be blocked until provenance/license/source qualification is recorded.

## Key Entities

- **Evidence** — immutable producer claim with provenance and epistemic class.
- **Finding** — reconciled security judgment linked to one or more Evidence items.
- **CoverageRecord** — what was analyzed, skipped, unavailable, failed, or unsupported.
- **AgentSecurityEvent (ASEL Event)** — append-only record of an agent/tool/environment action or security decision.
- **PolicyDecision** — monotonic guard result with rule/kernel-invariant provenance.
- **SecurityGraphNode/Edge** — thin property-graph representation of claims/relationships with producer provenance.
- **EngineManifest/EngineRun** — bounded external evidence-producer contract and one execution record.
- **SecurityPackManifest** — provider/framework detection and evidence capabilities without direct verdict authority.
- **ProjectProfile** — detected stack/providers/coverage/configuration for a repository.

## Edge Cases

- Repository is empty, detached, shallow, very large, or contains malformed/binary files.
- Diff contains renamed/deleted files, generated code, symlink paths, Unicode-confusable filenames, or very large blobs.
- External engine returns malformed JSON/SARIF, hangs, floods output, exits non-zero, or reports absolute paths outside repository root.
- Two engines disagree about the same claim.
- A repository attempts to configure Sentrdel to ignore evidence or widen access.
- MCP tool descriptions/results contain prompt-injection or instruction-shaped content.
- User runs without network, without any external engine, or without an LLM.
- A detected provider (such as Supabase) has no installed/mature security pack; this MUST appear as partial coverage.
- Git hook is bypassed; Sentrdel must not claim the associated control remained enforced.

## Success Criteria

- **SC-001** On the v0.1 release benchmark, clean-PR false-positive rate is no worse than **1 false positive per 5 clean PRs** for release-gating checks.
- **SC-002** Every high-severity/blocking finding emitted by v0.1 has a valid repository-relative location (when applicable), evidence chain, producer provenance, and explicit proof/epistemic status.
- **SC-003** `sentrdel review` completes warm native-only diff analysis in **<5 seconds p95** for diffs under 2,000 changed LOC on the reference benchmark machine; broader warm 100k-LOC project review target is **<30 seconds**.
- **SC-004** Guard decisions at the in-process MCP policy seam complete in **<50 ms p95**, excluding downstream MCP tool execution and explicit human approval time.
- **SC-005** Removing or failing a configured external engine changes coverage state to a visible gap and never changes it to `clean`.
- **SC-006** A property/contract test proves no extension policy can downgrade a kernel-invariant DENY.
- **SC-007** A hostile prompt-injection fixture cannot cause optional LLM output to become FACT/VERIFIED, suppress deterministic evidence, or weaken policy.
- **SC-008** A novice-facing usability fixture can render every benchmark finding as one sentence naming actor/capability/object plus a clear action category without requiring CWE/CVSS knowledge.
- **SC-009** Base installation and primary tests succeed without an LLM provider, external scanner installation, or cloud account.
- **SC-010** Source-qualification records exist before any donor source is copied into the repository.

## Non-Goals for v0.1

- Building a universal Code Property Graph or compiler-quality semantics for all languages.
- Full Supabase/Firebase/cloud/provider security analysis; v0.1 provides detection and Security Pack contracts only.
- Autonomous exploit generation or production penetration testing.
- General runtime enforcement/eBPF.
- Full verification sandbox and `FIX_VERIFIED` execution pipeline.
- VS Code/Cursor/JetBrains/GitHub App UI integrations.
- Automatic application of security fixes.
- Competing on total rule count or replacing mature SAST/SCA/IaC ecosystems.

## Assumptions

- Initial supported host platforms for review/init are Linux, macOS, and Windows where Rust capabilities permit; enforcement fidelity may vary by seam and MUST be reported honestly.
- MCP gateway behavior will target current standard transports supported by the selected Rust MCP implementation after source qualification.
- Core project licensing remains open-source; the exact repository license is a release-governance decision and MUST be frozen before donor source is copied or the first release is published.
