# Feature Specification: Sentrdel v0.1 Evidence + Guard Foundation

**Feature Branch:** `spec/001-v0-1-evidence-guard-foundation`  
**Created:** 2026-08-24  
**Status:** SPECIFIED_AFTER_MAJOR_REVIEW  
**Roadmap:** R1 in `specs/000-sentrdel-roadmap/roadmap.md`  
**Major review:** `major-review-2026-08-24.md`

## Overview

Sentrdel v0.1 establishes the smallest trustworthy foundation that is already useful in real AI-assisted development workflows. It provides a Rust-first local CLI that reviews git changes, turns heterogeneous security signals into a canonical evidence model, explains findings in plain language, records coverage gaps honestly, and enforces monotonic policy at vendor-neutral seams Sentrdel can actually control.

Sentrdel's category is the **open-source security evidence and control plane for the whole software project, from agent action to production**. R1 does not attempt to beat mature scanners on rule count or build a universal CPG. It builds the trustworthy adjudication/control substrate for later A-to-Z security packs, with Supabase now the first dedicated post-R1 provider posture spec.

## User Scenarios & Testing

### User Story 1 — Review an AI-generated change before merge (Priority: P1)

A developer uses any coding agent—or no agent—to modify a repository. They run `sentrdel review` and receive a concise security judgment focused on changed code and its bounded blast radius.

The output explains real-world impact first, shows exact locations/evidence underneath, and distinguishes direct observations from security interpretations/hypotheses.

**Why this priority:** It works across agents today and does not depend on proprietary hook APIs.

**Independent Test:** Given a fixture git repository containing a changed secret, vulnerable high-signal structural pattern, dependency delta with an advisory fixture, and security-sensitive GitHub Actions change, `sentrdel review` emits deterministic evidence-backed findings with locations, producer identities, epistemic status, coverage and correct exit behavior.

**Acceptance Scenarios:**

1. Clean supported diff -> no unsupported check is silently treated as clean; coverage gaps are separate.
2. High-signal pattern -> finding has location, direct observation/basis, security interpretation, producer and proof status.
3. Independent supporting producers -> one correlated finding retaining provenance.
4. Contradictory evidence -> contested/unproven, never verified.
5. Hostile Git configuration -> review does not execute hooks, textconv/external diff/filter helpers, submodule fetches, credential helpers or network operations.

---

### User Story 2 — Guard controllable agent actions (Priority: P1)

A developer wants Sentrdel active while an AI coding agent works. In v0.1 the true vendor-neutral enforcement seam is a **bounded stdio MCP gateway**; git hooks are partial/advisory guardrails. Remote/Streamable HTTP MCP is not in R1.

Sentrdel evaluates actions using monotonic policy and records an integrity-linked Agent Security Event Log (ASEL). The UI clearly states whether a control is ENFORCED, PARTIAL or ADVISORY.

**Independent Test:** A fixture stdio MCP client attempts allowed, approval-required, kernel-denied, malformed, oversized and unsupported-version calls through `sentrdel guard mcp`. The gateway returns correct decisions, enforces byte/framing limits, records an ASEL chain/head and proves later policy cannot downgrade a kernel DENY.

**Acceptance Scenarios:**

1. Explicit allow + no stricter rule -> ALLOW and forward.
2. Human approval required -> ASK blocks at the controlled seam until scoped decision.
3. Kernel invariant violated -> final DENY remains DENY regardless of later policy/LLM/plugin.
4. Policy/transport decision unavailable -> UNDECIDABLE fails closed according to policy.
5. Bypassable git hook -> PARTIAL/ADVISORY, never universal enforcement.
6. Oversized/unterminated stdio frame -> bounded rejection without unbounded buffering.
7. Unsupported/ambiguous MCP protocol version -> fail closed; never depend on SDK default/LATEST alone.

---

### User Story 3 — Initialize Sentrdel and understand project coverage (Priority: P1)

A developer runs `sentrdel init` in an unfamiliar project. Sentrdel discovers repository characteristics without executing target build/install/Cargo/package-manager scripts.

It identifies languages, package ecosystems, CI workflows, MCP configuration and provider signals such as Supabase, then reports exactly what R1 can and cannot analyze.

**Independent Test:** Fixture repositories for Rust, TypeScript/Next.js+Supabase, Python and mixed monorepo produce deterministic profiles, reject unsafe traversal inputs, and expose unsupported domains as coverage gaps.

**Acceptance Scenarios:**

1. Next.js+Supabase -> provider detected; deep posture is explicitly NOT_IMPLEMENTED/PARTIAL, never secure-by-absence.
2. Repo config tries to weaken kernel invariant -> rejected.
3. Malicious filenames/oversized input -> bounded diagnostic, no execution.
4. Rust target repo with malicious `.cargo/config.toml` -> Sentrdel does not invoke Cargo/metadata/build tools during analysis.

---

### User Story 4 — Explain a finding and its evidence (Priority: P2)

A non-security developer runs `sentrdel explain <finding-id>` and sees three tiers: plain-language impact, attacker/security narrative + minimal remediation, then technical evidence/provenance/coverage.

**Independent Test:** A fixture finding renders all tiers without changing canonical severity/proof/workflow state.

---

### User Story 5 — Optional LLM reasoning without surrendering authority (Priority: P3)

A developer may opt into `--reason` through a configured local or explicit user-key provider. The model may summarize evidence/draft hypotheses/translate findings, but cannot create facts, mark verification complete, suppress findings, weaken policy or independently lower authoritative severity.

**Independent Test:** Hostile source/MCP text instructing the model to mark a finding safe is stored only as INFERENCE/HYPOTHESIS and cannot mutate deterministic evidence/kernel restrictions.

## Functional Requirements

### Canonical schemas and storage

- **FR-001** Sentrdel MUST define a versioned canonical Evidence schema in Rust and generate machine-readable JSON Schema.
- **FR-002** Evidence MUST include stable identity/content hash, producer identity/version, input digests, direct observation/basis, security claim/interpretation, category, epistemic class, subjects/locations, optional confidence band, provenance and reproduction metadata where available.
- **FR-003** Epistemic classes MUST distinguish at least `FACT`, `INFERENCE`, `HYPOTHESIS`, `OBSERVATION`, `VERIFIED`, and `CONTRADICTION`; FACT is limited to directly observable bounded properties, not semantic exploit/security conclusions merely because a detector is deterministic.
- **FR-004** Sentrdel MUST define Findings separately from Evidence; only the reconciler may create/update canonical Findings.
- **FR-005** Finding state MUST separate epistemic state from workflow state.
- **FR-006** Sentrdel MUST persist evidence, findings, coverage and event-log metadata locally in an inspectable content-addressed store.
- **FR-007** Discovered secret plaintext MUST be removed before persistence. Sentrdel MUST NOT persist a stable unkeyed digest derived solely from the discovered secret value; persistent evidence may keep location, rule/type, redacted display and sanitized non-secret fingerprints.

### Review

- **FR-008** `sentrdel review` MUST accept working-tree/staged/base diff modes without executing target repository hooks, build/install scripts, Cargo/package-manager commands, external diff/textconv/filter processes, submodule fetches, credential helpers or network remotes.
- **FR-009** v0.1 MUST include high-signal deterministic checks for changed secrets, selected structural security patterns, dependency/advisory deltas for supported ecosystems, and GitHub Actions security-sensitive changes including permissions/OIDC, `pull_request_target`, untrusted shell interpolation, action pinning and self-hosted/untrusted-runner boundaries where statically observable.
- **FR-010** Baseline structural matching MUST run in-process through qualified Rust-native parsing/matching where feasible.
- **FR-011** External engines MUST implement a versioned Engine boundary; executable identity, child environment, stdout/stderr/JSON/SARIF are untrusted and size/time/resource bounded. Child environments MUST be scrubbed/allowlisted rather than inheriting all developer credentials by default.
- **FR-012** Missing/failed engines MUST produce explicit coverage gaps, never a clean result.
- **FR-013** Review MUST correlate equivalent evidence from independent producers into a single Finding while retaining provenance/contradictions.
- **FR-014** Review MUST support changed-symbol/blast-radius infrastructure without requiring a custom universal CPG.

### Guard and ASEL

- **FR-015** Sentrdel MUST define versioned ASEL suitable for append-only JSONL and future publication as an open specification.
- **FR-016** ASEL MUST cover actor, event kind, normalized target, parameter/result digests, policy decision, provenance, sequence, previous-hash linkage and timestamp/session identity.
- **FR-017** R1 MUST support events for MCP discovery/invocation, relevant installed git-hook operations, approval/denial and tool results; schema reserves namespaced future event kinds.
- **FR-018** `sentrdel guard mcp` MUST support **stdio MCP only in R1**, using Sentrdel-owned bounded framing/buffering, explicit protocol-version negotiation/allowlisting and payload byte/depth caps. Tool descriptions/results are untrusted data, not instructions. Remote/Streamable HTTP MCP is out of R1.
- **FR-019** Guard decisions MUST use `ALLOW`, `ASK`, `DENY`, `UNDECIDABLE`; UNDECIDABLE at an enforcement seam fails closed according to policy.
- **FR-020** Kernel-invariant DENY MUST be absorbing for the action scope; no downstream policy/plugin/LLM may downgrade it.
- **FR-021** Every guard surface MUST declare `ENFORCED`, `PARTIAL`, or `ADVISORY` in machine/human output.
- **FR-022** Repository-local policy/config may only narrow permissions and cannot disable evidence logging. Rego policy/input size/depth and supported features MUST be bounded; kernel invariants remain Rust-owned.

### Initialization and A-to-Z extensibility

- **FR-023** `sentrdel init` MUST detect languages, package ecosystems, CI, MCP and provider/framework signals without executing target install/build/Cargo/package-manager code.
- **FR-024** Provider/framework detection MUST be separate from provider security verdicts and from static-vs-live-vs-business-logic coverage.
- **FR-025** Architecture MUST define a Security Pack Evidence/Coverage contract. Supabase is the P0 post-R1 pack and cannot bypass reconciliation.
- **FR-026** Base install MUST remain useful without external scanners, cloud services or LLM providers.

### LLM boundary

- **FR-027** LLM integration MUST be optional and feature/config gated.
- **FR-028** LLM-produced Evidence MUST be structurally restricted to INFERENCE/HYPOTHESIS.
- **FR-029** LLM output MUST NOT suppress Findings, set VERIFIED, weaken policy/kernel invariants or independently lower authoritative severity/proof state.
- **FR-030** Remote raw source/prompt upload requires explicit configuration; local-only default remains.

### Security of Sentrdel

- **FR-031** Sentrdel MUST never construct target/external-engine commands through shell strings; argv arrays only and child environments deny-by-default/allowlisted.
- **FR-032** Untrusted repository, engine, policy/Rego and MCP inputs MUST have explicit byte/path/process/time/depth/buffer bounds appropriate to the boundary.
- **FR-033** Analysis MUST NOT execute target hooks, build scripts, proc macros, Cargo metadata/package-manager code, external Git transforms, submodule/network fetches or repository-configured helpers merely to inspect a target repository.
- **FR-034** Event/evidence history MUST be integrity-linked through hashes and expose verifiable session/head state; product language MUST NOT claim an unauthenticated local hash chain independently proves non-truncation/non-replacement.
- **FR-035** Third-party source reuse and privileged Sentrdel dependencies MUST be qualified. R1 pins Rust 1.98.0, commits `Cargo.lock` once dependencies exist, uses `cargo-audit` + `cargo-deny`, and applies elevated review to build scripts/proc macros/native/download-at-build dependencies.

## Key Entities

- **Evidence** — immutable producer observation/claim with provenance and epistemic class.
- **Finding** — reconciled security judgment linked to Evidence.
- **CoverageRecord** — what was covered, partial, unsupported, unavailable, failed or skipped.
- **AgentSecurityEvent** — integrity-linked record of agent/tool/environment action or decision.
- **PolicyDecision** — monotonic guard result with rule/kernel provenance.
- **SecurityGraphNode/Edge** — thin property/evidence graph with producer provenance.
- **EngineManifest/Run** — bounded external evidence producer contract and execution record.
- **SecurityPackManifest** — provider/framework evidence capability declarations without verdict authority.
- **ProjectProfile** — detected stack/providers/coverage/configuration.

## Edge Cases

- Empty/detached/shallow/large repositories; binary/generated/renamed/deleted/symlink/confusable files.
- Hostile Git config attempting external diff/textconv/filter/credential/network execution.
- Hostile `.cargo/config.toml` in target repo.
- External engine malformed JSON, hangs, output flood, non-zero, outside-root path or attempts to consume inherited secrets.
- Engines disagree.
- Repo policy tries to widen permissions or disable logging.
- MCP description/result prompt injection; giant/unterminated stdio frame; unsupported version negotiation.
- Deep/oversized Rego policy/input.
- Offline/no engine/no model operation.
- Supabase detected without installed deep pack -> visible partial/not-implemented coverage.
- Git hook bypass -> no enforcement overclaim.

## Success Criteria

- **SC-001** Clean-PR false-positive rate for release-gating checks is no worse than **1 FP per 5 clean PRs** on the R1 benchmark.
- **SC-002** Every high/blocking finding has valid repo-relative location when applicable, direct evidence basis, producer provenance and explicit proof/epistemic status.
- **SC-003** Warm native diff review completes **<5s p95** under 2,000 changed LOC on reference machine; broader warm 100k LOC target **<30s**.
- **SC-004** In-process MCP policy decision **<50ms p95**, excluding downstream tool/human time and bounded framing I/O.
- **SC-005** Removing/failing configured engine creates visible coverage gap, never clean.
- **SC-006** Contract/property tests prove no extension policy can downgrade kernel DENY and pathological bounded Rego inputs cannot bypass fail-closed behavior.
- **SC-007** Hostile prompt/MCP content cannot make LLM output FACT/VERIFIED, suppress deterministic evidence or weaken policy.
- **SC-008** Every benchmark finding has novice sentence naming actor/capability/object + clear action category without CWE/CVSS requirement.
- **SC-009** Base install/tests succeed without LLM, external scanner or cloud account; R1 MCP tests prove bounded stdio behavior and explicit protocol negotiation.
- **SC-010** Apache-2.0 license is present; source/dependency qualification exists before donor source copy or privileged dependency adoption; self-security gates pass before release.

## Non-Goals for v0.1

- Universal CPG/compiler semantics for all languages.
- Full Supabase/Firebase/cloud/provider security; R1 detection/contract only, Supabase static posture is R2.
- Remote/Streamable HTTP MCP gateway.
- Autonomous exploit generation/production pentesting.
- eBPF/runtime enforcement.
- Full verification sandbox / FIX_VERIFIED execution.
- VS Code/Cursor/JetBrains/GitHub App UI.
- Automatic fix application.
- Competing on total rule count/replacing mature SAST/SCA/IaC.

## Assumptions

- Review/init target Linux, macOS, Windows where Rust capabilities permit; enforcement fidelity varies and is reported.
- R1 MCP gateway is stdio-only even if upstream SDK supports remote transports.
- Sentrdel Core is licensed under Apache-2.0; exact donor compatibility remains per-source qualification.
