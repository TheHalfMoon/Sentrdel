# Sentrdel Constitution

**Version:** 1.0.1  
**Ratified:** 2026-08-24  
**Authority:** This document is the highest project-level authority for architecture, specifications, plans, tasks, reviews, and implementation. If a lower-level artifact conflicts with this constitution, the lower-level artifact MUST change.

## Mission

Sentrdel is the open-source security system for software development. It MUST protect the project from AI-assisted authoring through source changes, dependencies, identity, data, infrastructure, CI/CD, deployment, and runtime. It is not merely a SAST scanner, PR commenter, or model-specific coding-agent feature.

The product North Star is simple: developers should feel unsafe allowing an AI coding agent to change a meaningful project without Sentrdel protecting and reviewing that work.

## Principle I — Rust Trusted Core

The trusted Sentrdel core MUST be Rust-first. Security-critical orchestration, canonical schemas, evidence reconciliation, policy evaluation, event logging, graph logic, guard verdicts, and CLI behavior MUST live in Rust unless a specification proves a narrowly bounded exception.

External tools MAY be used through explicit process/protocol boundaries. Their output is untrusted input and MUST NOT become a Finding without canonical validation and reconciliation by the Rust core.

A Python, JVM, Go, or TypeScript donor MUST NOT silently become a runtime requirement for the base Sentrdel installation merely because reuse is convenient.

## Principle II — Evidence Before Verdict

Sentrdel MUST distinguish security knowledge by epistemic class. At minimum, the system MUST represent machine-observed facts, deterministic inferences, hypotheses, runtime observations, verified results, contradictions, and coverage gaps.

A FACT MUST describe a directly observable bounded property, not a semantic security conclusion merely inferred from that property. LLM output MUST NOT be structurally capable of becoming a fact or independently verified result. High-severity claims MUST expose their evidence chain and proof status. Missing analysis capability MUST be represented as a coverage gap, never as evidence that the project is clean.

Only the Sentrdel reconciler may create canonical Findings from Evidence.

## Principle III — Vendor-Neutral, Local-First Security

Sentrdel MUST remain useful without a proprietary cloud service and MUST NOT depend on one coding-agent vendor, model provider, forge, database provider, or deployment platform.

Vendor-specific integrations MAY improve fidelity, but the product architecture MUST remain centered on vendor-neutral seams: repository/diff analysis, MCP, git/CI gates, environment controls, stable protocols, and provider-independent evidence.

Raw project source, prompts, secrets, and evidence MUST remain local by default. Any remote model/provider usage MUST be explicit, optional, and bounded.

## Principle IV — Honest and Monotonic Guardrails

Sentrdel MUST distinguish an **enforced** control from an **advisory** observation. The product MUST NOT claim universal pre-execution interception where a vendor exposes no enforceable seam.

At controlled seams, verdict severity MUST be monotonic: downstream rules/plugins may make a decision stricter but MUST NOT weaken a kernel invariant or prior DENY. An undecidable action at an enforcement seam MUST fail closed into human review rather than silently pass.

Repository-controlled configuration MUST NOT be able to widen core permissions or disable evidence capture.

## Principle V — Safe Verification, Never Autonomous Exploitation

Verification MUST mean bounded, opt-in, isolated test execution that proves or disproves a security claim using synthetic or explicitly authorized local data. It MUST NOT mean autonomous exploitation of third-party or production systems.

Verification MUST default off until an isolation tier, network policy, resource limits, artifact-retention policy, and authorization boundary are proven for the target platform.

`FIX_VERIFIED` or equivalent status MUST require execution evidence, not LLM review or diff inspection alone.

## Principle VI — Full-Stack A-to-Z Security Through Explicit Packs

Sentrdel's long-term scope includes source, authentication, authorization, databases, storage, secrets, dependencies, supply chain, CI/CD, infrastructure, cloud, deployment, payments, webhooks, AI agents, MCP, and runtime.

Breadth MUST NOT be achieved through shallow generic checks. Provider/framework-specific Security Packs SHOULD encode deterministic domain knowledge where it materially improves security judgment. Supabase is a priority provider pack and MUST include RLS, grants, Auth, service-role boundaries, Storage policies, Edge Functions, migrations, exposed schemas, and relevant database security behavior as its coverage matures.

Packs MUST emit canonical Evidence and MUST NOT bypass the same reconciliation and proof rules as every other producer. Provider detection, static posture coverage, credentialed live posture coverage, and cross-layer business-logic coverage MUST be represented as distinct coverage dimensions rather than collapsed into one PASS/FAIL label.

## Principle VII — Reuse Mature Security Infrastructure; Own the Judgment Layer

Sentrdel SHOULD reuse proven OSS components instead of rebuilding parsers, policy languages, vulnerability databases, sandboxes, or mature scanners without a demonstrated reason.

Every adopted donor MUST have recorded provenance, exact version/commit, license qualification, security boundary, maintenance status, and modification history before source is copied or vendored.

Copyleft or restricted components MUST NOT contaminate the permissive trusted core; where legally appropriate they MAY remain optional external engines behind clean process boundaries.

Sentrdel's primary intellectual and community value MUST be the canonical evidence/event specifications, adjudication, invariants, agent-action security, provider-aware security packs, business-logic reasoning substrate, verification discipline, and developer experience—not the number of scanners wrapped.

## Principle VIII — False Positives, False Blocks, and Latency Are Security Quality

A security tool developers disable is a failed security control. Precision, false-positive rate, guard false-block rate, warm review latency, guard verdict latency, memory, and coverage gaps MUST be measured and treated as release-quality gates.

High-severity findings MUST prioritize correct evidence and location over rule-count coverage. Regressions in benchmarked precision or guard usability MUST block release according to the active release specification.

## Principle IX — Sentrdel Must Secure Itself

Target repositories, scanner output, MCP descriptions/results, rule packs, model output, git metadata, external-engine output, and Sentrdel's own third-party dependencies MUST be treated as untrusted until the applicable boundary validates them.

The core MUST prohibit string-built shell execution, sanitize paths, cap untrusted inputs, pin and record engine/dependency versions, scrub inherited subprocess environments, redact secrets before persistence, and maintain integrity-linked evidence/event history.

A local hash chain proves internal consistency only relative to a trusted checkpoint/head. Sentrdel MUST NOT describe an unauthenticated local hash chain as tamper-proof or as independently proving that history was not truncated or rewritten. Signing/remote attestation MAY strengthen this in later specifications.

Sentrdel's own dependencies and release artifacts MUST be auditable and supply-chain hardened. Dependencies that execute during build—especially `build.rs` scripts and procedural macros—require explicit qualification commensurate with their authority.

## Principle X — Spec Kit Governance

All implementation work MUST be driven by Spec Kit artifacts. Large initiatives MUST use a spec-of-specs roadmap and then bounded sub-specs rather than one unimplementable mega-spec.

The normal lifecycle is:

`constitution → specify → clarify → plan/research/design → checklist → tasks → analyze → implement → converge`

Implementation MUST NOT start for a slice until its `spec.md`, `plan.md`, required design/contracts, implementation-readiness checklist, and `tasks.md` are complete and internally consistent.

Founder constraints and explicit safety/authority boundaries override inferred convenience. Generic implementation progress MUST NOT silently expand permissions such as live exploitation, credential access, production mutation, external scanning, or destructive repository operations.

## Governance

- Amendments require an explicit documented change to this constitution and a version bump.
- **MAJOR**: removes or materially weakens a principle or changes the project category/trust model.
- **MINOR**: adds a new binding principle or materially expands governance.
- **PATCH**: clarifies language or tightens an existing invariant without changing the product category.
- Every Spec Kit plan MUST include a Constitution Check before implementation.
- Any justified exception MUST be documented in the feature plan's Complexity/Exception section with scope, expiry, risk, and rejected simpler alternative.
