# Sentrdel Source-Driven Security Expansion — 2026-09-08

**Status:** ROADMAP_RESEARCH_SUPPLEMENT  
**Research date:** 2026-09-08  
**Planning base:** `main@bf50d14ef3747b028069d148f23c1696e9e67a42`  
**Active implementation boundary at planning time:** R3-T032 implementation is canonical; PR #301 owns the R3-T032 task-ledger closeout; R3-T033 remains unauthorized until that closeout is itself canonical and post-merge proven.  
**Sources:** Tencent/AI-Infra-Guard, google/magika, Tencent/AICGSecEval, Tencent/secguide, Tencent/TscanCode.  
**Source pins and license observations:** `docs/third-party/source-candidate-assessment-2026-09-08.md`  
**Authority:** Roadmap planning and research only. This document does not amend the Constitution, modify Spec 003, reorder R3-T033..R3-T038, qualify donor source/data for reuse, admit a dependency, authorize network/credential/target execution, or authorize post-R3 implementation.

## Executive decision

The five sources do **not** justify turning Sentrdel into another scanner bundle or red-team platform. They reveal three missing capability families that strengthen Sentrdel's existing category moat:

1. **Artifact Identity + Evasion-Resistant Analyzer Routing** — do not trust extensions or repository labels to decide what analysis is required; distinguish deterministic content observations from probabilistic classification and make routing disagreement visible.
2. **Agent / MCP / Skill Security** — treat tool descriptions, skill instructions, packaged code, permissions, dependencies, credential boundaries, and agent actions as first-class security artifacts that can be correlated with ASEL and the Sentrdel Semantic Security Graph (SSG).
3. **AI-Generated / Agentic Code Security Conformance** — evaluate repository-level changes produced by coding models/agents using invariant-regression, coverage, provenance, static evidence, and separately authorized dynamic verification rather than only counting CWE detections.

These additions must reinforce, not displace, the current post-R3 priority: **Security Invariant Regression first**. S1-S5 remain the shortest path to product differentiation. The source-driven capabilities enter as bounded cross-cutting gates around S4/S6 and later R7/R9 work.

## What the source study changes

The existing roadmap is correct on its major strategic choice: mature raw scanners should usually be imported, not rebuilt, and Sentrdel should own evidence contracts, coverage truth, semantic identities, invariants, regression, verification discipline, and judgment.

The study adds five refinements:

- **Before routing to analyzers, Sentrdel needs a trust model for artifact identity.** A file name or extension is untrusted repository input. Classifier output is also not authoritative truth.
- **Agent security needs a dedicated semantic/security domain rather than being implicit under generic MCP or supply-chain work.** The domain includes instruction, memory, tool, permission, dependency, credential, exfiltration, and action provenance risks.
- **SentrdelBench needs an agent-generated-code profile.** The evaluator must remain independent from the generator and must measure security-property regression and coverage loss, not merely whether a generated patch contains a known CWE.
- **Knowledge/rule sources require a candidate pipeline with license, freshness, provenance, and promotion controls.** A security guide or external rule library is not automatically a Sentrdel rule pack.
- **Agent/model provenance needs a claimed-versus-attested identity boundary.** A coding agent may claim one model/provider while a relay or endpoint serves another. Sentrdel should preserve this distinction for audit and reproducibility without making default review perform network model fingerprinting.

## Source disposition

| Source | Planning disposition | High-value contribution | Explicit non-adoption |
|---|---|---|---|
| `Tencent/AI-Infra-Guard` | `RESEARCH_PINNED / HIGH_PRIORITY_TAXONOMY_AND_CONFORMANCE_REFERENCE` | MCP/Agent/Skill threat taxonomy, scanner-evasion cases, security-skill evaluation patterns, AI-infrastructure evidence shapes, model/API-relay integrity research, red-team test ideas | No full Python/Go/Docker platform; no default remote scan; no inherited LLM/API-key requirement; no dynamic attack or relay-probing authority in ordinary review |
| `google/magika` | `RESEARCH_PINNED / HIGH_PRIORITY_OPTIONAL_ARTIFACT_CLASSIFIER_CANDIDATE` | Content-based file classification, confidence/unknown behavior, fast routing signal, Rust implementation reference | No classifier output as FACT; no analyzer suppression solely from ML prediction; no ONNX/native/model dependency in base installation without separate qualification |
| `Tencent/AICGSecEval` | `RESEARCH_PINNED / HIGH_PRIORITY_BENCHMARK_METHODOLOGY_REFERENCE` | Repository-level AI-generated code tasks, CWE/CVE metadata, agent evaluation, static+dynamic evaluation separation | No unreviewed dataset/image/PoC copy; no normal-path Docker/provider credentials/GitHub tokens; no dynamic proof treated as ordinary static evidence |
| `Tencent/secguide` | `RESEARCH_PINNED / KNOWLEDGE_SOURCE_ONLY` | Secure-coding knowledge and remediation/rule-candidate ideas | No direct text/rule corpus adaptation into the Apache-2.0 trusted core while CC-BY-SA/source-license questions remain unresolved; no stale guidance promoted without current validation |
| `Tencent/TscanCode` | `RESEARCH_PINNED / LOW_PRIORITY_EXTERNAL_ENGINE_REFERENCE` | Legacy static-analysis output shape, C/C++ defect examples, XML importer/conformance edge case | No GPL source/linkage in the permissive trusted core; no priority engine adoption; no language-support claim based on upstream marketing alone |

## Gap analysis

### G1 — Artifact identity is currently under-specified

**Problem:** analyzer selection can be weakened if Sentrdel trusts file extensions, generated metadata, declared language, MIME strings, or a single probabilistic classifier. Extension spoofing, bytecode, charset tricks, binary/text ambiguity, generated files, and polyglot-like content can create silent coverage loss.

**Plan:** define an Artifact Identity contract with separate fields for:

- repository path and declared/extension-derived type — untrusted observation;
- deterministic bounded byte/content observations — FACT-capable when directly observed;
- optional classifier output — INFERENCE only;
- confidence/unknown state;
- disagreement diagnostics;
- analyzer-routing decision and why each analyzer was included or excluded;
- explicit coverage state when routing cannot be resolved safely.

**Hard rule:** no probabilistic classifier may be the sole reason to suppress an analyzer that deterministic or extension-based signals would otherwise select. Prefer conservative **union routing** under resource caps. Disagreement must remain visible.

### G2 — Probabilistic security producers need a general epistemic boundary

The Constitution already constrains LLM output. The same discipline should explicitly cover ML classifiers and AI-assisted scanners.

A model score, file-type prediction, external confidence, external severity, or external reachability claim is not a Sentrdel FACT merely because the producer is accurate on a benchmark. It remains the producer's classification unless corroborated through a stronger Sentrdel evidence path.

Future Evidence/importer conformance should freeze this rule for all probabilistic producers, not only LLMs.

### G3 — Agent/MCP/Skill security is not explicit enough

Sentrdel already has an MCP guard seam and agent-security events, but the roadmap does not yet freeze a dedicated static security domain for agent artifacts and tool ecosystems.

The future domain should evaluate, where statically and deterministically supported:

- instruction hijacking / instruction-authority confusion;
- memory poisoning or persistent untrusted-context injection;
- tool poisoning, tool-description spoofing, and capability mismatch;
- credential and data-exfiltration paths;
- indirect prompt-injection paths;
- SSRF-via-agent capability paths;
- RCE-via-tool capability paths;
- remote payload download/execution declarations;
- embedded malicious code in skills/plugins;
- privilege escalation / over-broad permissions;
- persistence mechanisms;
- insecure or newly introduced dependencies;
- web/network exfiltration capability;
- suspicious install/build/runtime actions;
- unsupported/dynamic behavior as visible coverage, not clean output.

The first slice must be **static/local-first**. Dynamic attack generation, live remote MCP probing, model jailbreak testing, or execution-based tool abuse belongs only in a future R6 verification/red-team tier with explicit isolation and authorization.

### G4 — Agent artifacts should join ASEL and the SSG

A standalone "agent scanner" would be easy to copy and weakly differentiated. Sentrdel should instead bind agent artifacts to its existing judgment substrate when provenance permits.

Candidate semantic chain:

`skill/tool manifest -> instruction/context origin -> declared capability/permission -> credential/network/filesystem boundary -> ASEL action -> code/dependency/provider/resource impact -> invariant/coverage state`

This allows Sentrdel to answer a stronger question than "is this skill suspicious?":

> Which project security property can this agent artifact or action weaken, what authority does it request, what evidence supports that path, and what remains unproven?

### G5 — AI-generated code needs a repository-level SentrdelBench profile

SentrdelBench currently measures Sentrdel quality. It should additionally freeze a profile for **changes produced by AI coding models and agents**.

Each benchmark item should preserve:

- trusted-base revision;
- repository/task identity;
- generator type (`model`, `agent`, or human control);
- claimed generator/provider/model/version/config when publishable;
- separately attested/observed generator identity when available;
- candidate patch/revision digest;
- intended functional requirement;
- expected security invariant states before/after;
- expected coverage states before/after;
- CWE/CVE metadata when relevant but not required for every semantic regression;
- static expected evidence;
- optional verification contract separated from static labels;
- reproducibility metadata;
- public/protected corpus classification.

Primary metrics should include invariant-regression precision/recall, clean-change FP rate, coverage-loss truthfulness, explanation correctness, deterministic replay, and latency. Raw CWE count is secondary.

### G6 — Public benchmark contamination and evaluator independence need stronger wording

The generator, candidate-improvement loop, and R11 learning plane must not have access to the protected release holdout or mutate the evaluator/labels used to judge the current candidate.

Public agentic cases are for ecosystem interoperability and debugging. Protected holdouts remain release qualification evidence. Generator performance and Sentrdel evaluator performance must be reported separately.

### G7 — Scanner-evasion/adversarial routing corpus is missing

Add future R9 conformance fixtures for at least:

- extension/content disagreement;
- generic/unknown content classification;
- text encoded to evade naive scanners;
- bytecode or compiled artifacts adjacent to source claims;
- malformed/truncated inputs;
- oversized content and cap exhaustion;
- duplicate/conflicting paths or metadata;
- generated/minified artifacts;
- nested archive/container content only when a future bounded archive contract explicitly supports it;
- external producer output with malformed encodings, huge messages, path traversal strings, duplicate IDs, and adversarial SARIF/XML/JSON fields.

Every failure must either produce bounded evidence or explicit coverage diagnostics. It must never become PASS because a parser or classifier declined the input.

### G8 — External Evidence Import needs a generic producer-adapter contract

S6 correctly prioritizes SARIF, CycloneDX, SPDX, and OSV. It should also define a generic adapter envelope for tool-specific XML/JSON without granting each tool bespoke judgment semantics.

The envelope should preserve:

- producer name/version/digest;
- producer config/rule-pack identity;
- original record ID/classification/severity/confidence;
- source location and artifact digest;
- import parser/version;
- validation and truncation diagnostics;
- mapped Sentrdel Evidence class and authority ceiling;
- coverage emitted when parsing/producer capability is missing or failed.

TscanCode-style XML and AI-Infra-Guard-style SARIF/JSON are useful future conformance fixtures; neither should become a canonical dependency merely to support the format.

### G9 — Knowledge sources need provenance, freshness, and promotion states

Security guides, vulnerability rule libraries, research reports, and community submissions should enter R11 as **candidate knowledge**, never directly as trusted rules.

A future candidate record should include:

- exact upstream repository/ref/file or publication identity;
- license and reuse mode;
- source freshness / last validated date;
- affected language/framework/version scope;
- CWE/CVE/OWASP taxonomy mappings where applicable;
- transformation history;
- candidate author/generator identity;
- evidence supporting the rule/pattern;
- benchmark qualification results;
- protected-holdout results;
- promotion/retirement/revocation state;
- revalidation deadline for time-sensitive intelligence.

Old but useful guidance may remain research evidence while being ineligible for automatic rule promotion.

### G10 — Benchmark/data provenance needs artifact-level rights tracking

A benchmark repository license does not automatically prove that every embedded project sample, CVE-derived file, patch, PoC, Docker image, or generated corpus item can be copied into Sentrdel.

Before any external benchmark data is imported, freeze a data-import record containing source repository, exact commit/artifact, license/provenance, CVE/CWE linkage, transformation, expected outcome, execution requirements, and public/protected distribution eligibility.

### G11 — Dynamic evaluation must be separated from normal review authority

AI-Infra-Guard and AICGSecEval include useful dynamic/red-team ideas but also rely on combinations of Docker, live services, remote URLs, model/provider APIs, credentials, tokens, PoCs, and target execution.

Those capabilities map to future R6 verification/red-team tiers only after isolation, network policy, resource caps, authorization, secret handling, artifact retention, and reproducibility are frozen. Ordinary `sentrdel review` remains static/local/no-target-execution.

### G12 — Source freshness belongs in qualification

Future source/dependency/data qualification should record:

- exact ref/date;
- upstream release cadence / maintenance observation;
- last Sentrdel revalidation date;
- security-sensitive change delta since prior qualification;
- required requalification trigger (version, features, model, rules, dataset, native dependency, network behavior, or license change).

This matters because the studied sources range from active 2026 projects to security guidance and scanner code with substantially older maintenance lines.

### G13 — Language breadth must not preempt the regression moat

AICGSecEval demonstrates broad multi-language evaluation. That breadth is useful for future benchmark design, but Sentrdel should not chase language-count parity before S1-S4 prove invariant-regression quality.

Future language/provider expansion should continue to use **invariant leverage**:

- what new actor/guard/resource semantics become provable?
- which security invariant becomes more precise?
- how much coverage improves?
- what new false-positive/authority/dependency risk appears?

### G14 — Model/provider identity and relay provenance are missing action context

AI-assisted development increasingly depends on hosted models, API relays, gateways, and agent runtimes. A configured or reported model name is not proof that the expected model/provider actually produced a response. AI-Infra-Guard's model/API-relay integrity work highlights substitution and poisoned-relay risk as a distinct provenance problem.

Sentrdel should **not** respond by placing live model fingerprinting in ordinary static review. Instead, future ASEL/benchmark/posture contracts should distinguish:

- claimed agent/model/provider/version identity;
- agent/runtime configuration digest;
- relay/gateway identity or sanitized configuration identity when present;
- attestation/signature/fingerprint evidence when independently available;
- verification state (`UNVERIFIED`, `ATTESTED`, `MISMATCH`, or future equivalent);
- provenance for the mechanism that established the stronger identity claim;
- explicit absence of identity verification as audit context, not an automatic code Finding.

Any active black-box model/API relay audit requires a separately authorized network/credential verification tier and produces imported/verification evidence with bounded authority. It must not silently mutate the identity recorded for historical ASEL actions.

This gap primarily strengthens reproducibility, agent-action provenance, and later R10 project posture; it is not a reason to reorder S1-S6.

## Refined post-R3 execution sequence

Canonical S1-S11 identities remain unchanged. The labels below are **planning gates**, not new authorized slice IDs.

1. **S1 — Security Invariant Regression Core** — unchanged.
2. **S2 — Security Regression Developer Contract** — unchanged.
3. **S3 — GitHub / Forge Delivery** — unchanged.
4. **S4 — Open Regression Conformance** — unchanged.
5. **Gate A — Agentic Code Security Conformance Profile (R9)** — extend SentrdelBench with repository-level AI/agent-generated change pairs and protected holdouts before broad agent-specific detector growth.
6. **S5 — Bounded Verification of High-Value Invariants** — unchanged; this remains the only path toward execution-backed `FIX_VERIFIED` claims.
7. **Gate B — Artifact Identity + Evasion-Resistant Routing (R7/R9)** — freeze content/extension/classifier disagreement semantics and analyzer routing before broad external-producer expansion.
8. **S6 — External Evidence Import Protocol** — retain standards-first imports, then generic bounded producer adapters.
9. **Gate C — Agent/MCP/Skill Static Security Domain (R7/R9, later R10 correlation)** — static/local artifact and capability analysis, with ASEL/SSG linkage; no dynamic red-team authority by default.
10. **S7 — Semantic Provider Expansion** — unchanged, chosen by invariant leverage.
11. **S8 — Dependency/Build Action Guard** — extend later to agent/skill installation actions where Sentrdel genuinely controls the seam.
12. **S9 — Runtime Correlation** — attach runtime/agent observations to stable semantic identities without rewriting static facts.
13. **S10 — SSG Project Posture** — compose mature domains, including agent/tool authority paths and separately qualified agent/model/provider provenance evidence.
14. **S11 — Open Intelligence / Controlled Learning** — add the provenance/freshness/license/revalidation pipeline defined above; candidate generation still cannot self-promote.

## Gate A — Agentic Code Security Conformance

### Entry conditions

- R3 canonical closeout;
- S1 regression state contracts frozen;
- S4 public/protected conformance separation established;
- exact data-rights/provenance rules defined before importing external benchmark material.

### Exit conditions

- at least one safe and one vulnerable/coverage-loss repository-level agent-generated change per supported semantic family;
- generator and evaluator identities separated;
- claimed and independently attested generator identity are not conflated;
- deterministic expected regression/coverage outputs;
- protected holdout unavailable to candidate-generation logic;
- no provider API or agent runtime required to replay the frozen candidate changes;
- optional dynamic validation stored as a different evidence tier.

## Gate B — Artifact Identity + Evasion-Resistant Routing

### Minimum contract

For each considered artifact, Sentrdel should be able to explain:

1. what path/extension claimed;
2. what bounded deterministic content observations showed;
3. what optional probabilistic classifier predicted;
4. where signals disagreed;
5. which analyzers were selected and why;
6. which analyzers were skipped and under what explicit coverage state;
7. which resource caps were reached.

### Magika decision boundary

Magika is a strong candidate **signal producer**, not a judgment authority.

Before any runtime/dependency adoption, a future qualification must compare at least:

- optional external-process integration;
- optional in-process Rust feature;
- no-Magika deterministic baseline.

The review must account for ONNX Runtime/native/model artifact surfaces, feature flags, artifact/model provenance, update mechanism, memory/latency, offline behavior, and whether an external process keeps the trusted base smaller. Base Sentrdel must remain useful without the classifier.

## Gate C — Agent/MCP/Skill Static Security Domain

### Initial supported artifacts

A future spec should choose a deliberately small set of inspectable local artifacts, for example:

- MCP server/tool manifests and tool schemas;
- agent skill/plugin manifests;
- skill instruction files;
- bundled local code referenced by a skill;
- declared dependencies/install hooks;
- declared filesystem/network/secret/command capabilities;
- Sentrdel-observed ASEL events for related actions.

### Initial evidence families

Candidate evidence may represent:

- instruction/context source and trust class;
- declared tool capability;
- requested permission/credential/network scope;
- dependency and install/build behavior;
- suspicious cross-boundary data flow;
- action provenance;
- claimed agent/model/provider identity as non-attested context;
- explicit unsupported/dynamic coverage.

No single heuristic, LLM answer, external risk score, or claimed model identity creates a Finding. The same reconciler and evidence/coverage authority rules apply.

## Source-specific follow-up qualification backlog

These are future research/qualification candidates only. They are not active R3 tasks.

### AI-Infra-Guard

- Pin exact candidate files only for the threat taxonomies, SARIF/output mapping, static MCP/Skill rules, model/API-relay integrity methodology, and benchmark methodology that a future spec actually needs.
- Separate static rules from dynamic red-team and relay-probing code.
- Record LLM/API-key/network/Docker/runtime surfaces explicitly.
- Do not inherit its unauthenticated web service or remote-target scanning model.
- Treat black-box model/API relay checks as future optional verification/external evidence, never default review authority.
- Prefer independently authored Sentrdel contracts/taxonomy mappings unless exact source reuse materially reduces risk or effort.

### Magika

- Qualify the exact Rust library/model artifacts only if Gate B proves classifier value beyond deterministic routing.
- Treat prediction as INFERENCE.
- Benchmark false routing, unknown behavior, adversarial extension/content mismatch, latency, memory, and offline reproducibility.
- Never activate download-at-build/test features in production qualification merely for convenience.

### AICGSecEval

- Study dataset schema, context extraction, agent integration, checkpoint/reproducibility, and static/dynamic evaluation separation.
- Import no sample, CVE-derived project, PoC, image, or generated output until artifact-level rights/provenance are recorded.
- Reuse methodology first; copy data only when independently justified.

### secguide

- Treat the repository as a research bibliography/knowledge source.
- Resolve the repository README/license wording inconsistency before any adapted material is distributed.
- Prefer independently authored rules/remediation backed by current primary references and Sentrdel benchmarks.
- Record staleness and affected-version scope.

### TscanCode

- Keep GPL implementation outside the Apache-2.0 trusted core.
- If future demand justifies it, evaluate only an optional external process boundary with explicit version pin, argv/env/cwd/output caps, and imported low-authority evidence.
- Use representative XML as an importer conformance case without making TscanCode a required engine.

## Release and quality metrics added by this supplement

In addition to the existing product scorecard, future applicable specs should measure:

- analyzer-routing false-negative rate caused by artifact identity;
- extension/content/classifier disagreement rate and handling correctness;
- unknown-classification coverage truthfulness;
- external-import parser robustness and truncation behavior;
- agent artifact threat-family precision/recall on supported static scope;
- agent/skill clean-case false-positive rate;
- ASEL/SSG linkage provenance correctness;
- claimed-versus-attested agent/model/provider identity handling and provenance completeness where applicable;
- agent-generated-code invariant-regression precision/recall;
- benchmark contamination controls;
- source/rule freshness and revalidation compliance;
- base-install dependency/latency/memory impact of optional classifier or external producers.

## Explicit deferrals and non-goals

This supplement does **not** propose:

- cloning AI-Infra-Guard's platform;
- making an LLM mandatory for Sentrdel security judgment;
- autonomous jailbreak generation or exploitation;
- remote MCP/agent scanning in ordinary review;
- default network model/API fingerprinting or relay probing;
- provider credentials in the default path;
- treating an unverified model/provider identity as proof of compromise;
- a universal malware scanner;
- replacing all file parsers with ML classification;
- importing AICGSecEval Docker/PoC workloads into normal CI;
- copying CC-BY-SA guidance into the Apache-2.0 core without exact qualification;
- linking GPL TscanCode implementation into Sentrdel;
- expanding to every language simply because an external benchmark contains it;
- allowing external severity/confidence to bypass the reconciler;
- allowing R11 candidate generation to alter the evaluator or holdout used to judge itself.

## Reconciliation with the existing roadmap

This supplement **strengthens** rather than replaces the 2026-09-02 blueprint:

- S1-S5 remain the first post-R3 product path.
- S4 gains an explicit agentic-code benchmark profile.
- S6 gains an artifact-identity prerequisite and a generic external-producer adapter contract.
- R7 gains a future static Agent/MCP/Skill domain and stronger source/knowledge provenance.
- R9 gains routing-evasion, probabilistic-producer, importer, and agentic-code conformance.
- R10 may later correlate agent/tool capabilities and separately qualified model/provider provenance through the existing SSG/ASEL substrate.
- R11 gains freshness/license/revalidation state but no new promotion authority.

No canonical roadmap ID is renumbered by this document. Gate A/B/C are planning labels until ordinary future Spec Kit artifacts freeze implementation scope and identifiers.

## No current implementation authority

The active line remains Spec 003. At this document's planning base, the R3-T032 implementation is canonical and PR #301 owns its ledger closeout. R3-T033 may begin only when the canonical R3 task ledger and repository-governance proof say it may begin. Nothing in this supplement authorizes source adoption, dependency changes, runtime integration, benchmark-data import, dynamic evaluation, network access, credential use, model/API relay probing, or any post-R3 product code before the normal governance gates are satisfied.
