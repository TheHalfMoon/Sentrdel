# Sentrdel R1/R2/R3 Threat Model

**Tasks:** T083 / R2-T032 / R3-T035  
**Scope:** v0.1 Evidence + Guard Foundation, Spec 002 Supabase static posture, and Spec 003 bounded cross-layer business-logic analysis  
**Authority:** descriptive security documentation subordinate to the Constitution and active Spec Kit contracts

## 1. Security objective

Sentrdel is a local-first security evidence and control plane for software development. Its security objective is to inspect attacker-controlled development inputs, produce provenance-bearing evidence, and enforce only explicitly owned guard boundaries without allowing those inputs to become execution, policy, credential, epistemic, or release authority.

R1 establishes the evidence/control plane and guard boundaries. R2 extends that plane with a bounded offline Supabase static posture pack. R3 extends it with bounded static cross-layer business-logic analysis and tightening-only security invariants. This document describes implemented trust boundaries and non-claims. It does not create new product authority.

## 2. Trusted computing base

The trusted computing base includes:

- the first-party Rust workspace under `crates/`;
- canonical schema validation, hashing, Evidence/Finding/Coverage/ASEL contracts;
- Rust-owned policy kernel invariants and monotonic policy composition;
- bounded repository/Git readers and native producer framework;
- the reconciler as the only canonical Finding creation path;
- the bounded Sentrdel Semantic Security Graph substrate and its provenance/resource limits;
- bounded external-engine process orchestration and adapters;
- bounded stdio MCP gateway framing, policy, approval, forwarding, and ASEL path;
- trusted bootstrap/configuration code that constructs non-deserializable authority capabilities;
- the R2 Rust-owned Supabase static-posture producers and their bounded parser/state/config/source-context substrate;
- the R3 Rust-owned route/actor/guard/value/data/link/path/invariant analysis substrate and runtime-owned Evidence/Coverage producer authority;
- release/self-security governance for Sentrdel's own trusted workspace.

Third-party dependencies are not assumed safe merely because they are inside the build graph. They remain governed supply-chain inputs and are admitted through dependency/source qualification policy.

## 3. Attacker-controlled or untrusted inputs

Unless an explicit higher-authority contract says otherwise, treat these as attacker-controlled data:

- target repository files, file names, symlinks, Git metadata/config/history, diffs, and commit messages;
- repository documentation, comments, generated files, instructions, policy/configuration text, and hidden tool configuration;
- Supabase migrations, SQL, `supabase/config.toml`, Edge Function source, application source, and key-shaped literals found in a target repository;
- R3 route/application source, dynamic registration/dispatch patterns, project invariant declarations, semantic-link inputs, and unsupported framework/language constructs;
- issue, pull-request, review, CI-log, chat, ticket, browser, and retrieved-document content;
- external-engine executable behavior, stdout, stderr, SARIF, JSON, locations, and self-reported severity;
- MCP server/tool names, descriptions, schemas, arguments, results, resources, prompts, protocol behavior, and child-process output;
- LLM/model prompts, responses, summaries, suggested commands, severity claims, and remediation text;
- imported context, feedback, or future memory records unless independently admitted by trusted-core authority;
- dependency/build-time code until qualified.

Readable or parseable content is not trusted instruction.

## 4. Core authority invariant

Sentrdel separates content availability, epistemic status, and instruction authority:

```text
readable content != trusted instruction
stored context != FACT
model agreement != policy authority
scanner severity != canonical severity authority
repository configuration != capability widening
project invariant declaration != suppression or execution authority
graph confidence != epistemic upgrade
```

Authority capabilities are constructed only by trusted Sentrdel paths. Untrusted serialized content cannot mint or deserialize filesystem, process, network, credential, policy, Evidence, reconciler, workflow, verification, benchmark, or release authority.

Instruction-shaped text remains data even when it is imperative, repeated, signed by an untrusted identity, produced by a model, returned by an MCP tool, stored in a repository, or retrieved from future memory.

## 5. Primary trust boundaries

### 5.1 Repository -> review

**Threats:** path traversal, symlinks, confusables, oversized files, hostile Git configuration, binary input, hidden instructions, target-controlled build/package-manager helpers, malicious lock/config files.

**Controls:** bounded path normalization/file reads, read-only Git access, no target hooks/filters/textconv/package-manager/Cargo execution, explicit size bounds, deterministic producer ownership, redaction-before-persist, explicit coverage gaps.

**Non-claim:** Sentrdel does not provide compiler-complete semantic analysis for all languages.

### 5.2 External engine -> core

**Threats:** malicious executable behavior, output floods, hangs, inherited credentials, malformed output, forged paths, self-assigned authority.

**Controls:** trusted executable resolution, argv execution rather than shell strings, bounded cwd/time/stdout/stderr, deny-by-default child environment with explicit allowlist, strict result adapters, normalized repo-relative locations, explicit CoverageRecord on failure/unavailability.

**Non-claim:** a successful engine run does not make the engine trusted or its conclusion canonical by itself.

### 5.3 MCP peer -> guard

**Threats:** giant or unterminated frames, protocol confusion, malicious descriptions/results, prompt injection, argument manipulation, credential inheritance, downstream hangs/failures, attempts to widen policy through tool metadata.

**Controls:** Sentrdel-owned bounded stdio framing, explicit protocol-version allowlist, bounded metadata/args/results, pre-invocation monotonic policy, scoped approval, fail-closed protocol handling, ASEL events, and a Rust-owned child-process environment boundary.

**Scope:** R1 enforcement is bounded stdio MCP only. Remote/Streamable HTTP MCP is not implemented.

### 5.4 Repository policy/config -> kernel

**Threats:** policy weakening, DENY downgrade, silent ALLOW on evaluation failure, evidence suppression, capability widening.

**Controls:** `ALLOW < ASK < DENY` monotonic composition, Rust kernel invariants, narrowing-only repository policy, bounded Regorus evaluation, explicit UNDECIDABLE/failure behavior.

### 5.5 Model/context -> reasoner and presentation

**Threats:** prompt injection, fact fabrication, finding suppression, authoritative severity downgrade, policy downgrade, credential requests, instructions hidden in repository/MCP/web/model content.

**Controls:** provider-neutral bounded reasoner request, explicit local/remote network gates, model output mapped only to `INFERENCE`/`HYPOTHESIS`, no reconciler or policy authority, prompt-injection authority tests, deterministic review independent of model availability.

The binding context/learning authority ceiling is defined in `specs/001-v0-1-evidence-guard-foundation/contracts/context-learning-authority.md`.

### 5.6 Evidence/reconciler -> Finding

**Threats:** forged producer identity, epistemic escalation, unsupported interpretations labeled as facts, direct Finding creation by producers/models, contradiction erasure.

**Controls:** runtime-owned producer authority, canonical Evidence identity validation, producer-specific epistemic ceilings, reconciler-only canonical Finding creation, preserved provenance/contradictions, deterministic correlation.

### 5.7 Persistence/export -> durable security state

**Threats:** secret persistence, stable secret-value fingerprint leakage, forged canonical IDs, mutable Evidence, misleading ASEL integrity claims.

**Controls:** redaction before persistence, prohibition on secret plaintext and stable unkeyed secret-only hashes, content-addressed Evidence identity, immutable Evidence persistence, ASEL hash-link validation, explicit trusted-head distinction.

**Non-claim:** an unauthenticated local ASEL hash chain is not tamper-proof against complete local history replacement or truncation.

### 5.8 Dependency/build -> Sentrdel release

**Threats:** malicious/yanked/vulnerable crates, build scripts, proc macros, native linkage, unqualified sources, dependency confusion, compromised self-security tooling.

**Controls:** exact direct dependency requirements, committed lockfile, crates.io-only third-party sources, privileged dependency declarations/qualification, checksum-pinned cargo-audit/cargo-deny tools, release malicious-package defense-in-depth denylist, recurring advisory refresh, protected-main CI.

R3's TypeScript grammar admission remains governed by its exact source/dependency qualification record rather than by language-support demand.

**Non-claim:** advisory/denylist PASS is not proof that every dependency is behaviorally safe.

### 5.9 Supabase repository state -> R2 static posture

**Threats:** hostile or ambiguous migration order, unsupported/dynamic SQL, misleading comments or prompt-shaped source, malformed/oversized configuration or source, secret/service-role material in client code, disabled Edge Function platform verification without equivalent authorization, and attempts to make repository text authorize provider/network/target execution.

**Controls:** canonical bounded migration discovery, bounded SQL/config/source parsing, deterministic repository-derived posture state with provenance, first-class UNKNOWN/partial coverage, explicit key authority and source-context classification, secret redaction before persistence, supported replacement-authorization proof only where the frozen contract permits it, and adversarial no-network/no-target-execution/instruction-authority canaries.

**Authority boundary:** R2 Supabase producers emit Evidence and Coverage only. They cannot create canonical Findings directly, weaken policy, grant network/provider credentials, or execute target code.

**Non-claims:** R2 does not inspect hosted Supabase state, connect to a database/dashboard/API, run the Supabase CLI or SQL/migrations/Edge Functions, or prove runtime provider behavior. `LIVE_POSTURE` and `RUNTIME` remain explicit unimplemented/not-executed dimensions.

### 5.10 Repository application semantics -> R3 business logic

**Threats:** lexical names masquerading as identity proof, guards elsewhere in code being treated as dominating an operation, unsupported middleware/dynamic dispatch being treated as safe, ambiguous semantic links becoming authoritative, static R2 posture being upgraded to hosted truth, project declarations becoming a suppression channel, graph confidence becoming verdict authority, hostile instruction-shaped source gaining execution/network/credential/Finding authority, and resource-limit exhaustion disappearing into a clean result.

**Controls:** explicitly allowlisted adapters, typed route/actor/guard/value/data observations, bounded derivation and path/link semantics, explicit UNKNOWN/PARTIAL/unsupported coverage, hard parser/graph/path/invariant caps, provenance-bearing SSG projection, R2 evidence retained as static supporting input, tightening-only project invariants, runtime-owned R3 producer authority, and reconciler-only Finding creation.

**Implemented scope:** bounded supported JavaScript/TypeScript Express, Next.js App Router, Next.js Pages API, Supabase Edge Function, and Supabase JavaScript data-operation patterns frozen by Spec 003. Built-in invariant families cover tenant/object binding, privileged function/role authorization, protected-property mutation, and elevated provider-client application boundaries.

**Authority boundary:** ordinary R3 analysis performs no target application/build/package-manager/test/migration/database/provider-tool execution, requires no provider-admin credential or hosted-provider connection, performs no provider-network interrogation, and does not create Findings directly. Project invariant declarations may add requirements only; they cannot suppress Evidence, waive Findings, lower severity, accept risk, widen process/network/credential authority, impersonate built-ins, or execute content.

**Non-claims:** R3 does not prove runtime exploitability, actual cross-tenant access, hosted provider truth, production authorization behavior, universal CPG/compiler semantics, or support for every framework/language/middleware/ORM/auth pattern. Unsupported or dynamic semantics reduce coverage rather than imply security.

## 6. MCP credential inheritance boundary

The stdio MCP child is a separate authority boundary. The default is **no ambient environment inheritance**.

Sentrdel may pass only normalized process requirements and capabilities explicitly authorized for that child. Repository text, MCP descriptions/results, model output, or a tool argument naming a credential must never cause that credential to be inherited.

The default child environment excludes cloud/model/forge/signing/SSH/database/provider-admin credential canaries. Tests must continue to prove this absence. A future explicit capability may authorize a narrowly scoped value, but that requires its own trusted configuration/authority path and cannot be created by the MCP peer itself.

This boundary limits accidental credential exposure; it does not claim OS-level sandboxing of the child process.

## 7. Context and instruction authority

Untrusted context can be parsed, displayed, correlated, summarized, or converted into schema-authorized low-authority Evidence. It cannot directly or indirectly:

- widen filesystem/process/network/credential/provider/MCP/repository permissions;
- downgrade a kernel DENY or turn UNDECIDABLE into silent ALLOW;
- disable redaction, provenance, coverage, or ASEL requirements;
- suppress/delete canonical Evidence or Findings;
- mint authority tokens or create Findings outside the reconciler;
- promote model/context output to FACT/OBSERVATION/VERIFIED outside its producer contract;
- make a project invariant weaken a built-in invariant or authorize execution;
- alter evaluator/holdout/release authority for a candidate it is helping generate.

Future memory/feedback/learning features remain deferred and inherit this authority ceiling.

## 8. Secret handling

Discovered secret material is handled under a minimize-before-persist rule:

- secret plaintext must not enter durable Evidence/store/export/log/snapshot fixtures;
- stable unkeyed hashes derived only from the secret value are also prohibited because they create reusable cross-context identifiers;
- changed-secret and R2 Supabase key Evidence retain only allowed rule/type/location/redacted display and sanitized non-secret fingerprints/provenance;
- R3 hostile/project-invariant fixtures cannot grant secret/provider credential authority;
- engine/MCP child environments deny ambient credentials by default.

Sentrdel does not claim to prevent a compromised operating system or already-compromised Sentrdel process from observing in-memory values.

## 9. Enforcement fidelity

Sentrdel reports enforcement fidelity rather than flattening every integration into a single "protected" claim.

- proxied bounded stdio MCP actions can be `ENFORCED` at the Sentrdel gateway seam;
- installed local Git hooks are bypassable and therefore `PARTIAL`/advisory;
- R2 Supabase static posture is repository-derived evidence, not a live provider enforcement seam;
- R3 business-logic analysis is bounded static Evidence/Coverage, not a runtime enforcement seam;
- unsupported remote MCP/provider/runtime/framework/language semantics are explicit coverage gaps, not implicit security.

No documentation or UI should present a coverage gap as a clean verdict.

## 10. Network boundary

Local-first operation is the default. Network use is explicit and bounded:

- ordinary deterministic review, including R2 Supabase static posture and R3 business-logic analysis, must not depend on a model or provider network service;
- R2/R3 have no provider-network authority and do not use Supabase provider-admin credentials;
- optional OSV/model HTTP paths obey explicit configuration and `--no-network` behavior;
- R1 MCP forwarding is stdio-only;
- self-security CI may access pinned release/advisory sources for Sentrdel's trusted workspace and does not analyze arbitrary target repositories through Cargo tooling.

## 11. Denial of service and resource exhaustion

Sentrdel applies bounded reads, frame sizes, metadata/argument/result caps, output caps, process timeouts, policy depth/byte limits, R2 migration/SQL/config/source caps, and R3 parser/observation/derivation/graph/path/invariant limits at exposed seams. Resource-bound failure must be explicit and must not become silent success.

Sentrdel does not claim protection against every host-level resource exhaustion scenario or a hostile administrator controlling the machine.

## 12. Integrity and provenance

Cryptographic identity is scoped to what it actually proves:

- content IDs bind canonical bytes to a domain-separated digest;
- Evidence producer identity is runtime-owned and validated;
- R2 static posture keeps repository statement/config/source provenance separate across independent controls before reconciliation;
- R3 cross-layer observations and paths preserve repository-relative provenance and link basis; graph/path confidence cannot upgrade epistemic authority;
- ASEL links recorded events but requires an external trusted checkpoint/signature for stronger replacement/truncation detection;
- a signature, if introduced later, proves only the statement/key relationship it actually verifies and does not automatically grant instruction authority.

Unknown/failed provenance or integrity cannot be upgraded because contradictory evidence is absent.

## 13. Cross-platform qualification boundary

Supported R3 static paths and adversarial authority canaries are exercised in the canonical Linux/macOS/Windows matrix. This proves that the tested bounded Rust paths and canaries pass on those runners.

It does **not** prove identical operating-system interception semantics, hostile-code sandboxing, universal process/network containment, hosted-provider behavior, or runtime authorization equivalence across operating systems.

## 14. Explicit non-goals

R1/R2/R3 do not implement or claim:

- autonomous exploitation or production probing;
- remote/Streamable HTTP MCP enforcement;
- OS sandboxing/eBPF runtime enforcement;
- sandboxed exploit-condition verification;
- runtime proof that a static R3 path is exploitable or actually crosses tenant boundaries;
- universal compiler/CPG semantic certainty;
- automatic fix application;
- general-purpose Security Memory or memory-driven suppression;
- autonomous security research/learning or candidate promotion;
- signed community-pack distribution;
- IDE/forge enforcement integrations;
- credentialed/live Supabase posture, hosted provider interrogation, or runtime Supabase verification;
- complete framework/language/middleware/ORM/auth semantics beyond declared bounded adapters;
- deep Firebase/payment/cloud posture or provider packs outside explicitly implemented scopes.

## 15. Security regression expectations

Changes affecting a trust boundary must preserve tests that prove, as applicable:

- no target build/install/package-manager execution during analysis;
- no shell-string target/external command execution;
- no ambient engine/MCP credential inheritance;
- no provider network or target execution authority in R2 static posture or ordinary R3 business-logic analysis;
- malformed/oversized/dynamic/unsupported input fails boundedly or degrades coverage visibly;
- kernel DENY remains absorbing;
- model/context/repository comments/project invariants cannot gain FACT/VERIFIED/policy/reconciler/execution/network/credential authority;
- secret plaintext and stable secret-only digests are absent from persistence/export/log fixtures;
- missing/failed/unsupported producers remain visible in coverage;
- canonical Findings remain reconciler-owned;
- graph confidence and R2 static posture cannot become stronger epistemic/live truth through R3 correlation;
- protected-main and self-security gates are not weakened to make a change pass.

## 16. Reporting and triage

A Sentrdel vulnerability is a defect that crosses these documented boundaries or violates a security invariant in Sentrdel itself. A weakness found only in an analyzed target is a target Finding unless malicious target input can compromise Sentrdel or escape its declared analysis boundary.

Use GitHub private security reporting/advisories when available. Do not publish real credentials or unnecessary exploit payloads in public reports.
