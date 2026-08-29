# Sentrdel R1 Threat Model

**Task:** T083  
**Scope:** v0.1 Evidence + Guard Foundation  
**Authority:** descriptive security documentation subordinate to the Constitution and active Spec Kit contracts

## 1. Security objective

Sentrdel is a local-first security evidence and control plane for software development. Its security objective in R1 is to inspect attacker-controlled development inputs, produce provenance-bearing evidence, and enforce only explicitly owned guard boundaries without allowing those inputs to become execution, policy, credential, epistemic, or release authority.

This document describes the implemented R1 trust boundaries and non-claims. It does not create new product authority.

## 2. Trusted computing base

The R1 trusted computing base includes:

- the first-party Rust workspace under `crates/`;
- canonical schema validation, hashing, Evidence/Finding/Coverage/ASEL contracts;
- Rust-owned policy kernel invariants and monotonic policy composition;
- bounded repository/Git readers and native producer framework;
- the reconciler as the only canonical Finding creation path;
- bounded external-engine process orchestration and adapters;
- bounded stdio MCP gateway framing, policy, approval, forwarding, and ASEL path;
- trusted bootstrap/configuration code that constructs non-deserializable authority capabilities;
- release/self-security governance for Sentrdel's own trusted workspace.

Third-party dependencies are not assumed safe merely because they are inside the build graph. They remain governed supply-chain inputs and are admitted through dependency/source qualification policy.

## 3. Attacker-controlled or untrusted inputs

Unless an explicit higher-authority contract says otherwise, treat these as attacker-controlled data:

- target repository files, file names, symlinks, Git metadata/config/history, diffs, and commit messages;
- repository documentation, comments, generated files, instructions, policy/configuration text, and hidden tool configuration;
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
```

Authority capabilities are constructed only by trusted Sentrdel paths. Untrusted serialized content cannot mint or deserialize filesystem, process, network, credential, policy, Evidence, reconciler, workflow, verification, benchmark, or release authority.

Instruction-shaped text remains data even when it is imperative, repeated, signed by an untrusted identity, produced by a model, returned by an MCP tool, stored in a repository, or retrieved from future memory.

## 5. Primary trust boundaries

### 5.1 Repository -> review

**Threats:** path traversal, symlinks, confusables, oversized files, hostile Git configuration, binary input, hidden instructions, target-controlled build/package-manager helpers, malicious lock/config files.

**Controls:** bounded path normalization/file reads, read-only Git access, no target hooks/filters/textconv/package-manager/Cargo execution, explicit size bounds, deterministic producer ownership, redaction-before-persist, explicit coverage gaps.

**Non-claim:** R1 does not provide compiler-complete semantic analysis for all languages.

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

**Non-claim:** advisory/denylist PASS is not proof that every dependency is behaviorally safe.

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
- alter evaluator/holdout/release authority for a candidate it is helping generate.

Future memory/feedback/learning features remain deferred and inherit this authority ceiling.

## 8. Secret handling

Discovered secret material is handled under a minimize-before-persist rule:

- secret plaintext must not enter durable Evidence/store/export/log/snapshot fixtures;
- stable unkeyed hashes derived only from the secret value are also prohibited because they create reusable cross-context identifiers;
- changed-secret Evidence retains only allowed rule/type/location/redacted display and sanitized non-secret fingerprints;
- engine/MCP child environments deny ambient credentials by default.

R1 does not claim to prevent a compromised operating system or already-compromised Sentrdel process from observing in-memory values.

## 9. Enforcement fidelity

Sentrdel reports enforcement fidelity rather than flattening every integration into a single "protected" claim.

- proxied bounded stdio MCP actions can be `ENFORCED` at the Sentrdel gateway seam;
- installed local Git hooks are bypassable and therefore `PARTIAL`/advisory;
- unsupported remote MCP/provider/runtime surfaces are explicit coverage gaps, not implicit security.

No documentation or UI should present a coverage gap as a clean verdict.

## 10. Network boundary

Local-first operation is the default. Network use is explicit and bounded:

- ordinary deterministic review must not depend on a model or network service;
- optional OSV/model HTTP paths obey explicit configuration and `--no-network` behavior;
- R1 MCP forwarding is stdio-only;
- self-security CI may access pinned release/advisory sources for Sentrdel's trusted workspace and does not analyze arbitrary target repositories through Cargo tooling.

## 11. Denial of service and resource exhaustion

R1 applies bounded reads, frame sizes, metadata/argument/result caps, output caps, process timeouts, and policy depth/byte limits at exposed seams. Resource-bound failure must be explicit and must not become silent success.

R1 does not claim protection against every host-level resource exhaustion scenario or a hostile administrator controlling the machine.

## 12. Integrity and provenance

Cryptographic identity is scoped to what it actually proves:

- content IDs bind canonical bytes to a domain-separated digest;
- Evidence producer identity is runtime-owned and validated;
- ASEL links recorded events but requires an external trusted checkpoint/signature for stronger replacement/truncation detection;
- a signature, if introduced later, proves only the statement/key relationship it actually verifies and does not automatically grant instruction authority.

Unknown/failed provenance or integrity cannot be upgraded because contradictory evidence is absent.

## 13. Explicit R1 non-goals

R1 does not implement or claim:

- autonomous exploitation or production probing;
- remote/Streamable HTTP MCP enforcement;
- OS sandboxing/eBPF runtime enforcement;
- sandboxed exploit-condition verification;
- universal compiler/CPG semantic certainty;
- automatic fix application;
- general-purpose Security Memory or memory-driven suppression;
- autonomous security research/learning or candidate promotion;
- signed community-pack distribution;
- IDE/forge enforcement integrations;
- deep Supabase/Firebase/payment/cloud posture beyond explicitly implemented detection scope.

## 14. Security regression expectations

Changes affecting a trust boundary must preserve tests that prove, as applicable:

- no target build/install/package-manager execution during analysis;
- no shell-string target/external command execution;
- no ambient engine/MCP credential inheritance;
- malformed/oversized input fails boundedly;
- kernel DENY remains absorbing;
- model/context cannot gain FACT/VERIFIED/policy/reconciler authority;
- secret plaintext and stable secret-only digests are absent from persistence/export/log fixtures;
- missing/failed producers remain visible in coverage;
- canonical Findings remain reconciler-owned;
- protected-main and self-security gates are not weakened to make a change pass.

## 15. Reporting and triage

A Sentrdel vulnerability is a defect that crosses these documented boundaries or violates a security invariant in Sentrdel itself. A weakness found only in an analyzed target is a target Finding unless malicious target input can compromise Sentrdel or escape its declared analysis boundary.

Use GitHub private security reporting/advisories when available. Do not publish real credentials or unnecessary exploit payloads in public reports.
