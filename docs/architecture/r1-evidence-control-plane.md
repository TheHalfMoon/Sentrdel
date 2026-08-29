# R1 Evidence and Control-Plane Architecture

**Task:** T084  
**Scope:** Sentrdel v0.1 / R1  
**Status:** IMPLEMENTED_ARCHITECTURE_DOCUMENTATION

This document describes the architecture that is implemented by the R1 Spec Kit slice. It is descriptive, not an authority expansion. The constitution, active specification, contracts, and Rust schemas remain binding where wording differs.

## 1. Architecture objective

Sentrdel R1 is a local-first security evidence and control plane. Its trusted judgment path is intentionally narrower than the set of data it can read:

```text
untrusted repository / engines / MCP / model context
                    |
                    v
        bounded producer boundaries
                    |
                    v
               Evidence
                    |
                    v
              Reconciler
                    |
                    v
               Finding
                    |
          +---------+---------+
          |                   |
       review               policy/guard
```

Only the reconciler creates canonical Findings from validated Evidence. Repository text, engine output, MCP content, model output, issue text, logs, and other context are data unless an explicit trusted contract grants a narrower authority.

## 2. Trusted-core ownership

The security-critical control plane is Rust-owned. R1 separates responsibility across the workspace:

- `sentrdel-schema`: canonical Evidence, Finding, Coverage, ASEL, policy, engine, pack, profile, graph, and reasoner contracts.
- `sentrdel-store`: immutable Evidence persistence, Finding projections, coverage/profile storage, redaction-before-persist, and ASEL chain state.
- `sentrdel-graph`: provenance-aware graph projection and bounded reachability context.
- `sentrdel-engine`: the only external evidence-engine process boundary; argv-only execution and scrubbed/allowlisted child environment.
- `sentrdel-policy`: Rust kernel invariants plus monotonic bounded policy composition.
- `sentrdel-guard`: bounded stdio MCP gateway, approvals, ASEL emission, and declared enforcement fidelity.
- `sentrdel-review`: non-executing repository/diff analysis, deterministic producers, reconciliation, coverage, explanation, and optional bounded reasoner use.
- `sentrdel-cli`: stable human/JSON entry points and exit behavior.

External components can produce input but do not inherit canonical judgment authority from being integrated.

## 3. Evidence model

Evidence is immutable, producer-attributed security knowledge. R1 keeps observation, interpretation, provenance, location, confidence, and epistemic class explicit instead of collapsing producer output directly into a verdict.

The implemented epistemic classes include:

- `FACT`: a directly observable bounded property only;
- `INFERENCE`: a deterministic or reasoned interpretation supported by evidence;
- `HYPOTHESIS`: a lower-authority proposed interpretation;
- `OBSERVATION`: runtime-observation authority where explicitly permitted;
- `VERIFIED`: reserved for a stronger execution-verification authority that R1 does not grant to ordinary producers;
- `CONTRADICTION`: evidence that conflicts with another security claim or observation.

LLM reasoners are structurally restricted to `INFERENCE` and `HYPOTHESIS`. They cannot mint FACT/VERIFIED authority, suppress deterministic evidence, mutate canonical Findings, or weaken policy.

### Secret persistence boundary

Changed-secret detection is permitted, but discovered secret plaintext and stable unkeyed value-only secret hashes are removed before persistence. Persistent records may retain rule/type, location, redacted display, and sanitized non-secret fingerprints.

### Coverage is separate from evidence

A missing, unavailable, failed, detection-only, or not-implemented producer remains visible through Coverage records. Absence of a producer signal is not evidence that a project is secure.

## 4. Finding reconciliation

Producer output does not become a canonical Finding directly. The reconciler owns correlation and canonical Finding creation.

R1 reconciliation preserves:

- supporting Evidence identities and producer provenance;
- contradictions rather than silently discarding them;
- deterministic correlation/fingerprinting;
- explicit epistemic/proof state separate from workflow state;
- bounded graph context without inventing unsupported causality.

This separation prevents a scanner, model, repository-controlled rule, or external tool from self-assigning canonical severity or proof authority.

## 5. ASEL architecture

The Agent Security Event Log (ASEL) is the integrity-linked record of controlled agent/tool activity and decisions. R1 records relevant discovery, invocation, approval, denial, tool-result, and guard events with normalized targets, digests, sequence, previous-hash linkage, policy decision, provenance, and session identity.

```text
ASEL event N-1 --hash link--> ASEL event N --hash link--> ASEL event N+1
                                                |
                                                v
                                      computed session head
```

### Trusted-head limitation

The local ASEL hash chain proves internal consistency relative to the bytes and head being checked. By itself, it does **not** independently prove that history was never truncated, replaced, or rewritten before inspection.

R1 therefore distinguishes:

1. local chain consistency; and
2. validation against an optional externally trusted expected head/checkpoint.

Product text must not call an unauthenticated local chain "tamper-proof". Signing, remote attestation, or independently anchored checkpoints are later-scope strengthening mechanisms.

## 6. MCP control boundary

R1 enforcement supports bounded **stdio MCP only**.

The gateway owns:

- bounded framing and buffer limits;
- explicit protocol-version negotiation/allowlisting;
- bounded tool metadata, arguments, and results;
- policy evaluation before controlled forwarding;
- scoped approvals;
- fail-closed handling of malformed/unsupported/undecidable input;
- explicit enforcement-fidelity reporting;
- deny-by-default child environment inheritance for Sentrdel-launched MCP servers.

MCP descriptions, schemas, arguments, and results are untrusted data. Instruction-shaped content can become Evidence/candidate telemetry but does not gain policy or credential authority from its wording.

### Credential inheritance boundary

Sentrdel-launched MCP children do not inherit the ambient developer environment by default. Cloud, model, forge, signing, SSH, database, and provider-administration credentials require an explicit capability and user-authorized policy path.

This environment boundary is not a general process sandbox. R1 does not claim kernel isolation, remote-MCP security, or production-system containment.

### Remote MCP non-claim

Streamable HTTP and other remote MCP transports are not implemented in R1. The presence of protocol/library support upstream does not authorize those transports in Sentrdel.

## 7. External-engine boundary

External scanners are optional Evidence producers behind `sentrdel-engine`. R1 does not run target repository build/install/package-manager commands merely to inspect a repository.

Engine execution uses trusted executable resolution, explicit argv, bounded cwd/time/output, strict result parsing, normalized repo-relative locations, and a scrubbed/allowlisted child environment. Engine failures become Coverage state rather than a clean verdict.

The target repository remains data: its hooks, Git filters/textconv/external diff helpers, credential helpers, package managers, Cargo configuration, submodule fetches, and network remotes are not executed during ordinary analysis.

## 8. Evaluation plane

SentrdelBench is part of the security architecture. The evaluator measures explicit dimensions including precision, known-ground-truth misses/recall, clean-PR false positives, coverage completeness, provenance completeness, deterministic replay, latency/resource behavior, guard false blocks, and MCP/authority-boundary behavior.

The corpus is separated into public regression, development-evaluation, and protected-holdout classes.

### Evaluation-plane limits

R1 does not claim that the benchmark proves universal security quality. The benchmark demonstrates behavior on its declared corpus and machine metadata. Unsupported ecosystems and unmeasured threat classes remain coverage limitations.

Candidate-generation logic must not receive protected expected outputs or mutate the evaluator/metrics that judge its current candidate.

## 9. Future learning authority

The binding future-learning/context contract is `specs/001-v0-1-evidence-guard-foundation/contracts/context-learning-authority.md`.

R1 freezes the authority boundary only. It does **not** implement general Security Memory or autonomous Research/Learning.

Future research automation may propose candidate rules, packs, fixtures, fuzz cases, graph heuristics, or remediation text, but candidate artifacts cannot:

- create canonical Findings;
- mint FACT or VERIFIED authority;
- weaken Rust kernel policy;
- alter verification semantics;
- modify the evaluator or protected-holdout labels judging the current candidate;
- self-promote into trusted production authority.

Promotion remains an independently governed step outside candidate generation.

## 10. Network and model boundary

The base installation remains useful without cloud services, external scanners, or models. Model reasoning is optional. Local HTTP/Ollama-compatible and explicitly configured remote HTTP adapters are bounded behind the reasoner contract.

`--no-network` must preserve deterministic review behavior. Remote raw-source upload is not implicit and whole-repository upload is prohibited by default.

## 11. Enforcement fidelity

R1 distinguishes the strength of a control:

- `ENFORCED`: Sentrdel controls the seam and can block the action;
- `PARTIAL`: useful but bypassable coverage such as installed git-hook behavior;
- `ADVISORY`: observation/recommendation without a controlled blocking seam.

Sentrdel does not claim universal interception across coding agents or development environments where no enforceable vendor-neutral seam exists.

## 12. Dependency and release boundary

Sentrdel's own dependency/build graph is part of the trusted computing base. Rust 1.98.0, the committed lockfile, dependency/source qualification, privileged dependency declarations, `cargo-audit`, `cargo-deny`, release malicious-package policy, and cross-platform CI are release gates for the trusted workspace.

These Cargo-based self-security tools are not run against arbitrary target repositories as an analysis primitive.

## 13. R1 non-claims

R1 intentionally does not claim or implement:

- remote/Streamable HTTP MCP enforcement;
- autonomous exploitation or production pentesting;
- a general verification sandbox or ordinary `VERIFIED` producer;
- universal CPG/compiler semantics;
- deep Supabase/Firebase/cloud/payment posture analysis;
- general-purpose Security Memory;
- autonomous research-learning promotion;
- universal agent interception;
- independent non-repudiation from the local ASEL hash chain;
- proof of security from a green CI run or absent producer signal.

These boundaries are part of the architecture, not missing documentation to be interpreted as implicit authority.
