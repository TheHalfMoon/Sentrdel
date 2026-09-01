# Implementation Plan: Business-Logic Substrate + Invariants

**Branch:** `spec/003-business-logic-invariants`  
**Date:** 2026-09-01  
**Spec:** `specs/003-business-logic-invariants/spec.md`  
**Depends on:** R1 and completed R2, canonical planning baseline `2d7b632ae745c4fda1bbd4e2ed3b7a3e119c5734`

## Summary

Build R3 as a bounded, static cross-layer authorization substrate on top of canonical R1/R2. R3 extracts supported routes, actor identity, authorization guards, request/value origins, data operations, provider/client authority and explicit security invariants; correlates them through deterministic bounded paths and the existing thin security graph; emits canonical Evidence/Coverage; and relies on the existing reconciler for Findings.

R3 does not execute target code or tooling, connect to hosted providers, consume provider-admin credentials, prove runtime exploitability, or introduce a universal CPG. Unsupported semantics remain explicit business-logic coverage gaps.

## Technical Context

**Language/Version:** Rust 1.98.0 exact trusted-core pin unless separately amended.  
**Existing substrate:** `sentrdel-schema`, `sentrdel-review`, `sentrdel-graph`, `sentrdel-store`, SentrdelBench, bounded SCIP ingestion, R2 Supabase static-posture/key authority.  
**Existing structural dependencies:** `ast-grep-core 0.45.2`, `tree-sitter 0.26.13`, `tree-sitter-javascript 0.25.0`.  
**Potential dependency:** TypeScript grammar candidate only; no adoption without explicit qualification.  
**Primary inputs:** bounded repository source/config, R1 profile/diff/view data, canonical R2 Evidence/Coverage, optional already-qualified SCIP artifacts, optional bounded project invariant declarations if implemented.  
**Network:** none in base R3.  
**Target execution:** none.  
**Persistence:** canonical Evidence/Coverage and existing graph/store boundaries; no new secret persistence.  
**Quality:** exact-head CI, cross-platform supported-path qualification, deterministic fixture replay, SentrdelBench precision/miss/coverage/provenance/authority/resource gates.

## Constitution Check

| Principle | R3 gate | Result |
|---|---|---|
| Rust Trusted Core | Extraction/correlation/invariant evaluation/Evidence orchestration remain Rust-owned | PASS |
| Evidence Before Verdict | R3 emits Evidence/Coverage; reconciler remains sole Finding authority | PASS |
| Vendor-Neutral, Local-First | Base R3 uses repository evidence and optional bounded local semantic artifacts; no provider account required | PASS |
| Honest/Monotonic Guardrails | UNKNOWN/unsupported semantics stay visible; declarations can tighten only | PASS |
| Safe Verification | No target/provider/runtime execution in R3 | PASS |
| Full-Stack Through Packs | R3 correlates route/guard/data/provider layers through bounded adapters | PASS |
| Reuse Mature Infrastructure | Reuse structural matcher, graph, SCIP seam, R2 posture and benchmark plane | PASS |
| FP/Latency Quality | Fixture/evaluation contracts precede release-gating breadth | PASS |
| Sentrdel Secures Itself | Inputs bounded; project config untrusted; dependencies require qualification | PASS |
| Spec Kit Governance | Dedicated R3 specification/design/contracts/readiness/tasks before implementation | PASS |

**Gate result:** PASS. No constitutional exception is requested.

## Architecture

```text
bounded repository source/config
          |
          +--> route adapters --------+
          +--> actor/auth adapters ----+
          +--> guard adapters ---------+
          +--> value-origin adapters --+
          +--> data-operation adapters +----> normalized cross-layer IR
          |                            |               |
R2 Evidence/Coverage -----------------+               +--> existing sentrdel-graph projection
optional qualified SCIP ------------------------------+          |
project invariants (tightening-only) ---------------------------+
                                                                   v
                                                         invariant/path evaluator
                                                                   |
                                                         Evidence + Coverage
                                                                   |
                                                           existing reconciler
                                                                   |
                                                                Finding
                                                                   |
                                                      review/init/explain + bench
```

## Trust Boundaries

1. **Repository source boundary:** source/code/comments/config are attacker-controlled data; parsing never grants instruction or execution authority.
2. **Framework boundary:** each adapter proves only its declared syntax/semantics; unsupported dynamic behavior degrades coverage.
3. **Identity boundary:** lexical name equality does not prove actor/object/tenant identity equivalence.
4. **Project invariant boundary:** repository declarations may add requirements only; they cannot suppress or widen authority.
5. **R2 boundary:** static provider posture remains static; R3 does not convert it to live/hosted truth.
6. **Graph boundary:** graph confidence/path metadata are context, not epistemic or Finding authority.
7. **SCIP boundary:** semantic artifacts are optional untrusted evidence validated through the existing bounded ingestion contract.
8. **Finding boundary:** only the reconciler creates canonical Findings.
9. **Benchmark boundary:** candidate-generation logic cannot alter the evaluator/ground truth used to qualify that candidate.
10. **Dependency boundary:** no new parser/grammar/build surface is admitted without explicit source/privileged qualification.

## Planned Components

### `crates/sentrdel-review/src/business_logic/`

Proposed internal modules, subject to implementation-task refinement:

- `mod.rs` — bounded orchestration and public internal contract.
- `model.rs` — normalized cross-layer IR and stable identities.
- `route.rs` — supported Express/Next/Edge route extraction.
- `actor.rs` — authenticated actor/tenant/role identity sources.
- `guard.rs` — typed authn/authz/tenant/property guard observations.
- `value.rs` — bounded request/value-origin derivation.
- `data.rs` — supported Supabase JavaScript data-operation/filter/field extraction.
- `link.rs` — local and optional SCIP semantic links.
- `path.rs` — deterministic bounded cross-layer path correlation.
- `invariant.rs` — built-in and optional project-declared invariant evaluation.
- `coverage.rs` — business-logic/framework/linking coverage aggregation.
- `integration.rs` — Evidence/Coverage mapping into existing review substrate.

Module names are planning targets and do not authorize public API breakage.

### Existing contracts reused

- canonical Evidence/Coverage and `EvidenceAuthority` boundaries;
- existing reconciler-only Finding creation;
- `SecurityPackManifest` and `BUSINESS_LOGIC` coverage semantics;
- `RepoFileView`/normalized path/file bounds;
- structural matching registry;
- thin `sentrdel-graph` stable identity/provenance/bounded traversal;
- bounded SCIP ingestion;
- R2 Supabase static-posture/key authority observations;
- SentrdelBench evaluation plane;
- redaction and persistence contracts.

Public schema expansion is not assumed. If implementation proves a public contract gap, the change must be minimal, versioned/compatible where possible, separately tested, and cannot widen authority.

## Cross-Layer IR Strategy

R3 will represent only security-relevant normalized facts needed for the frozen invariant families.

Core concepts:

```text
RouteObservation
ActorContext
GuardObservation
ValueOrigin
DataOperation
ProviderClientAuthority
CrossLayerPath
InvariantDefinition
InvariantEvaluation
BusinessLogicCoverage
```

Every record carries stable repository-relative identity and provenance. Dynamic or unresolved semantics use explicit UNKNOWN/unsupported states rather than guessed relationships.

## Initial Adapter Strategy

### Routes

Initial intended supported families:

- Express method/path route registration and bounded callback/middleware chains;
- Next.js App Router `route.js` / `route.ts` HTTP-method handlers;
- Next.js Pages API route handler conventions;
- bounded Supabase Edge Function handler patterns.

Dynamic route generation, arbitrary framework metaprogramming, custom routers, unresolved callback factories, and unsupported middleware composition remain coverage gaps until separately added.

### Actor and guards

Supported observations may include:

- verified/authenticated user identity sources exposed by qualified adapters;
- route parameters and request-controlled values;
- supported role/tenant claims;
- explicit equality/membership/allowlist guards in the frozen subset;
- explicit property allowlisting/filtering;
- project invariant requirements.

R3 will not equate variables merely because names are similar.

### Data operations

Initial Supabase JavaScript subset targets:

- relation/resource selection;
- `select`, `insert`, `update`, `upsert`, `delete`, and bounded `rpc` observations;
- supported equality/in/match-like filters required by tenant/object invariants;
- explicit selected/mutated field sets when statically visible;
- client authority correlation from supported R2/local evidence.

Operation extraction is observation, not proof that the query executes in production.

## Graph Strategy

R3 projects only validated cross-layer observations required for bounded context/path queries into the existing graph. Stable route/data/invariant identities map to existing node vocabulary where semantically valid; relation direction remains explicit.

Path search has hard caps for:

- nodes;
- edges;
- traversal depth;
- candidate paths per route/operation;
- total correlated observations;
- diagnostics.

Cap exhaustion degrades coverage and cannot produce a clean invariant result.

## Invariant Families — Initial Release Candidates

Candidate families, promoted only after fixture and benchmark qualification:

1. **Tenant/object binding:** request-selected tenant/user-owned resource access lacks a supported binding to the authenticated actor/tenant along the correlated operation path.
2. **Function/role authorization:** privileged route/action or elevated operation lacks a supported required-role/privilege guard.
3. **Protected-property mutation:** request-controlled broad mutation can write known protected fields without a supported allowlist/property guard.
4. **Elevated provider authority:** request-driven use of an elevated Supabase/service-role client lacks supported application authorization before the privileged data operation.
5. **Project-declared requirements:** bounded tightening-only invariant requirements evaluated against the same cross-layer IR.

No family is release-gating merely because it can detect a fixture.

## Project Invariant Strategy

A potential `.sentrdel/invariants.toml` contract may be implemented after its parser/task is authorized. It is declarative data only.

Permitted requirement families may include:

- tenant binding for a resource/path;
- required role for a route/action;
- protected properties for a resource/mutation;
- allowed server contexts for elevated client authority.

Forbidden semantics include:

- suppressions/waivers/ignore rules;
- severity reductions;
- accepted-risk declarations;
- policy/kernel/reconciler overrides;
- process/network/credential grants;
- executable plugins/scripts/templates;
- FACT/VERIFIED declarations.

Invalid project invariant configuration cannot disable built-in analysis.

## Coverage Model

R3 maps to canonical business-logic coverage and preserves diagnostics needed to distinguish at least:

- route/framework extraction;
- actor/auth identity extraction;
- guard extraction;
- data-operation extraction;
- local/inter-file link coverage;
- R2 provider-correlation coverage;
- invariant evaluation coverage;
- aggregate `CROSS_LAYER_BUSINESS_LOGIC`/`BUSINESS_LOGIC` state.

A clean Finding set cannot erase partial/unsupported dimensions.

## Implementation Phases

### Phase A — Planning gate, contracts and ground truth

Canonicalize the complete planning slice first. Then freeze pack/coverage metadata, cross-layer IR, invariant contract and synthetic fixture/benchmark ground truth before implementation breadth.

### Phase B — Structural extraction substrate

Qualify any required TypeScript grammar before use; extend only the bounded structural language/adapters needed for frozen route/actor/guard/value/data observations; add malformed/dynamic/adversarial tests before rule interpretation.

### Phase C — Graph/link/correlation substrate

Map validated observations to the existing graph, add bounded local/SCIP linking, correlate route → actor/guard → data/client paths, integrate R2 static posture and preserve explicit coverage.

### Phase D — Invariant evaluation

Implement tenant/object, function/role, protected-property and elevated-client invariant families, then optional tightening-only project invariant declarations.

### Phase E — Product integration

Integrate Evidence/Coverage into review/init/explain without changing reconciler authority; expose bounded path/invariant provenance and coverage.

### Phase F — Evaluation and closeout

Run R3 SentrdelBench release corpus, clean-case FP and known-miss gates, deterministic replay, authority checks, latency/resource qualification, dependency/source governance, no-network/no-target-execution canaries, cross-platform qualification, consistency analysis, implementation closeout, protected-main governance and canonical closeout.

## Dependency Policy

No new third-party crate is authorized by this plan. A dependency candidate must receive before adoption:

- exact package/version/checksum and upstream ref;
- license/notices;
- feature and transitive closure justification;
- `build.rs`, proc-macro, native/FFI, download/network/credential assessment;
- source qualification and privileged-dependency declaration where applicable;
- lockfile review and Self Security qualification.

If TypeScript grammar qualification cannot satisfy these gates, the implementation must retain honest narrower coverage rather than bypass dependency governance.

## Rollback / Failure Semantics

- Parser/adapter failure -> affected coverage degrades; no clean invariant result.
- Unresolved identity/link -> UNKNOWN/partial path; never infer equivalence.
- Graph/path cap exhaustion -> partial/failed business-logic coverage.
- Optional SCIP missing/unqualified -> explicit semantic-link gap.
- Malformed project invariant declaration -> declaration rejected/diagnosed; built-in analysis continues.
- R2 evidence absent/partial -> provider correlation remains partial; no live-state inference.
- Dependency qualification failure -> dependency not adopted; supported scope remains narrower.
- Benchmark regression/authority violation -> candidate not promoted.

## Complexity / Exceptions

No constitutional exception is requested. The deliberate complexity is a bounded cross-layer IR plus typed adapters and invariant evaluator. This is justified because business-logic authorization cannot be represented safely as isolated lexical rules, while a universal compiler/CPG/runtime verifier would exceed R3 authority and complexity.
