# Graphify Source Qualification — GQ-001

**Status:** `QUALIFIED_FOR_SELECTIVE_RUST_PORT`  
**Qualification date:** 2026-08-24  
**Sentrdel base:** `c60ed8610643406dea0c3298eb1eb83520f0d7be`  
**Upstream:** `Graphify-Labs/graphify`  
**Upstream default branch:** `v8`  
**Exact upstream commit:** `b2cd36267456c166788c95be6e68574064a92a42`  
**Exact upstream tree:** `be8636735370ed82708bb53eba33170e85acc369`  
**Observed package version:** `0.9.48`

## Decision

Graphify is qualified as a **design/source donor for a bounded native Rust port** into Sentrdel's existing `sentrdel-graph` boundary. It is **not** qualified as a runtime dependency, vendored Python subsystem, second canonical graph store, MCP server, LLM subsystem, or extractor runtime.

No Graphify source is copied into Sentrdel by this qualification change. Any derived implementation lands in a later implementation PR with explicit attribution, behavior tests, provenance, and Sentrdel-specific authority constraints.

The preferred adoption units are:

1. graph snapshot diff semantics from `graphify/analyze.py::graph_diff`;
2. reverse impact/blast-radius traversal from `graphify/affected.py::affected_nodes`;
3. bounded seed-resolution lessons from `graphify/affected.py::resolve_seed`, but with stricter fail-closed ambiguity handling in Sentrdel;
4. extraction/edge validation vocabulary from `graphify/validate.py`, translated into Sentrdel's stronger evidence/authority model rather than copied as authority.

Import-cycle analysis and surprise/bridge scoring are useful follow-on candidates, but they are not part of the first port gate.

## Licensing and provenance

The current package metadata declares `Apache-2.0`. The repository root contains the Apache License 2.0, `LICENSE-MIT`, and `NOTICE`. `NOTICE` states that current Graphify is licensed under Apache-2.0 and that portions contributed before relicensing remain available under MIT terms.

For the files selected below, this qualification does **not** assume that the older MIT grant applies file-by-file. Unless exact file history later proves otherwise, a derived Sentrdel port will conservatively use the current **Apache-2.0 grant** and preserve required notice/attribution.

Project-governance reuse authority is also recorded as `FOUNDER_ATTESTATION_2026-08-24`. No separate source-specific private permission reference is stored in this repository; none is invented here. The public Apache-2.0 license is the operative reusable-source license basis for this qualification.

Required downstream provenance for a derived implementation:

- identify `Graphify-Labs/graphify` and exact commit `b2cd36267456c166788c95be6e68574064a92a42`;
- identify the exact donor file(s) and blob SHA(s) used as derivation inputs;
- retain Apache-2.0 license compliance and attribution;
- preserve applicable Graphify NOTICE attribution in Sentrdel third-party notices;
- document semantic changes made by the Rust port;
- do not represent the port as upstream Graphify code or as upstream-supported behavior.

## Exact qualified source set

| Upstream artifact | Blob SHA | Qualified use | Decision |
|---|---|---|---|
| `graphify/analyze.py` | `0707e2be78eceef3a7f6ae7ee6d3659659ffdf55` | graph diff semantics; later import-cycle/bridge ideas | `SELECTIVE_PORT` |
| `graphify/affected.py` | `0184a8f88fa458de76107b63d08b77b0c739abbc` | reverse dependency traversal, relation allowlist, call-site location propagation | `SELECTIVE_PORT` |
| `graphify/validate.py` | `bab3ddc7c89e4a122e62e20f37d8c7c2f054a9bf` | graph record validation concepts and confidence vocabulary | `CONCEPT_PORT_ONLY` |
| `tests/test_analyze.py` | `7bff432cf7212da6f329588ce4d81a7cdca81d34` | behavioral test cases/specification reference | `TEST_DESIGN_REFERENCE` |
| `ARCHITECTURE.md` | `080f46f2235bfa3dee34a2488fdcc5b8caaefe54` | architecture and data-contract reference | `DOCUMENTATION_REFERENCE` |
| `pyproject.toml` | `15ea9dd57c500f219ec916ad0b99b9e07fa0a6ea` | package/dependency/build-authority qualification | `METADATA_REFERENCE` |
| `LICENSE` | `d645695673349e3947e8e5ae42332d0ac3164cd7` | Apache-2.0 terms | `LICENSE_RECORD` |
| `LICENSE-MIT` | `b1d9746fb5c6c39fd502e2ebe432a12ad9a097f3` | retained historical MIT terms | `LICENSE_RECORD` |
| `NOTICE` | `791bf88bb1e50572902dbbe9228153ea29846adf` | attribution/relicensing notice | `NOTICE_RECORD` |

Anything outside this table remains unqualified for source reuse by GQ-001.

## Architecture findings

Graphify documents a staged Python pipeline:

`detect -> extract -> build -> cluster -> analysis -> report -> export`

Stages exchange Python dictionaries and NetworkX graphs. The graph extraction schema uses nodes with source locations and edges carrying `relation` plus one of three confidence labels:

- `EXTRACTED`
- `INFERRED`
- `AMBIGUOUS`

This is valuable input vocabulary, but **Graphify confidence is not Sentrdel epistemic authority**. A donor `EXTRACTED` edge is not automatically a Sentrdel `FACT`, and no Graphify edge can become `VERIFIED` merely because upstream labels or ranking say so. Sentrdel's existing EvidenceAuthority and R1 epistemic rules remain authoritative.

### `graph_diff` qualification

The upstream function provides a compact and useful baseline:

- added/removed nodes by node ID;
- added/removed edges by endpoints plus relation;
- directed and undirected edge-key handling;
- human-readable change summary.

However, Sentrdel MUST NOT port it verbatim as the final security graph delta contract. The upstream edge identity intentionally excludes confidence and most edge attributes, and node changes are ID-set based. Therefore an edge whose confidence/provenance changes without endpoint/relation changes is not itself represented as a changed edge, and node attribute changes are not modeled.

The Sentrdel port must strengthen the design to distinguish at minimum:

- added/removed node;
- materially changed node security attributes;
- added/removed edge;
- relation change;
- confidence/evidence-class change;
- provenance/producer change;
- trust-boundary or authority-bearing metadata change.

This is the key reason to **derive and harden** rather than vendor the Python function.

### `affected_nodes` / blast-radius qualification

`affected_nodes` is a strong donor seam for Sentrdel because it performs a bounded reverse traversal from a changed seed through an explicit relation allowlist, records traversal depth, and propagates the matched edge's source location so results point at the dependency/call site rather than only the target definition.

Useful upstream relations include calls, indirect calls, references, imports/imports_from, dynamic imports, re-exports, inheritance/implements/uses, and related structural relations.

Sentrdel should preserve the core principles but change the trust semantics:

- relation allowlists are typed policy, not arbitrary strings from an untrusted producer;
- direction must be explicit in Sentrdel's canonical graph record;
- traversal depth and visited-set behavior must be deterministic;
- unresolved/ambiguous seed selection fails explicitly rather than silently choosing a fuzzy match;
- each returned impact path retains evidence/provenance IDs, not only relation text;
- impact traversal does not by itself prove exploitability.

### Seed resolution

Graphify's resolver is user-friendly: exact node ID, exact label, callable-normalized label, source-file matching, file-node preference, and finally a unique substring/contains match.

For an AppSec control plane this final heuristic is too permissive for authority-bearing decisions. Sentrdel may reuse the normalization lessons, but canonical analysis should prefer stable node IDs and exact repo-relative paths. Fuzzy/substring resolution may be exposed only as an advisory UX feature and must return ambiguity rather than minting a canonical seed.

### Confidence and validation vocabulary

`validate.py` validates required node/edge keys and constrains confidence to `EXTRACTED`, `INFERRED`, or `AMBIGUOUS`. Sentrdel may map these into **adapter-local confidence metadata**, but the mapping into canonical Evidence must still be performed through a qualified adapter authority:

- `EXTRACTED` -> candidate direct observation only if the adapter can bind it to deterministic source evidence;
- `INFERRED` -> inference, never FACT solely because Graphify produced it;
- `AMBIGUOUS` -> unresolved candidate/low-confidence inference, not a confirmed finding.

## Dependency and execution authority

A whole-package adoption is rejected for the trusted core.

The package is Python `>=3.10` with `setuptools.build_meta` and a broad default dependency set including NetworkX, NumPy, RapidFuzz, tree-sitter, and many language-specific tree-sitter grammar packages. Optional extras add MCP/Starlette, Neo4j/FalkorDB/Postgres, PDF/Office/video tooling, LLM provider SDKs, cloud SDKs, and other runtime surfaces.

Consequences of whole-package integration would include:

- a second runtime language in the trusted graph path;
- a large dependency and native-wheel/grammar supply chain;
- optional network/provider/MCP surfaces that Sentrdel R1 does not need;
- duplicated canonical graph semantics beside `sentrdel-graph`;
- additional installation/build authority and platform variance.

GQ-001 therefore authorizes **no Graphify installation, dependency addition, plugin execution, MCP startup, network access, provider access, or donor test execution inside Sentrdel**.

The qualified port target remains dependency-minimal Rust under `crates/sentrdel-graph`.

## Security qualification

Graphify states that analysis is local by default, source code is parsed rather than executed, and networking is restricted to opt-in paths such as ingest. It documents SSRF/path/XSS/prompt-injection mitigations. These are useful design references, not inherited guarantees.

One maintenance-documentation inconsistency was observed: `SECURITY.md` says supported version `0.3.x` while the qualified package metadata is `0.9.48`. This does not disqualify the bounded algorithms selected here, but it means Sentrdel must not rely on Graphify's version-support table as a current security-support guarantee.

No donor runtime is admitted, so Graphify's optional HTTP/MCP/provider/network surfaces are outside the Sentrdel TCB for this qualification.

## Maintenance qualification

The exact upstream head is dated 2026-08-20 and recent commit history shows active fixes and tests around graph invariants, extraction resilience, exports, and dedup behavior. Maintenance activity is therefore assessed as **ACTIVE** at the qualified ref.

Because the project is fast-moving, Sentrdel must pin this exact commit for derivation. Later upstream changes are not silently inherited; adopting a later donor revision requires a new qualification delta.

## Sentrdel design changes required by the port

The first implementation PR should create native Rust contracts rather than mirror NetworkX:

- stable `GraphNodeId` / edge identity;
- typed relation enum with an explicit unknown/advisory representation if needed;
- evidence/provenance references on nodes and edges;
- confidence/epistemic separation;
- deterministic graph delta output;
- bounded reverse-impact traversal with path evidence;
- explicit partial/unknown coverage rather than "no affected nodes" implying safety.

The current `sentrdel-graph` invariant `UNIVERSAL_CPG = false` remains unchanged. The port must stay a thin evidence/property graph boundary and must not turn Sentrdel into a Graphify or universal-CPG fork.

## Minimum tests required before implementation can merge

A later port PR must include tests proving at least:

1. unchanged snapshots produce an empty delta;
2. added/removed nodes and edges are deterministic regardless of insertion order;
3. edge relation/confidence/provenance changes are surfaced rather than hidden;
4. directed edge orientation is preserved;
5. reverse impact traversal respects allowed relation types and depth;
6. member/call-site traversal retains the actual edge location/provenance;
7. cycles terminate via a visited set;
8. ambiguous seed resolution fails closed for canonical analysis;
9. absence/partial coverage cannot be rendered as a clean security result;
10. donor confidence cannot create `VERIFIED` or otherwise bypass Sentrdel EvidenceAuthority.

Property tests should cover insertion order, duplicate edges, cyclic graphs, depth bounds, and stable serialization/digests once the graph wire contract is introduced.

## Explicitly rejected in GQ-001

- vendoring the Graphify Python package;
- adding Graphify/NetworkX as a Sentrdel runtime dependency;
- importing its MCP server or HTTP transport;
- importing ingest/network fetch code;
- importing LLM/provider code;
- importing database backends;
- importing the full language extractor matrix;
- treating Graphify confidence labels as Sentrdel authority;
- adopting fuzzy seed resolution for canonical decisions;
- creating a second canonical graph store/runtime.

## Qualification result

`Graphify-Labs/graphify@b2cd36267456c166788c95be6e68574064a92a42` is **QUALIFIED_FOR_SELECTIVE_RUST_PORT** under the constraints above.

The next authorized engineering step is a separate implementation PR for the first bounded graph-delta + impact-traversal substrate. That PR may derive behavior from only the exact qualified files listed in GQ-001, must carry provenance/notice updates, and must remain inside Sentrdel's existing evidence and authority boundaries.
