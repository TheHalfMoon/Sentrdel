# Petgraph Dependency Qualification — PGQ-001

Status: **QUALIFIED_FOR_T033_BOUNDED_IN_MEMORY_GRAPH_PROJECTION**

Qualified on: 2026-08-28

## Decision

Sentrdel may use `petgraph =0.8.3` inside `sentrdel-graph` for ephemeral directed adjacency, incoming-edge traversal, and graph-index mechanics required by T033.

The dependency does **not** own canonical graph identity, provenance, confidence, semantic relation validation, persistence, findings, policy, or security verdicts. Canonical Sentrdel graph records are validated before projection, and observable results are returned in Sentrdel stable IDs.

## Exact source and package identity

- Repository: `petgraph/petgraph`
- Tag: `petgraph@v0.8.3`
- Annotated tag object: `64ee942b617260177f0423ceb9e79d9b415627cc`
- Exact commit: `162903562ce5b00cdba390a0d9c1bb80f1c75bf5`
- Crate: `petgraph =0.8.3`
- crates.io checksum: `8701b58ea97060d5e5b155d383a69952a60943f0e6dfe30b04c287beb0b27455`
- License expression: `MIT OR Apache-2.0`
- Upstream MSRV: Rust `1.64`

The Sentrdel manifest pins the exact crate version, disables default features, and enables only `std`:

```toml
petgraph = { version = "=0.8.3", default-features = false, features = ["std"] }
```

This excludes Petgraph's default `graphmap`, `stable_graph`, and `matrix_graph` features and does not enable optional `rayon`, `serde-1`, `quickcheck`, or DOT parser support.

## Qualified dependency closure

The committed T033 lockfile admits the following new normal-runtime closure:

| Package | Version | Checksum | Why admitted |
|---|---:|---|---|
| `petgraph` | `0.8.3` | `8701b58ea97060d5e5b155d383a69952a60943f0e6dfe30b04c287beb0b27455` | directed graph container and traversal mechanics |
| `fixedbitset` | `0.5.7` | `1d674e81391d1e1ab681a28d99df07927c6d4aa5b027d7da16ba32d1d21ecd99` | unconditional Petgraph dependency |
| `hashbrown` | `0.15.5` | `9229cfe53dfd69f0609a49f65461bd93001ea1ef889cd5529dd176593f5338a1` | Petgraph hash table dependency with only `default-hasher` and `inline-more` requested upstream |
| `foldhash` | `0.1.5` | `d9c4f5dac5e15c24eb999c26181a6ca40b39fe946cbe4c263c7209467bc83af2` | `hashbrown 0.15.5` default-hasher implementation |

The existing `indexmap 2.14.0` package is reused. Its existing `hashbrown 0.17.1` dependency is version-qualified in `Cargo.lock` only because T033 adds a second `hashbrown` version.

No new native library, build script, procedural macro, runtime subprocess, network client, artifact downloader, credential reader, or provider integration is admitted by this selected closure.

## Authority and security constraints

1. **Stable identity remains Sentrdel-owned.** `GraphNodeId` and `GraphEdgeId` are derived and revalidated by `sentrdel-schema` / `sentrdel-graph`; Petgraph node indexes are ephemeral implementation details.
2. **Provenance and confidence remain explicit Sentrdel records.** Petgraph edge/node weights contain only stable IDs. It cannot elevate `Inferred` data to `Extracted`, suppress provenance, or create findings.
3. **Projection fails closed.** Duplicate stable IDs, malformed records, and edges with missing endpoints are rejected before adjacency is exposed.
4. **Traversal is bounded.** Reverse reachability requires an explicit relation allowlist and a caller depth bounded by `MAX_BLAST_RADIUS_DEPTH`.
5. **Traversal is evidentiary, not causal authority.** Returned witness paths prove only reachability through admitted graph relations; callers must not reinterpret them as runtime causality or a security verdict.
6. **Determinism is Sentrdel-owned.** Records are indexed in stable-ID order and traversal candidates/results are sorted so input iteration order cannot alter observable output.
7. **No universal CPG expansion.** T033 projects only the thin evidence/property graph already defined by Sentrdel contracts. AST/CFG/type-system duplication remains out of scope.
8. **No target repository execution.** Petgraph runs only over already-produced Sentrdel graph records and does not execute, build, install, or query the analyzed repository.

## Relationship to qualified Graphify concepts

GQ-001 already permits selective native Rust reuse of Graphify's graph-diff and affected/blast-radius concepts. T033 implements a Sentrdel-owned Rust design rather than copying Graphify Python/NetworkX source. The implementation strengthens the concept by requiring stable Sentrdel identities, explicit relation allowlists, bounded depth, deterministic witness paths, and metadata/provenance/confidence-aware graph diff.

## Upgrade and maintenance rule

Any Petgraph version change, feature expansion, new transitive dependency, build/proc-macro/native/download surface, or movement of semantic authority into Petgraph requires a new qualification delta before merge.

Petgraph's upstream repository is evolving toward a multi-crate layout after the qualified release; Sentrdel therefore pins the published `0.8.3` release instead of following a moving branch.

## Evidence consulted

- `petgraph/petgraph` `Cargo.toml` at exact commit `162903562ce5b00cdba390a0d9c1bb80f1c75bf5`
- crates.io index records for `petgraph 0.8.3`, `fixedbitset 0.5.7`, `hashbrown 0.15.5`, and `foldhash 0.1.5`
- `rust-lang/hashbrown` manifest at tag `v0.15.5`
- Sentrdel `AGENTS.md`, constitution, active spec/plan/tasks, GQ-001 record, and T033 implementation/lockfile delta

No donor implementation source was copied into Sentrdel by PGQ-001.
