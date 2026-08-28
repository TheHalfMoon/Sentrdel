# SCIP Protocol Reference — T034

Status: **PROTOCOL_REFERENCE_ONLY — NO UPSTREAM RUNTIME OR SOURCE IMPORT**

Recorded on: 2026-08-28

## Exact reference

- Repository: `scip-code/scip`
- Exact commit: `a7b9c65a8aa148a79b67cc7f6dafea154dbc63d0`
- Files consulted:
  - `scip.proto` @ blob `9ae8c9633492d34f9fe4894b414c606c150fcbfc`
  - `LICENSE` @ blob `261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64`
- Upstream license: Apache-2.0

No SCIP source, generated binding, protobuf runtime, command, indexer, or package is copied or added as a Sentrdel dependency by T034.

## Protocol facts used by the Sentrdel boundary

The upstream protocol explicitly allows indexers across a precision spectrum, including compiler-backed and heuristic producers. Therefore a SCIP artifact's existence cannot by itself establish compiler-level semantic certainty.

The T034 design also relies on these protocol properties:

- an index contains producer `ToolInfo` metadata;
- documents are rooted under one index project root;
- `Document.relative_path` is required to be relative and canonical, with `/` separators and no empty, `.` or `..` components;
- occurrences identify symbol definitions/references and source ranges;
- local SCIP symbols are document-local rather than workspace-global.

## Sentrdel authority decision

Sentrdel does not infer producer authority from artifact-controlled `ToolInfo`, command arguments, repository text, or an indexer's self-description.

`ScipProducerQualification` is supplied by a trusted caller after separate producer qualification and carries a non-blank qualification ID. Both the original artifact digest and this qualification ID are preserved as graph provenance.

- qualified compiler/language-server-backed producer -> reference relations may use graph confidence basis `EXTRACTED`;
- qualified heuristic producer -> reference relations use `INFERRED`, and coverage remains `PARTIAL`;
- missing/unsupported/failed/timed-out/policy-skipped optional indexer -> explicit non-covered `CoverageRecord`;
- empty index -> `PARTIAL`, never a clean semantic result.

Graph confidence remains producer-local metadata and does not mint `FACT`, `VERIFIED`, Findings, policy decisions, or security verdicts.

## Runtime and parsing boundary

T034 defines only an adapter-normalized Rust ingestion interface. It performs no:

- protobuf decoding;
- filesystem discovery;
- target repository execution;
- compiler/language-server invocation;
- subprocess execution;
- package-manager execution;
- network access;
- artifact download.

A future concrete SCIP decoder or indexer adapter must receive its own dependency/source/runtime qualification and bounded hostile-input design before entering the repository.

## Resource and determinism constraints

The T034 graph boundary rejects invalid artifact digests, non-canonical document paths, blank producer/qualification metadata, invalid ranges, duplicate document paths, and requests exceeding hard document/occurrence limits.

Documents/occurrences are normalized into stable Sentrdel graph identities. Duplicate occurrences are deduplicated, local symbols are document-scoped, and output ordering is stable-ID deterministic.

## Scope

T034 covers only the ingestion contract and explicit graph-semantic coverage behavior required by R1. It does not authorize:

- mandatory language indexers;
- universal CPG behavior;
- call/data-flow certainty not represented by the bounded mapping;
- automatic producer trust;
- T035 CLI behavior;
- T046 Finding-context semantics.
