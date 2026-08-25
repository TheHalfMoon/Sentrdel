# Source Qualification Ledger

No donor source or data was copied into Sentrdel at bootstrap or in PR #3. GQ-001 qualifies a bounded Graphify source set for a future selective Rust port; the qualification branch itself still copies no donor implementation source.

## Founder source-reuse authorization

On 2026-08-24 the founder stated that Sentrdel has permission from the discussed GitHub source owners to reuse their code in this open-source project. Sentrdel records that statement as `FOUNDER_ATTESTATION_2026-08-24` and treats donor reuse as authorized at the project-governance level.

The repository does **not** currently contain source-specific private permission evidence identifying each granting owner, exact ref/files, and reuse scope. Sentrdel will not invent that evidence. Public open-source license grants remain independently applicable. Before copied/ported code lands, the import record must bind the exact upstream repository/ref/files, founder attestation and any available source-specific permission reference, attribution/notices, upstream license expression, modifications, build/runtime authority, and security review.

| Source | Exact ref | Mode | License observation | Decision | Security / architecture note |
|---|---|---|---|---|---|
| actions/checkout | `11d5960a326750d5838078e36cf38b85af677262` (v4.4.0 release line) | CI_ACTION | repository action consumed by immutable commit SHA | ADOPT for bootstrap CI | `persist-credentials: false`; immutable pin avoids mutable-tag drift; this commit contains backported fork/`pull_request_target` checkout hardening |
| Graphify-Labs/graphify | `b2cd36267456c166788c95be6e68574064a92a42` (`v8`, package `0.9.48`) | FOUNDER_ATTESTED_DONOR | current package is Apache-2.0; NOTICE retains older MIT-contributed portions; selected-file qualification conservatively uses Apache-2.0 | `QUALIFIED_FOR_SELECTIVE_RUST_PORT` via GQ-001; implementation remains separate | graph diff + affected/blast-radius traversal + validation concepts only; no Python/NetworkX/MCP/provider runtime; Sentrdel authority remains canonical |
| microsoft/regorus | `f98865fc980b9919d201e20969d9b28685ee72bc` (`regorus-v0.11.0`; crates.io `regorus 0.11.0`) | NATIVE_DEP | upstream package declares `MIT AND Apache-2.0 AND BSD-3-Clause` | `QUALIFIED_FOR_BOUNDED_IN_PROCESS_POLICY_ONLY` via RQ-001 | exact pin/checksum; defaults disabled; only `std` + `arc`; no HTTP/net/time/YAML/OPA-runtime/RVM policy authority; Regorus `build.rs`, transitive proc-macro/build surfaces, and `msvc_spectre_libs` native-link behavior recorded; Rust kernel remains authoritative |
| vitali87/code-graph-rag | UNPINNED — exact qualification required before import | FOUNDER_ATTESTED_DONOR | repository-level MIT observed; file-level record still required | QUALIFICATION_PENDING / selective port or adapter | permission basis currently `FOUNDER_ATTESTATION_2026-08-24`; source-specific proof not stored; resource/data-flow/static-runtime merge is high-value; Python/Memgraph is not the Sentrdel trusted base runtime |
| deepseek-ai/deepseek-harness | UNPINNED — exact qualification required before import | FOUNDER_ATTESTED_DONOR | repository-level MIT observed | QUALIFICATION_PENDING / selective port | permission basis currently `FOUNDER_ATTESTATION_2026-08-24`; source-specific proof not stored; durable events/tool guards/approval seams; do not inherit the whole rapidly evolving agent runtime |
| continuedev/continue | UNPINNED — exact qualification required before import | FOUNDER_ATTESTED_DONOR | repository-level Apache-2.0 observed | QUALIFICATION_PENDING / integration-layer reuse | permission basis currently `FOUNDER_ATTESTATION_2026-08-24`; source-specific proof not stored; VS Code/JetBrains/CLI/diff plumbing may be reused selectively; no need for a wholesale product fork |

## GQ-001 — Graphify exact qualification record

```text
source_id: GQ-001
repository: Graphify-Labs/graphify
exact_ref: b2cd36267456c166788c95be6e68574064a92a42
default_branch_at_qualification: v8
upstream_tree: be8636735370ed82708bb53eba33170e85acc369
upstream_package_version: 0.9.48
files_or_artifacts:
  - graphify/analyze.py @ 0707e2be78eceef3a7f6ae7ee6d3659659ffdf55
  - graphify/affected.py @ 0184a8f88fa458de76107b63d08b77b0c739abbc
  - graphify/validate.py @ bab3ddc7c89e4a122e62e20f37d8c7c2f054a9bf
  - tests/test_analyze.py @ 7bff432cf7212da6f329588ce4d81a7cdca81d34
  - ARCHITECTURE.md @ 080f46f2235bfa3dee34a2488fdcc5b8caaefe54
  - pyproject.toml @ 15ea9dd57c500f219ec916ad0b99b9e07fa0a6ea
  - LICENSE @ d645695673349e3947e8e5ae42332d0ac3164cd7
  - LICENSE-MIT @ b1d9746fb5c6c39fd502e2ebe432a12ad9a097f3
  - NOTICE @ 791bf88bb1e50572902dbbe9228153ea29846adf
permission_basis: FOUNDER_ATTESTATION_2026-08-24 + public Apache-2.0 license grant
source_specific_permission_reference: NOT_STORED
license_expression: Apache-2.0 for the qualified current source set; do not assume file-specific MIT without history evidence
notices: preserve applicable Graphify NOTICE attribution in any derived implementation
integration_mode: SELECTIVE_NATIVE_RUST_PORT into sentrdel-graph; no donor runtime dependency
executes_at_build: upstream uses setuptools.build_meta; upstream build/runtime is not admitted by GQ-001
procedural_macro: N/A for selected Python source; no donor macro admitted
native_code: upstream dependency surface includes tree-sitter/native wheels; none admitted by GQ-001
downloads_artifacts: no donor artifact downloads authorized for the Sentrdel port
security_notes: confidence labels are adapter metadata, never Sentrdel authority; fuzzy seed resolution cannot drive canonical decisions; no MCP/network/provider surfaces admitted
maintenance_notes: ACTIVE at qualified ref; upstream exact head dated 2026-08-20; fast-moving project, so future updates require a qualification delta
modifications: future port must strengthen graph diff to surface attribute/confidence/provenance changes and bind impact paths to Sentrdel evidence
qualified_by: Sentrdel source qualification review
qualified_at: 2026-08-24
qualification_report: docs/third-party/graphify-source-qualification.md
```

## RQ-001 — Regorus dependency qualification record

```text
source_id: RQ-001
repository: microsoft/regorus
exact_ref: f98865fc980b9919d201e20969d9b28685ee72bc
tag: regorus-v0.11.0
annotated_tag_object: dd544d82a8a307b543fc31965e27ca8ba8f61e01
crate: regorus =0.11.0
crate_checksum: 3cc4dc91481b1d4001ba7f2e81f7faf674142e0ac36d37d79e5f02764d06571e
files_or_artifacts:
  - crates.io regorus 0.11.0 package
  - upstream Cargo.toml @ f98865fc980b9919d201e20969d9b28685ee72bc
  - upstream build.rs @ f98865fc980b9919d201e20969d9b28685ee72bc
  - committed Sentrdel Cargo.lock dependency closure
permission_basis: public package license grants
source_specific_permission_reference: N/A
license_expression: MIT AND Apache-2.0 AND BSD-3-Clause
notices: follow upstream package/license requirements; no donor source copied into Sentrdel
integration_mode: NATIVE_DEP
features: default-features=false; std; arc
executes_at_build: YES — Regorus build.rs is elevated-review complete; checkout-hook paths require an upstream .git checkout and are inactive in normal crates.io dependency builds; git rev-parse path is behind disabled opa-runtime; transitive build-script surfaces remain exact-lockfile governed
procedural_macro: YES, TRANSITIVE — compile-time proc-macro dependencies including thiserror-impl are admitted only as exact-lockfile Regorus closure and receive no runtime/policy authority
native_code: CONDITIONAL TRANSITIVE — Regorus std activates msvc_spectre_libs 0.1.3 (checksum 29e871a9861f3664f18b7e04e9301d4edd55090c2dadb4b1c602e26ab32b1f5b), which locates/links Spectre-mitigated libraries on Windows MSVC; Ubuntu exact-head CI does not prove Windows-MSVC qualification
downloads_artifacts: no Regorus or qualified transitive artifact-download path is admitted by T023
security_notes: no HTTP/net/time/YAML/UUID/regex/RVM/Azure/OPA-runtime policy features; policy/input/data caps precede parsing; fixed entrypoint; import/subset/builtin allowlists fail closed; execution timer; failures map to UNDECIDABLE; Rust kernel remains non-overridable
maintenance_notes: version or feature changes require a new qualification delta and lockfile/privileged-surface review; Windows-MSVC release claims require a separate proven build gate or dependency-strategy change
modifications: Sentrdel wrapper adds stricter depth/size/subset limits and authority boundaries; upstream source is not modified/copied
qualified_by: Sentrdel dependency qualification review
qualified_at: 2026-08-25
qualification_report: docs/third-party/regorus-qualification.md
```

## Record template

```text
source_id:
repository:
exact_ref:
files_or_artifacts:
permission_basis:
source_specific_permission_reference:
license_expression:
notices:
integration_mode:
executes_at_build:
procedural_macro:
native_code:
downloads_artifacts:
security_notes:
maintenance_notes:
modifications:
qualified_by:
qualified_at:
```
