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
| watchexec/process-wrap | `3d856eebd02799d025237134db51d05bbc4f1434` (`v9.1.0`; crates.io `process-wrap 9.1.0`) | NATIVE_DEP | upstream package declares `Apache-2.0 OR MIT` | `QUALIFIED_FOR_T027_UNIX_PROCESS_LIFECYCLE_CONTAINMENT` via PWQ-001 + PWQ-001-D1 | exact pins/checksums; defaults disabled; `std` + `process-group` + `job-object`; `nix 0.31.3` privileged syscall/build surface recorded; PWQ-001-D1 qualifies the bounded macOS post-reap signal-zero group-absence proof without widening sandbox/network/provider authority |
| petgraph/petgraph | `162903562ce5b00cdba390a0d9c1bb80f1c75bf5` (`petgraph@v0.8.3`; crates.io `petgraph 0.8.3`) | NATIVE_DEP | upstream package declares `MIT OR Apache-2.0` | `QUALIFIED_FOR_T033_BOUNDED_IN_MEMORY_GRAPH_PROJECTION` via PGQ-001 | exact pin/checksum; defaults disabled; `std` only; stable identity/provenance/confidence/verdict authority remains Sentrdel-owned; no new build/proc-macro/native/download/network surface in selected closure |
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

## PWQ-001 — process containment dependency qualification record

```text
source_id: PWQ-001
repository: watchexec/process-wrap
exact_ref: 3d856eebd02799d025237134db51d05bbc4f1434
tag: v9.1.0
annotated_tag_object: d61729ff63bb9e5c731c8c5720bfffbc9350d167
crate: process-wrap =9.1.0
crate_checksum: 2e842efad9119158434d193c6682e2ebee4b44d6ad801d7b349623b3f57cdf55
subsidiary_dependency: nix =0.31.3 @ b5933ca178802b558a667514f717a86b3a1cedcc; tag v0.31.3; annotated tag object 9cd968a1af35b46b05ed41e05acfcca5d02a5645; checksum cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d
files_or_artifacts:
  - crates.io process-wrap 9.1.0 package
  - process-wrap Cargo.toml @ 3d856eebd02799d025237134db51d05bbc4f1434
  - process-wrap src/std/process_group.rs @ v9.1.0
  - process-wrap src/std/job_object.rs @ v9.1.0
  - crates.io nix 0.31.3 package
  - nix Cargo.toml @ b5933ca178802b558a667514f717a86b3a1cedcc
  - nix build.rs @ b5933ca178802b558a667514f717a86b3a1cedcc
  - committed Sentrdel Cargo.lock dependency closure
permission_basis: public package license grants
source_specific_permission_reference: N/A
license_expression: process-wrap Apache-2.0 OR MIT; nix MIT
notices: follow upstream package/license requirements; no donor implementation source copied into Sentrdel
integration_mode: NATIVE_DEP behind private sentrdel-engine process_tree boundary
features: process-wrap default-features=false; std; process-group; job-object. nix direct dependency default-features=false; PWQ-001-D1 admits direct `process` + `signal` safe APIs for the bounded macOS post-reap group-absence proof. The effective resolved nix feature closure does not expand because process-wrap already enables `signal`, and nix `signal` implies `process`.
executes_at_build: process-wrap NO package build.rs. nix YES — qualified build.rs only declares cfg aliases/rustc-check-cfg metadata; no subprocess/download/network/credential behavior observed.
procedural_macro: CONDITIONAL TRANSITIVE — Windows target closure includes windows interface/implementation proc macros; lockfile governed. No proc macro receives Sentrdel policy or repository authority.
native_code: YES / PRIVILEGED OS SURFACE — process containment uses POSIX group signaling/waiting on Unix and Windows Job Object APIs on Windows; dependency implementations contain platform FFI/unsafe code while sentrdel-engine itself forbids unsafe code.
downloads_artifacts: no runtime/build artifact-download path admitted by the qualified process-wrap/nix feature set; normal crates.io dependency resolution occurs only for Sentrdel's trusted workspace.
security_notes: executable selection, argv, cwd confinement, env_clear allowlist, hard limits, network declaration admission, termination policy, and output interpretation remain Rust-owned Sentrdel authority. PWQ-001-D1 admits only macOS safe `Pid` plus signal-zero probing of the exact spawned process group after an exited root is reaped; only ESRCH proves absence. No hostile-code sandbox, network, credential, provider, target-execution, policy, Finding, or Evidence authority is added.
maintenance_notes: process-wrap 10.0.0 was released 2026-08-24 with breaking wrapper and Windows fixes. Any version/feature change, additional direct privileged API use, effective resolved feature-closure expansion, or broader platform/release claim requires a fresh qualification delta and lockfile review.
modifications: no upstream source modified/copied; Sentrdel adds a private containment wrapper, lifecycle regressions, and the PWQ-001-D1 macOS post-reap absence proof.
qualified_by: Sentrdel dependency qualification review
qualified_at: 2026-08-26
qualification_evidence: GitHub Actions run 32916506528 on Sentrdel head f61b71cae9f66168863da6768d24dbd2822f0160; Rust 1.98 semantic PASS; cargo-audit 0.22.0 PASS; cargo-deny 0.20.2 PASS without waiver
qualification_report: docs/third-party/process-wrap-qualification.md
qualification_delta: docs/third-party/process-wrap-qualification-delta-pwq-001-d1.md
```

## PGQ-001 — Petgraph dependency qualification record

```text
source_id: PGQ-001
repository: petgraph/petgraph
exact_ref: 162903562ce5b00cdba390a0d9c1bb80f1c75bf5
tag: petgraph@v0.8.3
annotated_tag_object: 64ee942b617260177f0423ceb9e79d9b415627cc
crate: petgraph =0.8.3
crate_checksum: 8701b58ea97060d5e5b155d383a69952a60943f0e6dfe30b04c287beb0b27455
files_or_artifacts:
  - crates.io petgraph 0.8.3 package
  - petgraph Cargo.toml @ 162903562ce5b00cdba390a0d9c1bb80f1c75bf5
  - crates.io fixedbitset 0.5.7 package @ checksum 1d674e81391d1e1ab681a28d99df07927c6d4aa5b027d7da16ba32d1d21ecd99
  - crates.io hashbrown 0.15.5 package @ checksum 9229cfe53dfd69f0609a49f65461bd93001ea1ef889cd5529dd176593f5338a1
  - crates.io foldhash 0.1.5 package @ checksum d9c4f5dac5e15c24eb999c26181a6ca40b39fe946cbe4c263c7209467bc83af2
  - committed Sentrdel Cargo.lock dependency closure
permission_basis: public package license grants
source_specific_permission_reference: N/A
license_expression: MIT OR Apache-2.0
notices: follow upstream package/license requirements; no donor implementation source copied into Sentrdel
integration_mode: NATIVE_DEP inside sentrdel-graph for ephemeral adjacency/index/traversal mechanics only
features: petgraph default-features=false; std only
executes_at_build: NO new package build-script surface admitted by the selected closure
procedural_macro: NO new procedural-macro surface admitted by the selected closure
native_code: NO new native/FFI dependency surface admitted by the selected closure
downloads_artifacts: no runtime/build artifact-download path admitted; normal crates.io dependency resolution remains lockfile governed
security_notes: canonical node/edge identity, schema validation, provenance, confidence, relation semantics, persistence, findings and verdict authority remain Sentrdel-owned; reverse reachability requires explicit relation allowlist and bounded depth; witness paths express graph reachability only
maintenance_notes: exact version/feature/closure pin; upstream post-release multi-crate evolution or any dependency/feature expansion requires a fresh qualification delta
modifications: no upstream source modified/copied; Sentrdel wraps Petgraph behind deterministic projection/diff APIs and returns only stable Sentrdel identities
qualified_by: Sentrdel dependency qualification review
qualified_at: 2026-08-28
qualification_report: docs/third-party/petgraph-qualification.md
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