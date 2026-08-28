# T039 ast-grep / Tree-sitter dependency qualification

**Status:** QUALIFIED_FOR_T039_ADMISSION_PENDING_LOCK_CLOSURE  
**Task:** T039 — native structural producer framework  
**Qualified at:** 2026-08-28

## Decision

Sentrdel may admit the following exact crates for T039 only after the implementation branch resolves and commits the complete Cargo lockfile closure and updates `docs/security/privileged-dependencies.toml` for every newly observed `custom-build`, `proc-macro`, or native `links` surface:

- `ast-grep-core =0.45.2`
- `tree-sitter =0.26.13`
- `tree-sitter-javascript =0.25.0` as the minimal first grammar used to prove the framework

This record does not admit `ast-grep`, `ast-grep-language`, its broad grammar bundle, the ast-grep CLI, dynamic loading, YAML rule configuration, network access, downloaded binaries, or any target-repository executable behavior.

## Upstream identity and license

### ast-grep-core

- Repository: `ast-grep/ast-grep`
- Tag: `0.45.2`
- Exact upstream commit: `c41e023a64060c9f263c23320aa5ff67be4bc474`
- Crate: `ast-grep-core 0.45.2`
- Crates.io checksum: `442c9ecc111490ac358901dea6baf854baab8b298b982126d4391ba283389d9d`
- License: MIT
- Rust minimum declared upstream: 1.88.0
- Package build script: none (`build = false`)
- Selected capability: in-process AST matching/traversal primitives only

The crate's selected `tree-sitter` feature is allowed because T039 explicitly requires the native Tree-sitter substrate. Other ast-grep workspace crates are not admitted by this record.

### tree-sitter

- Repository: `tree-sitter/tree-sitter`
- Tag: `v0.26.13`
- Exact upstream commit: `d97971e24500218865c05ed1febdee2acf41bae1`
- Crate: `tree-sitter 0.26.13`
- License: MIT
- Rust minimum declared upstream: 1.77
- Package build script: `binding_rust/build.rs`
- Native link surface: `links = "tree-sitter"`
- Selected capability: in-process parser runtime only

Tree-sitter compiles and links its bundled C runtime. This is a privileged trusted-workspace build surface. It must be declared in `docs/security/privileged-dependencies.toml` when the dependency lands. The runtime receives untrusted source bytes only through Sentrdel-owned bounded repository reads; it receives no filesystem, process, credential, network, policy, or Finding authority.

### tree-sitter-javascript

- Repository: `tree-sitter/tree-sitter-javascript`
- Tag: `v0.25.0`
- Annotated tag object: `f76aea6aa47322ea5c208c9c2e67f4a350d554f3`
- Tag verification: GitHub reports the SSH signature valid
- Exact upstream commit: `44c892e0be055ac465d5eeddae6d3e194424e7de`
- Crate: `tree-sitter-javascript 0.25.0`
- Crates.io checksum: `68204f2abc0627a90bdf06e605f5c470aa26fdcb2081ea553a04bdad756693f5`
- License: MIT
- Package build script: `bindings/rust/build.rs`
- Build dependency: `cc 1.2.x`
- Selected capability: JavaScript/JSX grammar used only to prove the T039 framework and tests

The grammar build compiles generated `parser.c` / scanner code. That compile-time native surface is privileged and must be present in the executable dependency declaration when admitted. This record does not authorize grammar generation, Node.js execution, the Tree-sitter CLI, or target-repository build tooling.

## Security boundary

The admitted parser stack is data-only from the target repository perspective:

1. Source bytes enter through the bounded repository/file view established by T038.
2. No target `Cargo`, npm, pip, package-manager, build, install, hook, filter, textconv, submodule, credential-helper, or remote command is executed.
3. Parsing and matching remain inside the Rust trusted process. Parser/matcher output is untrusted producer data until Sentrdel-owned validation converts it into canonical Evidence.
4. The T039 framework may emit observations/candidates only. It cannot create canonical Findings; only the reconciler has that authority.
5. Repository-owned rule text is not trusted instruction or policy. T039 uses a Sentrdel-owned typed rule format and bounded rule registry.
6. Parser failure, unsupported language, malformed source, timeout/resource limit, or bounded-input rejection must remain visible as failure/coverage state where applicable and must never become a clean-security result.
7. No dynamic grammar loading, shared-library discovery, remote grammar fetch, or repository-selected executable is authorized.

## Resource and failure requirements for T039

The implementation must:

- parse only bytes already accepted by `RepoFileView` bounds;
- impose an explicit per-document byte limit at or below the repository-view file limit;
- avoid recursive traversal controlled by untrusted depth where an iterative/bounded traversal is available;
- reject duplicate rule IDs and unsupported language/rule variants deterministically;
- keep rule identifiers, severity/category metadata, query/matcher definitions, and producer identity Sentrdel-owned;
- return typed errors for parse/language/rule failures instead of panicking;
- include positive, negative, malformed-source, oversized-input, duplicate-rule, and deterministic-replay tests;
- make no semantic type/dataflow claim that Tree-sitter cannot prove.

## Supply-chain qualification limits

This qualification is intentionally two-stage. It qualifies the direct intended packages and their known privileged package surfaces, but it does **not** pre-approve an unknown resolved transitive closure.

Before merge of the T039 implementation branch:

1. Resolve dependencies using Sentrdel's trusted workspace only and commit `Cargo.lock`.
2. Run `scripts/validate_dependency_governance.py` against the resolved metadata.
3. Add every newly observed build-script, proc-macro, or native-link package to `docs/security/privileged-dependencies.toml` with a qualification reference and rationale.
4. Run the canonical `Dependency security` workflow without waiver and require PASS on the exact PR head.
5. Require `Rust 1.98 bootstrap` and `Resolve and test schema substrate` on the same exact head.

If the locked closure introduces materially broader authority than the packages described here, this qualification must be amended before admission rather than weakening the validator.

## Maintenance and replacement

Version or feature changes require a qualification delta. The intended removal boundary is narrow: `sentrdel-review` owns an adapter/framework over the parser stack, so ast-grep or a grammar can be replaced without changing Evidence, Finding, policy, persistence, or CLI authority contracts.

## Final qualification result

`QUALIFIED_FOR_T039_ADMISSION_PENDING_LOCK_CLOSURE`

This result authorizes a bounded implementation candidate; it is not T039 completion and does not authorize checking the T039 task box until exact-head tests, self-security, review, merge, and post-merge canonical evidence are complete.
