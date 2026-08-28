# T039 parser stack locked admission

**Qualification ID:** `T039Q-001`  
**Task:** T039 — native structural producer framework  
**Status:** QUALIFIED_LOCK_CLOSURE_FOR_IMPLEMENTATION

## Direct packages

- `ast-grep-core =0.45.2`, checksum `442c9ecc111490ac358901dea6baf854baab8b298b982126d4391ba283389d9d`
- `tree-sitter =0.26.13`, checksum `17ebdd3a5a7e28a1890b876fdbd0c3c0fe0a6336cffaa104f11b9f720c9daa29`
- `tree-sitter-javascript =0.25.0`, checksum `68204f2abc0627a90bdf06e605f5c470aa26fdcb2081ea553a04bdad756693f5`

The direct source identities, upstream refs, licenses, selected authority, and prohibited capabilities are recorded in `docs/third-party/t039-ast-grep-tree-sitter-qualification.md`.

## Resolved privileged closure

The Rust 1.98 trusted-workspace resolution identified these newly introduced privileged packages in addition to the already-declared workspace closure:

| Package | Version | Privileged surface | Admission rationale |
|---|---:|---|---|
| `borsh` | `1.8.1` | build-script | Transitive ast-grep bit-set closure compile-time configuration only; no runtime repository authority. |
| `borsh-derive` | `1.8.1` | proc-macro | Transitive compile-time derive code only; no runtime policy, filesystem, process, credential, or network authority. |
| `tree-sitter` | `0.26.13` | build-script, native-link | Compiles/links the bundled Tree-sitter C runtime used only for in-process parsing of bounded source bytes. |
| `tree-sitter-javascript` | `0.25.0` | build-script | Compiles the committed generated JavaScript grammar; grammar generation and target build tooling are not authorized. |
| `tree-sitter-language` | `0.1.7` | build-script, native-link | ABI/language-function bridge in the locked Tree-sitter grammar closure; receives no target-repository authority. |

No downloaded runtime binary, dynamic grammar loading, target-repository command, credential access, network lookup, package-manager execution, or repository-controlled build step is admitted by this qualification.

## Verification provenance

A bounded verification-only GitHub Actions workflow resolved the lockfile and cargo metadata from canonical `main` plus the exact T039 direct dependency declarations using Rust 1.98.0. The workflow reported the five undeclared privileged packages listed above. Its temporary workflow file was removed after evidence collection and is not part of the T039 implementation candidate.

The implementation branch must still pass the canonical `Dependency security` workflow on its exact final head. This record does not waive `cargo-audit`, `cargo-deny`, dependency-source validation, or privileged-surface exhaustiveness.

## Authority boundary

Parser and matcher output is producer data only. T039 cannot create canonical Findings, change policy, execute target code, load repository-provided rules, or convert parser failure/missing coverage into a clean-security result. Later T040 rules remain Sentrdel-owned and deliberately bounded.
