# R3-T033 Final Dependency and Source Governance

**Task:** R3-T033  
**Status:** CANDIDATE_PENDING_EXACT_HEAD_QUALIFICATION  
**Canonical prerequisite:** `main@d168cd604d6f540a02a65966147e2c288ba21d6c`  
**R3 dependency baseline:** T007 merge `37545f1542e05cf8bfdb77ebd94749cd3cc8fcd7`  
**Authority:** Evidence/governance only. This record changes no dependency, lockfile, privileged surface, product behavior, public schema, Finding/reconciler/policy authority, network/credential authority, target execution, provider access, or runtime claim.

## Decision

R3 adopted exactly one dependency during its dependency-admission task: the already-qualified `tree-sitter-typescript =0.23.2` grammar package from R3-T007 / TSQ-001. The dependency and source-governance graph relevant to that admission is byte-for-byte unchanged between the canonical T007 merge and the R3-T033 prerequisite main.

No new R3 dependency or privileged dependency surface requires qualification in this task. R3-T033 therefore revalidates the existing TSQ-001 qualification and proves dependency/source-governance continuity rather than admitting or upgrading a package.

## Canonical T007 admission

R3-T007 was implemented in PR #257 against base `556aac3b3fe60dfbc6a620c201e32996311a8a32` and merged as:

```text
implementation_pr: 257
qualified_head: f91cc19d46417b945b3127b329dc75c032c384e1
merge_commit: 37545f1542e05cf8bfdb77ebd94749cd3cc8fcd7
source_qualification: TSQ-001
```

The exact T007 lockfile patch added only:

```text
workspace edge: sentrdel-review -> tree-sitter-typescript
package: tree-sitter-typescript 0.23.2
checksum: 6c5f76ed8d947a75cc446d5fccd8b602ebf0cde64ccf2ffa434d873d7a575eff
resolved dependencies: cc, tree-sitter-language
```

Both resolved dependencies were already present in the qualified structural-parser closure. No additional transitive package was introduced by the T007 lockfile delta.

The final independent T007 review covered exact range:

```text
556aac3b3fe60dfbc6a620c201e32996311a8a32..f91cc19d46417b945b3127b329dc75c032c384e1
```

and concluded `CLEAN` with no actionable findings.

## TSQ-001 exact identity

The canonical qualification remains:

```text
repository: tree-sitter/tree-sitter-typescript
release: v0.23.2
exact_ref: f975a621f4e7f532fe322e13c4f79495e0a7b2e7
crate: tree-sitter-typescript =0.23.2
crate_checksum: 6c5f76ed8d947a75cc446d5fccd8b602ebf0cde64ccf2ffa434d873d7a575eff
license: MIT
default_features: false
qualification_id: TSQ-001
decision: QUALIFIED_FOR_BOUNDED_R3_TYPESCRIPT_GRAMMAR
```

The admitted privileged surface remains exactly `build-script`. The build script compiles the package's committed generated TypeScript/TSX C parser/scanner sources through the already-qualified `cc` build closure. TSQ-001 admits no grammar generation, repository execution, target package-manager execution, network access, credentials, provider access, policy authority, Finding authority, reconciler authority, runtime exploitability claim, or universal CPG authority.

## Byte-identical governance proof

The following Git blob identities are identical at both:

- canonical T007 merge `37545f1542e05cf8bfdb77ebd94749cd3cc8fcd7`; and
- R3-T033 prerequisite `d168cd604d6f540a02a65966147e2c288ba21d6c`.

| Artifact | Git blob SHA at T007 merge | Git blob SHA at T033 prerequisite | State |
|---|---|---|---|
| `Cargo.toml` | `84f1a98e9019a4cb317e6e30d167d11924d2a1c0` | `84f1a98e9019a4cb317e6e30d167d11924d2a1c0` | UNCHANGED |
| `Cargo.lock` | `d2db9ef19e0d7cdd6c699b18b0c64a075849ebd9` | `d2db9ef19e0d7cdd6c699b18b0c64a075849ebd9` | UNCHANGED |
| `crates/sentrdel-review/Cargo.toml` | `dba296f69ce1764eae96d65d4027c5f892cc7ecb` | `dba296f69ce1764eae96d65d4027c5f892cc7ecb` | UNCHANGED |
| `docs/security/privileged-dependencies.toml` | `60fb5acfbacb913153275dbf1e32d0483a367814` | `60fb5acfbacb913153275dbf1e32d0483a367814` | UNCHANGED |
| `docs/third-party/source-qualification-ledger.md` | `bbcd88faf1fb90b27d687f0993cde32a3cb0855d` | `bbcd88faf1fb90b27d687f0993cde32a3cb0855d` | UNCHANGED |
| `docs/third-party/tree-sitter-typescript-qualification.md` | `b71940ab2c7d9ee86a8be3eccdf6c8849cf1bbc4` | `b71940ab2c7d9ee86a8be3eccdf6c8849cf1bbc4` | UNCHANGED |

This proves that the workspace dependency declaration, exact lock graph, consuming crate dependency edge, privileged-surface declaration, source-qualification ledger, and TSQ-001 qualification report have not drifted since the dependency became canonical.

## Current manifest and lock assertions

At the R3-T033 prerequisite:

```toml
# Cargo.toml
tree-sitter-typescript = { version = "=0.23.2", default-features = false }
```

```toml
# crates/sentrdel-review/Cargo.toml
tree-sitter-typescript.workspace = true
```

The canonical lockfile still binds:

```text
name = tree-sitter-typescript
version = 0.23.2
checksum = 6c5f76ed8d947a75cc446d5fccd8b602ebf0cde64ccf2ffa434d873d7a575eff
dependencies = cc, tree-sitter-language
```

The privileged dependency declaration still binds:

```text
package = tree-sitter-typescript 0.23.2
surfaces = build-script
qualification = TSQ-001
```

## Current automated governance evidence

The R3-T032 closeout post-merge Self Security run on exact prerequisite main completed successfully:

```text
main: d168cd604d6f540a02a65966147e2c288ba21d6c
workflow: Self Security
run: 34164363945
job: Dependency security
conclusion: SUCCESS
```

Its successful dependency-security path included:

- locked Sentrdel dependency metadata generation;
- source-qualification and privileged-declaration validation;
- release dependency-policy validator tests;
- release dependency-policy validation;
- advisory refresh and lockfile audit;
- dependency-policy enforcement.

That prerequisite success is historical evidence only. **R3-T033 is not qualified by it.** Self Security and all applicable project CI must pass again on the exact R3-T033 candidate head. Any candidate-head change invalidates prior exact-head qualification.

## T033 candidate gates

Before this R3-T033 implementation/evidence unit may merge:

1. the candidate delta must contain no dependency, lockfile, privileged-surface, source-qualification, workflow, product, or public-schema change;
2. Self Security / `Dependency security` must pass on the exact candidate head;
3. Bootstrap CI and Schema Lock Qualification must pass on the exact candidate head;
4. Cross-platform CI must pass on Linux, macOS, and Windows on the exact candidate head;
5. fresh independent exact-range review must report no actionable dependency/source/governance defect;
6. all review conversations must be resolved;
7. canonical `main` must remain the expected base and the merge must use the exact expected candidate head;
8. the resulting protected `main` must pass required and Cross-platform post-merge CI plus live repository-governance verification;
9. only after that proof may a separate checkbox-only closeout mark R3-T033 complete and open R3-T034 write authority.

## Non-claims

This record does not claim:

- that upstream `tree-sitter-typescript` has no vulnerabilities outside the exact package/ref and admitted surface;
- that static TypeScript parsing proves runtime behavior;
- that TSX support exists merely because upstream ships TSX generated sources;
- that build-script/native code is unprivileged;
- that dependency governance replaces Self Security;
- that external roadmap research candidates are qualified dependencies or donor sources;
- that R3-T034 or any later task is authorized before R3-T033 canonical closeout.

R3-T033 remains unchecked in `tasks.md` until the implementation/evidence candidate is canonical and post-merge proven.