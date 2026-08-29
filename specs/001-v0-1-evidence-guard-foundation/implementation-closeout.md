# R1 Implementation Closeout — T087

**Date:** 2026-08-29  
**Task:** T087  
**Result:** **PASS_READY_FOR_CANONICAL_MERGE**  
**Canonical baseline qualified:** `92b6dc9baacf03bc1e0374a5795adb9cd743d145`  
**Evidence collection commit:** `7838b3d64e3cb9f9c45f7ea66bc178ddb1639145`  
**Evidence workflow run:** `33243777617`  
**Self-security run:** `33243777585`  
**Runner:** Ubuntu 24.04, Rust 1.98.0

## Closeout scope

T087 performs final execution qualification for R1. It does not add product behavior or widen authority. The temporary evidence workflow used to collect these results was deleted from the branch after successful execution and is not part of the intended canonical diff.

## Workspace qualification

| Qualification | Result |
|---|---|
| `cargo +1.98.0 fmt --all -- --check` | PASS |
| `cargo +1.98.0 check --workspace --all-targets --locked` | PASS |
| `cargo +1.98.0 test --workspace --locked -- --nocapture` | PASS |
| `cargo +1.98.0 clippy --workspace --all-targets --locked -- -D warnings` | PASS |

The workspace suite completed without failed tests. One subprocess fixture test remains intentionally ignored because it is invoked by its owning adversarial runner tests; that fixture is not treated as independent qualification evidence.

Representative adversarial and authority assertions passed, including hostile Git configuration staying data-only, hostile Cargo configuration not activating wrappers/runners, prompt injection remaining unable to mint FACT/VERIFIED Evidence or Finding/policy authority, repository policy remaining unable to weaken the trusted floor, missing coverage remaining explicit, and kernel DENY remaining absorbing.

## Secret persistence canaries

The closeout reran the current secret persistence boundaries explicitly:

- `t019_redaction`: 2 passed, 0 failed.
- `t019_state_redaction`: 1 passed, 0 failed.
- `registered_secret_fails_closed_before_any_current_sqlite_write_path`: PASS.
- `export_log_and_snapshot_fixtures_use_the_same_redaction_boundary`: PASS.
- `every_current_state_write_path_rejects_registered_secret_material`: PASS.
- redaction registration detects plaintext, JSON-escaped material, and value-only SHA-256 derivatives: PASS.
- graph/state/ASEL persistence paths reject registered secret material before persistence: PASS.

The changed-secret producer also passed its persistence-safe contract: serialized Evidence is redacted and its sanitized fingerprint is independent of the secret value.

## External engine and MCP credential boundaries

The external-engine adversarial suite passed. The runner scrubbed ambient environment authority, rejected unallowlisted environment and workspace executables, enforced resource limits, and preserved explicit coverage gaps on failure.

The MCP credential boundary passed both unit and end-to-end canaries:

- default child environment excludes credential canaries;
- command application clears prior explicit environment;
- only explicit user capability may cross the boundary;
- `default_child_environment_drops_credential_canaries_before_stdio_launch`: PASS;
- bounded stdio protocol, untrusted-content handling, policy versions, and resource limits: PASS.

No inherited engine/MCP credential authority was observed in the qualified paths.

## Dependency and source qualification

Self Security run `33243777585` completed `Dependency security` successfully on the evidence collection commit. The following gates passed:

- checksum-pinned self-security tools and tool identity verification;
- locked dependency metadata generation;
- source qualification and privileged dependency declarations;
- release dependency policy validator tests;
- release dependency policy validation;
- T037 `gix` authority-surface validation;
- refreshed advisory audit against `Cargo.lock`;
- `cargo deny` advisories, bans, licenses, and sources enforcement.

Therefore this closeout found no unqualified donor or privileged dependency in the qualified R1 dependency graph.

## Release benchmark

`SentrdelBench` R1 release suite reported:

- corpus class: `DEVELOPMENT_EVALUATION`;
- clean cases: 1;
- clean cases with false positive: 0;
- clean false-positive Findings: 0;
- vulnerable cases: 1;
- vulnerable signal groups expected/detected: 2/2;
- expected coverage dimensions: 2;
- explicit coverage-gap dimensions: 1;
- clean-PR false-positive gate: `PASS` with threshold at most 1 false-positive clean PR per 5;
- guard allowed actions: 1;
- guard false blocks: 0;
- guard denied actions: 1;
- incorrect allows: 0;
- malformed cases/rejected: 2/2;
- target build execution allowed: false;
- remote MCP supported: false;
- reasoner remained hypothesis-bounded: true;
- failed authority assertions: 0.

The release suite passed deterministic replay and release-boundary assertions.

## Review latency benchmark

Targeted closeout rerun:

| Workload | Samples | p95 | Target | Result |
|---|---:|---:|---:|---|
| 1,500 changed LOC | 20 | 40 ms | < 5,000 ms | PASS |
| 100,000 changed LOC | 5 | 2,681 ms | < 30,000 ms | PASS |

Machine attribution: Linux x86_64, 4 logical CPUs, GitHub Actions runner.

## MCP policy/frame benchmark

Targeted closeout rerun:

- samples: 2,000;
- in-process policy p95: 0 microseconds at timer resolution;
- target: < 50,000 microseconds;
- result: PASS;
- stdio frame memory remains bounded by configured caps: PASS.

The benchmark explicitly excludes transport and human/wait time from in-process policy latency.

## Review steel-thread evidence

The canonical development review steel thread reported:

- true positives: 3;
- false negatives: 0;
- false positives: 0;
- expected coverage dimensions: 9;
- completed coverage dimensions: 8;
- explicit coverage-gap dimensions: 1;
- missing coverage records: 1;
- failed authority assertions: 0.

The missing dimension remains visible rather than being converted into a clean/PASS claim.

## Protected-main governance

The connected GitHub App still cannot read the detailed branch-protection endpoint directly. T087 therefore used the canonical bounded verifier with `SENTRDEL_GOVERNANCE_ADMIN_TOKEN`; the built-in `GITHUB_TOKEN` was explicitly unset and no secret value was printed.

Verifier output from run `33243777617`:

```text
repository-governance: PASS
repository=TheHalfMoon/Sentrdel
branch=main
head=92b6dc9baacf03bc1e0374a5795adb9cd743d145
required_checks=Dependency security,Resolve and test schema substrate,Rust 1.98 bootstrap
active_repository_rulesets=0
```

The verifier fails closed unless the canonical `main` protection requires pull requests, strict/up-to-date required checks with the exact three names above, conversation resolution, administrator enforcement/no bypass, disabled force pushes, disabled deletion, and active enforcement targeting `main`.

The public branch summary independently reported `main` as protected with enforcement for the same three required checks.

## Cross-platform qualification

Immediately before T087 execution closeout, the T086 closeout exact head `970c5d921831fa5059cc048df679c615bceaa2d4` passed the repository's `Cross-platform CI` on Linux, macOS, and Windows. T087's own documentation PR must independently pass every applicable exact-head CI gate before canonical merge; this document does not substitute historical cross-platform success for that final PR qualification.

## Non-claims

This closeout does not claim:

- executable Verify/FIX_VERIFIED authority in R1;
- remote/Streamable HTTP MCP support;
- autonomous exploitation or production pentesting;
- general Security Memory implementation;
- autonomous Research/Learning promotion;
- universal CPG or universal provider posture;
- independent tamper-proof/non-truncation guarantees from a local unauthenticated hash chain;
- that green CI alone proves repository governance.

## Final verdict

**PASS_READY_FOR_CANONICAL_MERGE**

R1 execution closeout passed the required workspace, lint, adversarial, secret-persistence, credential-boundary, dependency/source, benchmark, and live protected-main governance gates against the recorded canonical baseline. T087 becomes complete only after this evidence document is exact-head qualified, merged to protected `main`, and followed by the canonical checkbox closeout.
