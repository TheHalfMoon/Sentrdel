# Repository Governance — Protected `main`

**Task:** T092  
**Status:** `LIVE_ENFORCEMENT_VERIFIED`  
**Repository:** `TheHalfMoon/Sentrdel`  
**Canonical main at verification:** `673e6fac9e2511c536fd003ab52b637012595082`  
**Live state inspected:** 2026-08-28

## 1. Truth rule

GitHub Actions success is not branch protection. T092 is complete only when live GitHub enforcement is independently verified against the canonical policy.

## 2. Stable canonical checks

The exact required check contexts are:

1. `Rust 1.98 bootstrap`
2. `Dependency security`
3. `Resolve and test schema substrate`

The branch-summary API binds all three checks to GitHub Actions app id `15368` and reports enforcement level `everyone`.

## 3. Canonical `main` policy

The machine-readable desired policy is `docs/security/repository-governance-policy.json`.

Required semantics:

- changes reach `main` through pull requests;
- required status checks are strict/up-to-date;
- all three stable canonical checks are required;
- all review conversations must be resolved;
- administrator enforcement is enabled;
- force pushes are disabled;
- branch deletion is disabled;
- merge commits remain allowed; linear history is not required;
- no bypass actor is declared;
- required approving review count is zero because the repository is currently founder-owned/operated. This is a documented governance limitation, not an independent-review claim.

Equivalent classic branch-protection semantics are:

```json
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Rust 1.98 bootstrap",
      "Dependency security",
      "Resolve and test schema substrate"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "dismiss_stale_reviews": false,
    "require_code_owner_reviews": false,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "required_conversation_resolution": true,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "allow_fork_syncing": false
}
```

A repository ruleset may provide equivalent-or-stronger semantics, but no active repository ruleset existed at the final T092 verification.

## 4. Live branch-summary evidence

At canonical `main` `673e6fac9e2511c536fd003ab52b637012595082`, GitHub reported:

```text
branch: main
protected: true
protection.enabled: true
required_status_checks.enforcement_level: everyone
required_status_checks.contexts:
  - Rust 1.98 bootstrap
  - Dependency security
  - Resolve and test schema substrate
```

The repository rulesets collection reported:

```json
[]
```

Therefore the visible enforcement is classic branch protection rather than a repository ruleset.

## 5. Bounded behavioral evidence

### 5.1 Strict / up-to-date — PR #38

Probe head: `c2b5213691e899397f899a798f1542eb71b28a22`.

All three exact-head canonical workflows succeeded:

- Bootstrap CI run `33182298455`
- Self Security run `33182298480`
- Schema Lock Qualification run `33182298392`

After all checks passed, GitHub still reported `mergeable_state: behind` because the probe branch was stale relative to protected `main`. PR #38 was closed without merge.

### 5.2 Conversation resolution — PR #39

Probe head: `20e052a38cbcddecac894ac989765284d0c356bf`.

All three exact-head canonical workflows succeeded:

- Bootstrap CI run `33182479339`
- Self Security run `33182479376`
- Schema Lock Qualification run `33182479401`

With one unresolved inline thread, GitHub reported `mergeable_state: blocked`. After resolving exactly that thread with no content change, GitHub reported `mergeable_state: clean`. PR #39 was closed without merge.

### 5.3 Pull-request boundary

A direct protected-`main` contents write was rejected by GitHub with:

```text
Changes must be made through a pull request. 3 of 3 required status checks are expected.
```

No canonical content was changed by that rejected request.

## 6. Canonical verifier

The final verification used repository secret `SENTRDEL_GOVERNANCE_ADMIN_TOKEN` only as a masked read-only credential. The temporary verification workflow never persisted the token, never used it for repository mutation, and was removed from its non-canonical probe branch after execution.

Verification-only workflow run:

- run: `33184911696`
- exact probe head: `f4600adbb911db1271885d8d2aa930ab124ff2ca`
- canonical `main` verified: `673e6fac9e2511c536fd003ab52b637012595082`

`scripts/verify_repository_governance.py` produced:

```text
repository-governance: PASS
repository=TheHalfMoon/Sentrdel
branch=main
head=673e6fac9e2511c536fd003ab52b637012595082
required_checks=Dependency security,Resolve and test schema substrate,Rust 1.98 bootstrap
active_repository_rulesets=0
```

The verifier checks the authoritative detailed branch-protection response and fails closed unless all canonical fields match, including:

- protected `main`;
- exact required checks;
- strict/up-to-date status checks;
- administrator enforcement;
- pull requests required before merge;
- required approving review count `0`;
- required conversation resolution;
- force pushes disabled;
- deletion disabled;
- canonical merge-commit workflow not contradicted by required linear history;
- active repository ruleset count recorded.

## 7. T092 close criteria

All required T092 criteria are now proven:

- canonical `main` SHA captured — **PASS**;
- `main` protected — **PASS**;
- policy targets `main` — **PASS**;
- pull requests required — **PASS**;
- exact three required checks — **PASS**;
- strict/up-to-date checking — **PASS**;
- conversation resolution required — **PASS**;
- administrator enforcement — **PASS**;
- force pushes disabled — **PASS**;
- branch deletion disabled — **PASS**;
- enforcement active — **PASS**;
- no active contradictory repository ruleset — **PASS**;
- canonical administrator-readable verifier — **PASS**.

## 8. Limitations and non-claims

- T092 does not claim independent human review while required approving review count is zero.
- T092 does not add release signing, artifact attestation, CODEOWNERS, environment protection, or organization-wide governance.
- The verification credential is not a product runtime dependency and is not available to ordinary Sentrdel execution.
- CI success by itself is still not branch protection; the PASS above is based on live protected-branch verification.

## 9. Gate consequence

T092 is technically satisfied by live repository evidence. The task checkbox is closed in the same exact-head closeout change. After that closeout change passes protected-main CI, merges with expected-head protection, and the post-merge canonical `main` remains protected, the Evaluation Gate is satisfied and Phase 3/T037 may begin.
