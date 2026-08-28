# Repository Governance — Protected `main`

**Task:** T092  
**Status:** `CONFIGURATION_PENDING_LIVE_ENFORCEMENT`  
**Repository:** `TheHalfMoon/Sentrdel`  
**Canonical base inspected:** `7453d9302814f63c02003d9fde8bf33a9dbee1af`  
**Live state inspected:** 2026-08-28

## 1. Truth rule

GitHub Actions success is not branch protection.

T092 is complete only when the live GitHub repository reports an enforced protection/ruleset for `main` that requires the canonical stable checks described below. A checked-in policy document, CI workflow, successful PR, or maintainer convention is not a substitute for live repository enforcement.

## 2. Live state at this record

The live GitHub branch API reported:

```text
branch: main
head: 7453d9302814f63c02003d9fde8bf33a9dbee1af
protected: false
protection.enabled: false
required_status_checks.enforcement_level: off
required_status_checks.contexts: []
```

The live repository rulesets collection reported:

```json
[]
```

Therefore the repository is **UNPROTECTED** at this record. T092 MUST remain unchecked until a post-configuration live read proves otherwise.

The authenticated repository owner has `admin` permission. The connected GitHub operation surface used for this implementation exposes reads for branch protection/rulesets but does not expose a branch-protection/ruleset mutation operation. That tool limitation does not change the required GitHub state and MUST NOT be represented as task completion.

## 3. Stable canonical checks

Before live protection is activated, T092 removes path filtering from `Schema Lock Qualification` so all canonical merge checks have stable PR contexts.

The required check contexts are exactly:

1. `Rust 1.98 bootstrap`
   - workflow: `Bootstrap CI`
   - proves pinned Rust 1.98 format/check/test/clippy qualification.
2. `Dependency security`
   - workflow: `Self Security`
   - proves checksum-pinned self-security tools, locked dependency metadata, privileged-surface declarations, `cargo-audit`, and `cargo-deny`.
3. `Resolve and test schema substrate`
   - workflow: `Schema Lock Qualification`
   - now runs on every PR so a required check cannot remain absent merely because a path filter did not match.
   - proves locked dependency tree, workspace semantic qualification, public schema generation/lock, and committed schema-source formatting.

A future rename of any required job/check is a governance change: protection must be updated atomically or before the rename is merged so `main` is not left with a missing or stale required context.

## 4. Required `main` policy

The machine-readable desired policy is `docs/security/repository-governance-policy.json`.

The intended enforcement is:

- changes reach `main` through pull requests;
- required branches must be up to date before merge (`strict` status checks);
- all three stable canonical checks above are required;
- all review conversations must be resolved;
- administrator enforcement is enabled;
- force pushes are disabled;
- branch deletion is disabled;
- merge commits remain allowed (linear history is not required);
- no bypass actor is declared;
- T092 does not require a second-person approval because the repository is currently founder-owned/operated; this is a documented governance limitation, not an approval claim.

## 5. Why approval count is zero

A pull request boundary and required checks are mandatory, but T092 does not invent an independent reviewer who does not exist. Setting a required approval count of one in a single-maintainer repository can create an unusable self-approval deadlock and would not prove independent security review.

When a genuinely independent maintainer/reviewer role exists, repository governance SHOULD raise the required approval count and may add CODEOWNERS/restricted merge authority through an ordinary governance change.

Until then, the truthful guarantee is automated required checks + PR boundary + resolved conversations + administrator enforcement, not independent human approval.

## 6. Exact activation target

An administrator applying classic branch protection can use an equivalent GitHub API policy for `main` with:

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

A repository ruleset MAY implement equivalent-or-stronger semantics instead. If a ruleset is used, the final evidence MUST record its ruleset ID/name, enforcement state, branch target, bypass actors, and required check identities rather than claiming classic branch protection.

## 7. Post-configuration proof required to close T092

Before changing T092 to `[x]`, capture live GitHub evidence after configuration and verify all of the following:

- canonical `main` SHA at verification;
- `main` is protected by branch protection or an active ruleset;
- the rule actually targets `main`;
- pull requests are required before merge;
- the exact three required check contexts are enforced;
- strict/up-to-date status checking is enabled;
- conversation resolution is required;
- force pushes are denied;
- branch deletion is denied;
- administrator/bypass behavior matches the documented policy;
- the enforcement is active, not disabled/evaluate-only;
- no contradictory ruleset or branch-policy exception silently bypasses the rule.

Then run `scripts/verify_repository_governance.py` with an administrator-capable GitHub token and record its PASS output plus the live API evidence in this document/PR before closeout.

## 8. Limitations and non-claims

- This document does not itself protect `main`.
- A successful workflow run does not protect `main`.
- The current checked-in desired policy is not proof that GitHub accepted or enforces it.
- T092 does not claim independent human review while the required approval count is zero.
- T092 does not add release signing, artifact attestation, CODEOWNERS, environment protection, or organization-wide governance; later release-hardening tasks may strengthen those areas.
- Direct pushes remain technically possible until the live protection/ruleset is activated.

## 9. Gate consequence

The Evaluation Gate Checkpoint requires T092 and T095. T095 may be complete independently, but **Phase 3 T037 MUST NOT start while this document still reports `CONFIGURATION_PENDING_LIVE_ENFORCEMENT` or while live GitHub reports `main` unprotected.**
