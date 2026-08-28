# Repository Governance — Protected `main`

**Task:** T092  
**Status:** `LIVE_ACTIVATION_DETECTED_VERIFICATION_PENDING`  
**Repository:** `TheHalfMoon/Sentrdel`  
**Canonical main at latest live verification:** `656bd308219fbe3ff9846ed437465dda2bfb0f59`  
**Live state inspected:** 2026-08-28

## 1. Truth rule

GitHub Actions success is not branch protection.

T092 is complete only when the live GitHub repository reports an enforced protection/ruleset for `main` that satisfies the canonical policy below and the post-configuration verifier/evidence requirements are complete. A checked-in policy document, CI workflow, successful PR, maintainer convention, or partial API summary is not a substitute for complete live repository enforcement evidence.

## 2. Latest live state

After administrator activation and the evidence-record merge in PR #37, the live GitHub branch API reports:

```text
branch: main
head: 656bd308219fbe3ff9846ed437465dda2bfb0f59
protected: true
protection.enabled: true
required_status_checks.enforcement_level: everyone
required_status_checks.contexts:
  - Rust 1.98 bootstrap
  - Dependency security
  - Resolve and test schema substrate
```

The same response binds each required check to GitHub Actions app id `15368`.

The live repository rulesets collection reports:

```json
[]
```

Therefore classic branch protection is **LIVE and ACTIVE** for `main`, and the three canonical required check identities are visible and enforced at the branch summary surface.

The connected GitHub App still receives `403 Resource not accessible by integration` from the detailed branch-protection endpoint and its subresources. T092 remains unchecked until all required closeout fields are independently proven and the canonical verifier requirement is satisfied.

## 3. Stable canonical checks

The required check contexts are exactly:

1. `Rust 1.98 bootstrap`
   - workflow: `Bootstrap CI`
   - proves pinned Rust 1.98 format/check/test/clippy qualification.
2. `Dependency security`
   - workflow: `Self Security`
   - proves checksum-pinned self-security tools, locked dependency metadata, privileged-surface declarations, `cargo-audit`, and `cargo-deny`.
3. `Resolve and test schema substrate`
   - workflow: `Schema Lock Qualification`
   - runs on every PR so a required check cannot remain absent merely because a path filter did not match.
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

## 7. Bounded behavioral enforcement probes

Because the detailed protection endpoint is not readable from the connected GitHub App, T092 used non-destructive, non-merge PR probes to verify policy behavior that can be observed safely without mutating protected `main`.

### 7.1 Strict / up-to-date enforcement — PR #38

PR #38 was created from intentionally stale base commit `d17e69fcb410051d3861e7de1431391abd48f0d0` after canonical `main` had advanced to `656bd308219fbe3ff9846ed437465dda2bfb0f59`.

Probe head: `c2b5213691e899397f899a798f1542eb71b28a22`.

All three exact-head canonical workflows completed successfully:

- Bootstrap CI run `33182298455`: SUCCESS
- Self Security run `33182298480`: SUCCESS
- Schema Lock Qualification run `33182298392`: SUCCESS

After all required checks succeeded, GitHub reported:

```text
mergeable: true
mergeable_state: behind
```

Therefore the stale PR remained blocked specifically because it was behind protected `main`. This is bounded behavioral evidence that strict/up-to-date enforcement is active.

PR #38 was then closed without merge.

### 7.2 Conversation resolution enforcement — PR #39

PR #39 was created from current canonical `main` and contained one intentionally unresolved inline review thread.

Probe head: `20e052a38cbcddecac894ac989765284d0c356bf`.

All three exact-head canonical workflows completed successfully:

- Bootstrap CI run `33182479339`: SUCCESS
- Self Security run `33182479376`: SUCCESS
- Schema Lock Qualification run `33182479401`: SUCCESS

With the review thread unresolved, GitHub reported:

```text
mergeable: true
mergeable_state: blocked
```

The review-thread API independently reported the probe thread as `is_resolved: false`.

After resolving exactly that thread and changing no repository content, GitHub reported:

```text
mergeable: true
mergeable_state: clean
```

Therefore the unresolved review conversation was the active merge blocker and resolving it cleared the block. This is bounded behavioral evidence that required conversation resolution is active.

PR #39 was then closed without merge.

### 7.3 Probe safety

Neither probe was merged. Neither probe attempted direct writes to `main`, force-pushes, branch deletion, history rewriting, or any destructive action. Probe files remain only on their non-canonical branches.

A destructive behavioral test is not an acceptable substitute for authoritative configuration evidence. In particular, T092 will not attempt a direct push merely to see whether pull-request enforcement rejects it, and will not attempt force-pushing or deleting `main` merely to test whether GitHub blocks the action.

## 8. Post-configuration proof required to close T092

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

Current evidence proves active protection, the exact required checks, strict/up-to-date behavior, and conversation-resolution behavior. It does **not** eliminate the need for authoritative evidence for the remaining fields.

Then run `scripts/verify_repository_governance.py` with an administrator-capable GitHub token and record its PASS output plus the live API evidence in this document/PR before closeout. The current execution environment has no administrator-capable GitHub token and the connected GitHub App cannot read the detailed protection endpoint, so this verifier has **not** been represented as PASS.

## 9. Current verification boundary

Verified live or by bounded non-destructive behavior:

- canonical `main` is `656bd308219fbe3ff9846ed437465dda2bfb0f59` at this record;
- `main` reports `protected: true`;
- `protection.enabled: true`;
- required status-check enforcement reports `everyone`;
- the exact three canonical required checks are present;
- repository rulesets are empty, so the visible enforcement is classic branch protection rather than a repository ruleset;
- strict/up-to-date enforcement is active, proven by PR #38 remaining `behind` after all required checks passed;
- conversation resolution is active, proven by PR #39 moving from `blocked` with the unresolved thread to `clean` after that thread was resolved;
- the owner-authored PR #39 was subject to the conversation-resolution block, demonstrating that the ordinary owner merge path did not bypass that rule.

Still not independently verified from the current execution surface:

- authoritative pull-request-before-merge/direct-push configuration;
- complete administrator/bypass configuration beyond the observed owner PR behavior and branch-summary enforcement level;
- force-push policy;
- deletion policy;
- fork-sync setting;
- administrator-token verifier PASS.

No destructive behavioral probe will be used for the unresolved fields. A failed read is a verification gap, not evidence that a policy is absent or present.

## 10. Limitations and non-claims

- This document does not itself protect `main`.
- A successful workflow run does not by itself protect `main`.
- Bounded PR behavior proves the specific observed merge constraints but does not expose every underlying GitHub configuration field.
- The administrator-token verifier has not run PASS from this execution surface.
- T092 does not claim independent human review while the required approval count is zero.
- T092 does not add release signing, artifact attestation, CODEOWNERS, environment protection, or organization-wide governance; later release-hardening tasks may strengthen those areas.

## 11. Gate consequence

The Evaluation Gate Checkpoint requires T092 and T095. T095 may be complete independently, but **Phase 3 T037 MUST NOT start while T092 remains unchecked or while the complete post-configuration verification above is unresolved.**
