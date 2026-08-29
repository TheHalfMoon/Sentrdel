# Quickstart: R2 Supabase Static Posture Development

This is a contributor/developer quickstart for the R2 implementation lifecycle. It does not authorize bypassing task order or running target Supabase/Postgres tooling.

## Preconditions

- Read `.specify/memory/constitution.md`, `AGENTS.md`, this R2 spec/plan/contracts/tasks, and `docs/security/dependency-policy.md`.
- Confirm R2-T001 is canonical complete before product implementation.
- Use exact Rust 1.98.0 and the committed lockfile.
- Work from current protected `main` on a fresh task branch.

## Canonical local validation

```bash
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 check --workspace --all-targets --locked
cargo +1.98.0 test --workspace --locked
cargo +1.98.0 clippy --workspace --all-targets --locked -- -D warnings
```

These commands run only against the trusted Sentrdel workspace. Do not redirect them to arbitrary target repositories.

## R2 target-repository rule

Treat fixture/target repositories as bytes and paths only. Do not run:

```text
supabase ...
psql ...
postgres ...
docker compose ...
npm/pnpm/yarn ...
cargo ...        # inside a target repository
migration scripts
Edge Functions
repository hooks/helpers
```

R2 SQL analysis must use the Sentrdel-owned bounded parser/state reducer.

## Fixture workflow

Add synthetic fixtures under:

```text
fixtures/repos/r2-supabase/
```

Fixtures must contain no real credentials or production data. Secret/key tests use synthetic canaries and assert that persistent Evidence/log/store output is redacted.

Each high-signal check needs:

- positive fixture;
- negative fixture;
- ambiguous/unsupported fixture where relevant;
- bounded/malformed adversarial case;
- deterministic replay assertion;
- coverage assertion;
- Evidence authority/provenance assertion.

## Static truth language

Good observation:

```text
RLS is disabled for relation public.accounts in repository-derived migration state.
```

Not allowed without live evidence:

```text
Production public.accounts has RLS disabled.
```

## Pull request discipline

Before merge:

- exact-head applicable CI must pass;
- no unresolved review thread may remain;
- changed files must match the task scope;
- merge uses expected-head protection;
- post-merge canonical `main` and protection are re-read before task closeout.

## Scope reminders

R2 is static Supabase posture. Live provider posture, cross-layer tenant/business-logic invariants, automatic remediation, and execution verification remain outside this slice.
