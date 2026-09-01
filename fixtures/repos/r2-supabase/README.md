# R2 Supabase Fixture Matrix

These repositories are synthetic, offline ground-truth inputs for R2. They are data only: no fixture is authorized to execute SQL, Supabase tooling, package managers, Edge Functions, hooks, or network access.

## Matrix

| Class | Repository | Ground truth |
|---|---|---|
| positive | `positive/safe-posture` | RLS enabled, restrictive policies, bounded grants, pinned SECURITY DEFINER search_path, Storage policy, JWT verification enabled, low-authority browser key reference, elevated server and Edge Function key references that are not client-boundary misuse |
| negative | `negative/unsafe-posture` | RLS disabled/widened, broad grants, widened policy, unpinned SECURITY DEFINER search_path, permissive Storage policy, JWT verification disabled without replacement auth, elevated client key canary |
| adversarial | `adversarial/uncertain-posture` | malformed SQL, dynamic SQL, ambiguous migration order keys, malformed config, dynamic Edge auth, synthetic secret canaries, and a declared oversized-input case |
| adversarial | `adversarial/unsupported-syntax` | unsupported security-relevant dynamic SQL that must remain visible as unsupported coverage rather than a clean posture |
| adversarial | `adversarial/hostile-repository` | prompt/instruction text and repository helper configuration that remain untrusted data and must never authorize target execution |

## R2-T027 E2E command matrix

The CLI E2E matrix treats the repositories above as inert bytes and paths and proves deterministic `review` and `init` output for five ground-truth classes: safe, vulnerable, contradictory/unknown, unsupported syntax, and hostile repository. `explain` determinism is exercised when the fixture produces an already-canonical Finding; fixtures that deliberately produce no Finding have no explain target. Provider registration remains Evidence/Coverage-only and cannot mint a Finding.

## Adversarial oversized-input contract

`adversarial/uncertain-posture/fixture.toml` declares an oversized SQL case by requested byte length rather than committing a large inert blob before R2-T006 freezes parser byte caps. The R2 benchmark harness may materialize the deterministic repeated comment payload in memory only after the parser cap is canonical. Until then this case is ground-truth metadata and MUST NOT be interpreted as a parser PASS.

## Secret canary contract

All canary values are synthetic strings containing `SENTRDEL_CANARY` and are not usable credentials. They exist only to prove classification/redaction boundaries. Persistent evidence must never retain the full canary value.
