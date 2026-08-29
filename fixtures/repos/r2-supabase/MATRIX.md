# R2 Supabase Fixture Matrix

These repositories are inert test fixtures. Sentrdel must parse them as repository evidence only. Nothing here authorizes SQL execution, provider access, network access, or persistence of secret material.

| Class | Fixture | Coverage intent |
|---|---|---|
| positive | `positive/rls-and-policy` | RLS enabled with bounded policy and grants |
| positive | `positive/security-definer-safe` | SECURITY DEFINER with explicit safe search_path |
| positive | `positive/storage-policy` | Storage authorization policy evidence |
| positive | `positive/edge-auth` | Edge Function with explicit authorization pattern |
| negative | `negative/rls-disabled` | API-facing table with RLS disabled |
| negative | `negative/security-definer-search-path` | SECURITY DEFINER without bounded search_path |
| negative | `negative/key-in-client` | elevated key material placed in client context as canary text |
| negative | `negative/edge-auth-disabled` | Edge Function auth verification disabled without replacement evidence |
| adversarial | `adversarial/malformed-sql` | malformed SQL must degrade coverage |
| adversarial | `adversarial/dynamic-sql` | dynamic SQL must never be executed or semantically invented |
| adversarial | `adversarial/ambiguous-order` | duplicate migration order key must be rejected as ambiguous |
| adversarial | `adversarial/oversized-marker` | synthetic oversize marker for bounded-cap tests |
| adversarial | `adversarial/secret-canary` | redaction canaries must never survive persistence boundaries |

The fixture names define ground-truth intent only. Release-gating expectations belong to R2-T004 and later evaluation tasks.
