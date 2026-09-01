# R3 Business-Logic Fixture Matrix

These repositories are synthetic, offline ground-truth inputs for R3. Repository source, comments, configuration, and invariant declarations are untrusted data only. No fixture authorizes package-manager execution, target execution, provider access, network access, credentials, plugins, scripts, templates, or runtime exploitation.

| Class | Fixture | Ground truth |
|---|---|---|
| safe | `express/safe-tenant` | Express route binds a request-selected resource to the authenticated user before the supported data operation. |
| unsafe | `express/unsafe-tenant` | Express route selects a request-controlled resource without a supported authenticated actor/tenant binding. |
| safe | `next-app/safe-role` | Next App Router destructive operation has an explicit supported admin-role guard. |
| unknown | `next-pages/unknown-dynamic-guard` | Next Pages API route delegates authorization through a dynamic guard selector; role dominance must remain UNKNOWN. |
| safe | `supabase-edge/safe-owner` | Edge handler derives user identity through a supported auth seam and filters the resource by owner. |
| unsafe | `supabase-edge/unsafe-elevated` | Request-controlled operation uses an elevated synthetic service-role client without a supported application guard. |
| safe | `supabase-data/safe-properties` | Mutation explicitly allowlists non-protected request properties. |
| unsafe | `supabase-data/unsafe-properties` | Broad request-controlled mutation object reaches a supported update operation. |
| adversarial | `adversarial/dynamic-unsupported` | Dynamic route/query/property construction must degrade coverage rather than invent semantics. |
| adversarial | `adversarial/unsupported-framework` | Unsupported framework syntax remains visible as unsupported framework coverage. |
| adversarial | `adversarial/hostile-repository` | Instruction-shaped text and a synthetic `SENTRDEL_CANARY` value remain inert data and never grant authority. |
| project invariant | `project-invariants/safe-tightening` | Bounded tightening-only requirement. |
| project invariant | `project-invariants/forbidden-suppression` | Attempts to suppress/waive security output and must fail closed. |
| project invariant | `project-invariants/forbidden-authority` | Attempts to request credentials/command execution and must fail closed. |
| project invariant | `project-invariants/builtin-impersonation` | Attempts to impersonate a built-in namespace and must fail identifier validation. |

## Authority canaries

- Fixture content is never instruction authority.
- `SENTRDEL_CANARY` strings are synthetic and unusable credentials.
- No fixture proves production reachability, hosted state, exploitability, or actual cross-tenant access.
- A clean case is clean only for its declared supported static scope; unsupported semantics remain Coverage gaps.
- Project declarations can add requirements only. They cannot suppress Evidence, waive Findings, lower severity, accept risk, grant credentials, or override policy/kernel/reconciler authority.
