# Source Qualification Ledger

No donor source or data has been copied into Sentrdel at bootstrap or in PR #3.

## Founder source-reuse authorization

On 2026-08-24 the founder stated that Sentrdel has permission from the discussed GitHub source owners to reuse their code in this open-source project. Sentrdel records that statement as `FOUNDER_ATTESTATION_2026-08-24` and treats donor reuse as authorized at the project-governance level.

The repository does **not** currently contain source-specific upstream permission evidence identifying each granting owner, exact ref/files, and reuse scope. Sentrdel will not invent that evidence. Until a donor's exact import is qualified, its row therefore remains `QUALIFICATION_PENDING` even though founder authorization exists. Before copied/ported code lands, the import record must bind the exact upstream repository/ref/files, founder attestation and any available source-specific permission reference, attribution/notices, upstream license expression, modifications, build/runtime authority, and security review.

| Source | Exact ref | Mode | License observation | Decision | Security / architecture note |
|---|---|---|---|---|---|
| actions/checkout | `11d5960a326750d5838078e36cf38b85af677262` (v4.4.0 release line) | CI_ACTION | repository action consumed by immutable commit SHA | ADOPT for bootstrap CI | `persist-credentials: false`; immutable pin avoids mutable-tag drift; this commit contains backported fork/`pull_request_target` checkout hardening |
| Graphify-Labs/graphify | UNPINNED — exact qualification required before import | FOUNDER_ATTESTED_DONOR | repository observed with Apache/MIT artifacts; file-level record still required | QUALIFICATION_PENDING / selective Rust port or source reuse | permission basis currently `FOUNDER_ATTESTATION_2026-08-24`; source-specific proof not stored; graph diff, confidence, blast radius; do not introduce a second canonical graph/runtime |
| vitali87/code-graph-rag | UNPINNED — exact qualification required before import | FOUNDER_ATTESTED_DONOR | repository-level MIT observed; file-level record still required | QUALIFICATION_PENDING / selective port or adapter | permission basis currently `FOUNDER_ATTESTATION_2026-08-24`; source-specific proof not stored; resource/data-flow/static-runtime merge is high-value; Python/Memgraph is not the Sentrdel trusted base runtime |
| deepseek-ai/deepseek-harness | UNPINNED — exact qualification required before import | FOUNDER_ATTESTED_DONOR | repository-level MIT observed | QUALIFICATION_PENDING / selective port | permission basis currently `FOUNDER_ATTESTATION_2026-08-24`; source-specific proof not stored; durable events/tool guards/approval seams; do not inherit the whole rapidly evolving agent runtime |
| continuedev/continue | UNPINNED — exact qualification required before import | FOUNDER_ATTESTED_DONOR | repository-level Apache-2.0 observed | QUALIFICATION_PENDING / integration-layer reuse | permission basis currently `FOUNDER_ATTESTATION_2026-08-24`; source-specific proof not stored; VS Code/JetBrains/CLI/diff plumbing may be reused selectively; no need for a wholesale product fork |

## Record template

```text
source_id:
repository:
exact_ref:
files_or_artifacts:
permission_basis:
source_specific_permission_reference:
license_expression:
notices:
integration_mode:
executes_at_build:
procedural_macro:
native_code:
downloads_artifacts:
security_notes:
maintenance_notes:
modifications:
qualified_by:
qualified_at:
```
