# Source Qualification Ledger

No donor source or data has been copied into Sentrdel at bootstrap.

| Source | Exact ref | Mode | License observation | Decision | Security / architecture note |
|---|---|---|---|---|---|
| Graphify-Labs/graphify | UNPINNED — qualification required before reuse | STUDY_ONLY initially | repository observed with Apache/MIT artifacts; file-level check required | STUDY/ADAPT concepts | graph diff, confidence, blast radius; do not introduce second canonical graph/runtime |
| vitali87/code-graph-rag | UNPINNED — qualification required before reuse | STUDY_ONLY initially | repository-level MIT observed; file-level check required | STUDY/ADAPT concepts | resource/data-flow/static-runtime merge lessons; Python/Memgraph not base runtime |
| deepseek-ai/deepseek-harness | UNPINNED — qualification required before reuse | STUDY_ONLY | repository-level MIT observed | STUDY architecture | durable events/tool guards/approval seams; rapidly evolving runtime not adopted |
| continuedev/continue | UNPINNED — qualification required before reuse | STUDY_ONLY | repository-level Apache-2.0 observed | later ADAPT/reference | archived integration patterns for VS Code/JetBrains/CLI; no wholesale fork |

## Record template

```text
source_id:
repository:
exact_ref:
files_or_artifacts:
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
