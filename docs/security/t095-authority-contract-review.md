# T095 Authority Contract Review

**Task:** T095  
**Contract:** `specs/001-v0-1-evidence-guard-foundation/contracts/context-learning-authority.md`  
**Canonical base:** `04407524aba98db30257f22fb6ceaf2f934d9a8b`

## Review result

The contract is intentionally implementation-free and freezes lower-authority boundaries before future memory/research/context features exist.

It preserves the existing R1 authority model:

- untrusted content can be read without becoming privileged instruction;
- repository policy remains narrowing-only;
- feedback and memory cannot mint FACT, OBSERVATION, or VERIFIED Evidence;
- LLM/model material remains limited to INFERENCE/HYPOTHESIS;
- only the reconciler creates Findings;
- kernel DENY remains absorbing;
- unknown/stale authority-sensitive context fails closed;
- candidate-generation code cannot access protected expected outputs or modify evaluator/holdout/kernel/reconciler/verification/release authority for the candidate it is helping judge;
- general-purpose Security Memory/Learning remains deferred.

## Non-implementation statement

No runtime memory store, learner, research agent, model training path, automatic suppression, automatic promotion, or trusted-core self-modification is introduced by T095.

Future implementing tasks must add adversarial tests for the properties enumerated in the contract and remain bound by the canonical Evidence/ASEL, policy, and evaluation contracts.
