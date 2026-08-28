# T095 Schema / Implementation Deferral Notes

T095 deliberately defines authority semantics without adding a runtime wire schema.

A future task that introduces persisted `ContextProvenance`, `SecurityMemory`, feedback, or candidate-learning objects must:

1. define the owning typed Rust schema and generated JSON Schema under the then-current schema version;
2. preserve the authority ceiling in `context-learning-authority.md`;
3. prove unknown authority-bearing fields fail closed;
4. keep authority capabilities non-deserializable from untrusted payloads;
5. add migration/versioning rules before persistence;
6. add adversarial tests before enabling behavior.

Creating placeholder runtime structs during T095 would imply implementation breadth that the canonical task explicitly defers, so no such structs are introduced here.
