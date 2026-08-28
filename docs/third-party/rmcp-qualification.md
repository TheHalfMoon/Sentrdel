# RMCP 3.1.4 Qualification for T050

Status: `QUALIFIED_PROTOCOL_MODEL_REFERENCE_ONLY`

## Qualified source

- Repository: `modelcontextprotocol/rust-sdk`
- Package: `rmcp`
- Version: `3.1.4`
- Tag: `rmcp-v3.1.4`
- Annotated tag object: `2b7ea69be1701fd39de53161055212c4041ebf06`
- Exact release commit: `4a738b9dd99eaca418b614afa433a0cbdaf8d056`
- Upstream license: `Apache-2.0`
- Upstream minimum Rust: `1.88`
- Qualification date: `2026-08-29`

## Qualified scope

T050 qualifies RMCP only as an exact-version protocol/model reference. Sentrdel does not delegate its hostile stdio framing, buffering, protocol-version admission, child-process environment, policy, or authority boundaries to SDK transport defaults.

The qualified `rmcp 3.1.4` model surface records these known protocol revisions at the release commit:

- `2024-11-05`
- `2025-03-26`
- `2025-06-18`
- `2025-11-25`
- `2026-07-28`

Sentrdel mirrors that set as an explicit allowlist in `crates/sentrdel-guard/src/mcp/protocol.rs`. Unknown future revisions and symbolic `LATEST` values fail closed. Updating this set requires a new qualification delta and tests.

## Transport and feature boundary

T050 intentionally does **not** add the RMCP crate to the Sentrdel build graph. This is a security boundary, not an omission: the R1 framing path must remain Sentrdel-owned, and no SDK transport feature is required to implement or verify it. A later task may introduce exact RMCP model types only after the dependency/feature closure is independently qualified and lockfile-governed.

Not admitted by T050:

- `transport-streamable-http-*`
- `server-side-http`
- `reqwest` or authentication features
- `transport-child-process`
- RMCP stdio/async framing as the Sentrdel hostile-input boundary
- default feature activation, including macros/server transport conveniences
- SDK `Default`/`LATEST` semantics as protocol authority

## Security rationale

The upstream 3.x line is actively maintained and supports the modern MCP protocol model, but transport defaults are not a sufficient security boundary for Sentrdel. Historical review identified HTTP DNS-rebinding concerns and stdio buffering risk; T050 therefore keeps remote/Streamable HTTP out of R1 and implements explicit byte limits before JSON/policy processing.

The qualified upstream source itself has normal async/runtime dependencies even with optional transport features disabled. Because T050 does not add it to the build graph, no new transitive build script, proc-macro, native, network, credential, or artifact-download authority is admitted by this task.

## Update policy

Any RMCP version change, dependency introduction, feature activation, transport use, or protocol-version expansion requires:

1. exact upstream ref/version qualification;
2. lockfile diff review;
3. privileged dependency-surface review under `docs/security/dependency-policy.md`;
4. exact-head canonical CI;
5. adversarial framing/version regression tests.
