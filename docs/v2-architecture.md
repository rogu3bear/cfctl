# cfctl v2 architecture

`cfctl` v2 is a local-first, catalog-driven Cloudflare control plane. It has no MCP dependency.

## Crates

| Crate | Boundary |
|---|---|
| `cfctl-cli` | Public command parser, human/JSON rendering, orchestration |
| `cfctl-core` | Versioned contracts, hashes, evidence, redaction, plan lifecycle |
| `cfctl-auth` | OAuth PKCE, profiles, account selection, Keychain/Secret Service |
| `cfctl-cloudflare` | Schema-validated HTTP execution, retries, pagination, conditionals, and idempotency |
| `cfctl-catalog` | Official OpenAPI/docs/changelog/CLI ingestion and SQLite search index |
| `cfctl-planner` | Risk, impact, cost, and approval policy |
| `cfctl-workspace` | Registered-root Git/IaC discovery, exact local diffs, and repository/resource graph |
| `cfctl-agent` | Agent discovery, maintained instructions, recursion-safe handoff |
| `cfctl-storage` | Platform paths, atomic plans, locks, content-addressed evidence |
| `xtask` | Local verification, reproducible release assembly, publication |

## Adapter boundary

Every capability is classified as `native`, `dynamic_api`, `delegated_cli`, `governed_ui`, or `blocked`. The adapter is selected by catalog data; it is never inferred from model output.

- `native`: operation-specific behavior such as sink-only credential delivery.
- `dynamic_api`: schema-validated Cloudflare HTTP execution.
- `delegated_cli`: governed Wrangler/cloudflared process with a cleared environment, one selected credential, timeout, captured output, and redaction.
- `governed_ui`: target-bound `AgentActionV1` after API/CLI insufficiency is established.
- `blocked`: discoverable, with an exact missing permission, entitlement, cost, verification, or adapter reason.

Generated API writes are executable only when their operation contract is
complete. Reads remain dynamically executable; incomplete writes remain
searchable and explain every missing contract field.

OpenAPI parameter selectors resolve local `$ref` chains, homogeneous enum
values, and compatible value types carried through `allOf`, `oneOf`, or
`anyOf`. Schema-backed descriptions are retained, while empty, mixed, or
conflicting shapes stay explicitly `unknown`; normalization never guesses a
type from a parameter name.

Verification and automatic rollback strategies form a closed runtime set.
Catalog metadata must select a strategy that is implemented for the exact
operation identity and resource shape; a plausible but incompatible strategy
is contract debt, not execution authority. The adapter validates the verifier
again before network mutation to protect older or drifted plans.

## Workspace and transaction model

Workspace discovery never scans outside explicitly registered roots. It finds
configless Git repositories and parses Wrangler TOML/JSONC, Terraform, and
Pulumi files while excluding generated and vendor directories. The exact
supported representations are Wrangler TOML/JSON/JSONC, Terraform HCL/JSON,
and Pulumi YAML. Resource links
use canonical absolute repository paths, and every source-config snapshot
records the current hash, `HEAD` hash, exact worktree-diff hash, and dirty
status. Terraform and Pulumi resources also expose runtime identity links only
from literal, resource-type-specific properties; dynamic expressions and local
binding symbols never masquerade as Cloudflare identities. The supported-IaC
fixture matrix exercises all of those formats plus
staged, unstaged, and untracked state, duplicate repository basenames, and
cross-repository resource impact.

`PlanV1` carries a hash-chained transaction journal. Checkpoints distinguish
the point before a Cloudflare boundary from the persisted response, secret
sink, and operation-specific verification. A network failure after a boundary
attempt therefore enters rectification and cannot be mistaken for a safe
retry. Each checkpoint hash includes the plan status, and the storage boundary
validates the journal on both writes and reads. Adapter failures, missing
receipts, request-body cleanup failures, and missing sink-only outputs advance
through redacted response or sink artifacts instead of persisting a detached
status. The storage crash matrix drops volatile state and reopens the real local
store between each journal transition, proving recovery at every persisted
stage; it does not claim account-backed network mutation proof.

## Trust sequence

1. Pin profile and account.
2. Pin the derived executable-catalog hash while retaining the upstream OpenAPI source hash separately.
3. Read registered workspace impact.
4. Bind the request, permission lane, workspace graph, source-config hashes, official pricing references, cost metadata, and exact plan content hash.
5. Apply policy and, when required, approve that operation ID.
6. Acquire the local operation lock.
7. Recheck drift, append the consumption checkpoint, and durably consume the plan.
8. Append the boundary-attempt checkpoint and cross one adapter boundary.
9. Persist the response and secret sink, then run the operation-specific verifier.
10. Close verified/rejected transactions or require rectification without replay.
11. Write redacted, content-addressed evidence.

Apply, sink, and verification responses carry compact non-secret artifacts whose
hashes are part of their journal checkpoints. These mutable execution facts are
not part of the pre-execution approval hash, but they cannot be changed after
the boundary without invalidating the transaction chain. A supported rollback
uses them only to create a new compensation plan with independent authority.

## Executable guidance projection

The public explanation layer is a projection of the executable contracts, not
an independent architecture source. `cfctl-core` owns the typed
`CapabilityGuideV1` and versioned `GuideTopicDocumentV1` models. The CLI exposes
them through the compatible `cfctl guide <capability-id>` path and the additive
`cfctl guide --topic system|standing-authority` topics. Static topics do not
need a catalog refresh or network access.

The README and Quickstart embed canonical Markdown rendered from those topic
documents. Managed agent instructions route operators back to the same CLI
topics. `cargo xtask verify` compares each generated documentation section to
the core renderer byte-for-byte, so lifecycle facts cannot drift silently
between the executable behavior, human documentation, and agent guidance.

See [ADR 0001](architecture/adr/0001-rust-clean-break.md), [ADR 0002](architecture/adr/0002-risk-based-approval.md), and [ADR 0003](architecture/adr/0003-executable-guidance-projection.md).
