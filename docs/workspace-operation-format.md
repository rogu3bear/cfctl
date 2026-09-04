# Workspace operation contract v2 (proposed)

Status: **proposed**. This specifies the declarative format that replaces the
five application-named modules in `cfctl-cli`. Nothing implements it yet.

## Why

`CapabilityAuthorityScopeV1::WorkspaceOwned` exists and nothing uses it.
Operation packs already carry an application's *data* from a registered root,
but its *logic* is five Rust modules compiled into the CLI:

| module | lines |
|---|---|
| `workspace_d1_reply_admission` | 1,994 |
| `workspace_d1_migration` | 1,967 |
| `workspace_reply_subdomain_ingress` | 1,626 |
| `workspace_d1_evidence` | 1,167 |
| `workspace_d1_projection` | 826 |

`load_workspace_capability` (`crates/cfctl-cli/src/runtime/support.rs:189`)
calls them in a fixed sequence. Each is named for an application, so cfctl
cannot gain an operation without a cfctl release, and `CapabilityV1` carries
ten fields named for applications — two named for individual migrations.

## What the modules actually share

Despite the size difference, all five implement the same six extension points.
This is the seam, and it is what the format must express:

| extension point | what varies | what cfctl must keep |
|---|---|---|
| `load` | which pack, which id | root registration, clean HEAD, committed pack |
| `prepare_plan_target` | which fields become the target | plan construction, pinning, hashing |
| `local_artifact_paths` | which files bind into the plan | reading, hashing, symlink rejection |
| `validate_bound_plan` | which bindings must still hold | drift detection, fail-closed |
| `receipt_is_complete` | required keys, adapter name | journal, boundary accounting |
| `project_private_query_rows` | which columns may leave | redaction enforcement |

Everything in the right-hand column is authority. It stays in cfctl and is not
expressible in a pack. Everything in the middle column is application
knowledge and belongs in the owning repository.

## Not a kind enum

The obvious design — a `kind = "d1-migration"` field selecting one of five
generic implementations — reproduces today's problem with extra indirection.
The five modules do not differ by kind. They differ along four orthogonal
axes, and every existing operation is a point in that space:

| operation | mutates | compiled input | success proof | may leave the boundary |
|---|---|---|---|---|
| `d1-evidence-read` | no | no | row shape | declared projection |
| `inbound-acceptance-read` | no | no | row shape | declared projection |
| `d1-migrations-apply` | yes | no | assertion rows | counts only |
| `d1-policy-project` | yes | no | digest readback | digests only |
| `reply-admission-activate` | yes | yes (Bun, pinned) | cardinality + digest | nothing |

A format that declares the axes admits combinations no module implements today
without cfctl changing. A kind enum admits exactly five.

## The format

One schema, `schema_version = 2`, in `.cfctl/operations/*.toml`. The four
existing files keep their names; the schema is shared, so a pack's filename
stops carrying meaning.

```toml
schema_version = 2

[[operation]]
id = "star-maildesk-cf.d1-policy-project"
title = "Activate one private Maildesk policy revision"
description = "..."

  # ---- substrate: what this runs against ----
  [operation.substrate]
  adapter = "d1"
  config_template = "wrangler.mail-router.toml"
  production_config = "wrangler.mail-router.production.toml"
  database_binding = "DB"
  tool = "wrangler"
  tool_version = "4.110.0"

  # ---- effect: whether a plan is required, and what it may touch ----
  [operation.effect]
  mutates = true
  performs_on_call = false
  tables = ["alias_routes", "policy_projection_state"]

  # ---- input: what the caller may supply, and how it is validated ----
  [[operation.input]]
  name = "policy_sha256"
  type = "sha256"
  required = true

  # ---- verification: what proves the operation succeeded ----
  [operation.verification]
  strategy = "digest_readback"
  [[operation.verification.digest]]
  key = "active_policy_sha256"
  source = "input:policy_sha256"

  # ---- evidence: what the receipt must contain to count as complete ----
  [operation.evidence]
  adapter = "workspace_d1_policy_projection_v1"
  required_keys = ["route_count", "active_policy_sha256"]
  exact_keys = true

  # ---- projection: what may cross the boundary into evidence ----
  [operation.projection]
  columns = ["route_count", "active_policy_sha256"]
  raw_digest_columns = ["active_policy_sha256"]

  # ---- compensation ----
  [operation.compensation]
  recovery_capability_id = "d1-time-travel-get-bookmark"
  recovery_max_age_seconds = 600
  rollback_capability_id = "d1-restore-exact-bookmark"
```

A compiled input adds one block; nothing else changes:

```toml
  [operation.compiler]
  path = "scripts/reply-admission-receipt.ts"
  sha256 = "sha256:7402..."
  runtime = "bun"
  runtime_version = "1.3.14"
  runtime_sha256 = "sha256:e0c9..."
  input_contract = "maildesk_reply_admission_compiler_input_v1"
```

## Naming and versioning

- The type is `WorkspaceOperationContractV1` in `cfctl-catalog` — v1 of the
  *contract type*, carried in v2 of the *pack file*. The pack schema version
  and the contract type version are separate because a pack may gain fields
  without the contract changing.
- It is not `CapabilityV1`. A workspace operation resolves *into* a
  `CapabilityV1` through `CapabilityAuthorityScopeV1::WorkspaceOwned`; the ten
  application fields are what R28 removes once nothing reads them.
- `schema_version = 1` packs stay loadable until R26 completes, so a
  registered root is never broken by a cfctl upgrade it did not ask for.

## Verification strategies

Four, closed. A pack naming anything else fails to load.

| strategy | proves | used by |
|---|---|---|
| `row_shape` | the projection returned exactly the declared columns | evidence reads |
| `assertion_rows` | a declared query returned the expected row count | migrations |
| `digest_readback` | a declared state key equals a declared digest | policy projection |
| `cardinality_digest` | exactly N rows, and a declared digest matches | reply admission |

Adding a fifth is a cfctl change with tests, deliberately. That is the
difference between a closed vocabulary and a plugin surface: an operation
declares *which* proof applies, never *how* to prove it.

## What this does not do

- It does not let a registered root grant itself authority. Effect, risk,
  approval, and attestation stay catalog- and policy-owned.
- It does not accept SQL from the caller. The projection declaration bounds
  what may be read; cfctl builds the query.
- It does not make packs executable without registration, a clean HEAD, a
  committed pack, and pinned tool versions.

## Open questions for review

1. **`reply_subdomain_ingress` is not D1.** It projects zones and DNS and
   acquires an activation lock. Its substrate is `cloudflare`, not `d1`. Does
   `[operation.substrate] adapter` generalize cleanly, or does that operation
   want a separate contract type? R25 will not answer this — it migrates the
   D1 evidence read. This is the risk R26 carries.
2. **Locking.** `acquire_activation_target_lock` has no declarative analogue
   above. Proposal: `[operation.concurrency] lock = "target"` — but only one
   operation needs it, so it may belong in cfctl unconditionally.
3. **`is_unperformed_fresh_precondition_failure`.** Distinguishing "did not
   happen" from "happened and failed" is boundary accounting, so it should be
   cfctl-owned — but today it is per-module. Confirm it is genuinely generic
   before deleting the module.

## Gate

R25 migrates `workspace_d1_evidence` first: 1,167 lines, already
contract-driven, `row_shape` verification. **If this format cannot express
that case, stop and revise here rather than during R26's 1,994-line module.**
