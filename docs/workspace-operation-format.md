# Workspace operation format: supported subset and retained typed contracts

The implemented generic carrier is a committed TOML document with
`schema_version = 2` and `contract = "workspace_operation_v1"` under
`.cfctl/operations`. It currently binds only a non-mutating D1 evidence read to
an existing typed Maildesk projection. It does not supply a generic verifier,
arbitrary SQL, a compiler runner, or a mutating operation.

`WorkspaceOperationContractV1` is defined and exported by `cfctl-core`
(`workspace_d1.rs`); `cfctl-catalog` re-exports it. The type version, pack schema,
capability schema, application declaration and runtime binding are separate
version axes. The runtime does not construct an unused instance of this public
contract as a substitute for validated source binding.

## Supported declaration

```toml
schema_version = 2
contract = "workspace_operation_v1"

[[operation]]
id = "star-maildesk-cf.d1-evidence-read"
title = "Read Maildesk D1 evidence"
description = "Read the complete compiler-owned body-free projection."

[operation.substrate]
adapter = "d1"
config_template = "wrangler.toml"
production_config = "wrangler.production.toml"
database_binding = "DB"
tool = "wrangler"
tool_version = "4.120.1"

[operation.effect]
mutates = false
performs_on_call = true

[operation.verification]
strategy = "row_shape"

[operation.projection]
name = "maildesk_v1"
```

This is a supported declaration shape, subject to the same registered source,
committed template, private config, database and tool checks as its typed
carrier. It is not provider execution or application acceptance evidence. The
other supported projection name is `maildesk_inbound_acceptance_v1`, bound to
its exact `star-maildesk-cf.inbound-acceptance-read` identity. Ordinary evidence
IDs retain the typed owner's namespace and `.d1-evidence-read` rules.

Every parsed field has a defined disposition:

| Field | Disposition at the current binder |
|---|---|
| `schema_version`, `contract` | Enforced format identity: exactly 2 and `workspace_operation_v1`. The discriminator claims the document even if its schema or selected semantics are unsupported; binding then refuses. |
| `operation.id` | Enforced unique identity, with the typed projection's existing ID predicate. Duplicate IDs cannot select the first declaration. |
| `title`, `description` | Descriptive metadata, validated by the typed owner. They grant no risk, cost, permission or acceptance authority. |
| `substrate.adapter` | Enforced: `d1`. Other adapters have no generic binder. |
| `config_template`, `production_config`, `database_binding`, `tool_version` | Enforced through the existing source/config/tool contract. Safe relative paths, committed template identity, exact database binding and the typed Wrangler-version predicate remain mandatory. |
| `substrate.tool` | Enforced when present: `wrangler`. Omission is the fixed compatibility spelling for that same tool, never ambient tool selection. |
| `effect.mutates` | Enforced: false. Generic writes remain refused. |
| `effect.performs_on_call` | Enforced: true, matching the read entrypoint. False or omission is refused. |
| `effect.tables` | Must be absent or empty. A caller table constraint is unsupported and cannot describe or narrow the fixed query. |
| `input` | Must be absent or empty. The typed owner supplies the exact selectors; custom inputs are unsupported. |
| `verification.strategy` | Enforced: `row_shape`, with the complete existing typed application predicates still mandatory. This spelling does not replace them with shape-only validation. |
| `verification.digest` | Must be absent or empty. Custom digest joins are unsupported. |
| `projection.name` | Enforced fixed typed projection identity. |
| `projection.columns` | Absent or empty selects the complete named projection. If populated, it must equal the exact complete typed row-column set with no duplicates; order is immaterial. A narrowed, enlarged or conflicting set is refused. |
| `projection.raw_digest_columns` | Must be absent or empty. Raw digest declarations are unsupported. |
| `evidence`, `compensation`, `compiler` | Unsupported blocks; their presence is refused, including empty blocks. They cannot introduce caller-authored receipt acceptance, recovery authority or executable code. |

For `maildesk_v1`, the exact row-column set is the union of the existing
`MAILDESK_D1_EVIDENCE_COLUMNS_V1`, `MAILDESK_D1_POLICY_IDENTITY_COLUMNS_V2` and
`MAILDESK_D1_ROUTE_HEALTH_COLUMNS_V2` contracts in `cfctl-workspace`. For inbound
acceptance it is `MAILDESK_INBOUND_ACCEPTANCE_COLUMNS_V1`. These bind the rows
before the existing typed, body-free reduction; they do not expose raw rows or
replace the public result types. Unknown fields are refused. Unsupported blocks
are rejected without interpreting their contents.

The earlier example fixture's `columns = ["active_policy_digest"]` was accepted
while returning a broader typed projection. That was a semantic bug. Such
narrowing now refuses; use the complete fixed projection rather than implying a
constraint the runtime cannot honor. No current generic pack was found in the
committed Maildesk, Founder or Sign source inventories inspected during this
repair. Their existing typed carriers remain unchanged; that observation is not
a claim about other repositories or future source revisions.

## Unique source ownership

`cfctl-workspace::operation_identity` owns routing. The CLI's
`workspace_capability_with_source` delegates to it. One lookup first discovers
committed identity claims across recognized generic and typed carriers, then
binds the unique selected owner. It does not run every binder and keep whichever
one succeeds. Missing private inputs or unsupported semantics cannot erase a
competing claim.

Zero claims is unknown. Multiple claims refuse with bounded source identities,
whether the duplicates are in one pack, separate files, different carrier
families or different registered repositories. Overlapping roots deduplicate the
same canonical repository, while repositories with the same basename remain
distinct. The independent provider catalog cannot shadow, or be shadowed by, a
workspace claim to the same public ID. Inspection, intent resolution, calls,
approval when a catalog is available, and execution retain that boundary.

Discovery reads committed source identities without private config intake,
unrelated compilers or unrelated dirty-execution checks. Existing exclusions and
no-follow discovery remain in force. An unrelated missing root and an unknown
ID retain their existing behavior. Results are ephemeral and revalidated at
consequential consumption; there is no persistent second source registry.

`Inspect` reads the selected committed pack even when the application worktree
is dirty. `Execute` requires its admitted clean source and exact current bytes.
An explicit `D1ReadSourceSelectionV1` may select the genuine linked checkout only
after its registered owner, Git common directory, origin, HEAD, tree and pack
join. It still requires unique identity in the registered and selected scopes;
each query rechecks registration and selected source. It cannot introduce an
unrelated clone or waive query/source drift.

A schema-2 document without this generic contract discriminator remains owned
by the appropriate typed schema. Typed migration packs retain their established
filename and format. A different filename does not create a second typed
migration loader.

## Shared mechanics and typed acceptance

The borrowed `D1ConfigSource` in `cfctl-workspace` carries source, template,
production-config, database-binding and tool identity. CLI
`workspace_d1_config`, `workspace_d1_execution` and `workspace_d1_recovery` own
private config binding, pinned process mechanics and authenticated recovery
joins respectively. All four D1 consumers use them. Reads do not construct a
migration contract or evaluate fake recovery fields. Captured private bytes are
bounded and hashed once; launch rechecks their identity and uses the existing
immutable private stage. A changed config cannot redirect a reviewed launch.

Migration-only manifest selection, exact ledger prefix/order, schema assertions,
recovery chronology, canary/qualification joins and production eligibility stay
in the migration owner. Projection counts/digests, reply identity and compiler
closure, route-health completeness, and inbound provider acceptance stay in
their typed owners. The [compatibility table](architecture.md#application-compatibility-and-removal-conditions)
names their consumers and removal conditions.

| Retained predicate | Required consumer-cutover evidence |
|---|---|
| One inbound match; fingerprint-derived delivery/relay IDs; exact route and policy | No match, multiple matches and wrong identity/route/policy all refuse. |
| Provider acceptance, positive recipients, complete accepted count, valid thread/time | Partial or zero acceptance and malformed values refuse. |
| Exact bounded, body-free fields | Extra/private/missing columns and invalid values refuse. |
| Complete active route inventory, unique references, policy equality and enabled routes | Partial, duplicate, wrong-policy, disabled and oversized inventories refuse. |
| Source/config/query/tool identity | Dirty, drifted, aliased and ambiguous authority refuses. |
| Dispatch accounting and no replay | Real transport/process and post-response failure fixtures retain the consumed identity and known receipt. |

## Non-executable proposals and history

`assertion_rows`, `digest_readback` and `cardinality_digest` remain parseable
verification vocabulary with no generic execution binder. Mutating axes,
compiled generic inputs, custom evidence and compensation declarations remain
refused. Earlier R25/R26/R28 sequencing labels and examples were proposals, not
approved work orders or implemented support. This repair does not introduce a
policy DSL, plugin system, generic SQL interface or verifier-by-name.

Application consumers must prove semantic equivalence and cut over before their
typed adapters or frozen legacy exceptions can be removed. Source extraction
alone does not complete that migration. Source compilation, local proof,
provider qualification, policy activation and production admission remain
distinct gates.
