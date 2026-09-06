# cfctl v2 operator runbook

## Launch support triage

Support starts from the operator's own redacted `ResultEnvelopeV2`. Never
request or accept credential values, callback values, account identifiers, or
private evidence in a support channel. Ask for the cfctl version, the error
code, and the redacted `next_step`; keep source proof, provider reads, plans,
applies, and verification receipts separate.

| Symptom | Safe response | Stop condition |
|---|---|---|
| The installed command and the checkout behave differently | Run `cfctl version --json` and `cfctl doctor --json`; invoke each candidate executable directly and compare its self-reported path, version, commit, and identity source. Reinstall only from an exact release asset whose checksum matches `SHA256SUMS`. | Do not repair the mismatch with a symlink, PATH shim, unverified binary, or release override. Unknown or dirty identity remains unhealthy. |
| No profile is selected, or the governed fallback store is active | Run `cfctl auth profiles --json`, select one existing account-pinned profile with `cfctl auth use <profile> --json`, then rerun `cfctl auth status --json`. An active fallback store is authoritative by design; use the explicit repair command only when the operator intentionally wants to test or restore the platform keyring. | Never ask the operator to paste a token, OAuth callback, global key, or fallback file. Do not broaden permissions merely to make the error disappear. |
| Evidence qualification reports an uninitialized or split platform authority | Run `cfctl auth evidence-key status --json`, then `cfctl auth evidence-key init-preview --json` before any first initialization. Initialize only when both the canonical state-root marker and direct platform registry are absent. `init` is resumable across its own interruption: it publishes a private intent naming the state root before creating the authority, so a registry left without its marker by process death is recognized on the next `init` and resumed forward by creating only the missing marker. Rotate explicitly; retire only an inactive generation after cfctl reports zero authenticated local artifacts. | Never use the credential fallback store for the evidence integrity key, recreate a missing half over existing state, or treat legacy unauthenticated proof rows as current qualification. A valid registry with no published intent is not resumable and must never be completed by hand-creating its marker; that is an unknown-provenance authority, not an interrupted initialization. |
| The exact sole canonical evidence registry is valid but its marker is absent | Run `cfctl auth evidence-key adopt-preview --json` for a strictly read-only classification. `adopt-plan current|status` remain read-only historical inspection and `adopt-plan revoke` may retire only a plan that never crossed. `adopt-plan create` and `adopt <plan-id> --yes` return `CFCTL_AUTH_INSTALLED_IDENTITY_RECEIPT_REQUIRED`; they do not persist a plan, create the marker, publish a crossing seal, or complete adoption. Signed publication and installation may proceed independently. | Do not pass raw source, artifact, architecture, CDHash, algorithm, or provenance claims as adoption authority. Wait for a separately reviewed authenticated installed-identity receipt producer and consumer. Do not hand-create the marker, initialize a replacement authority, edit Keychain state, or treat historical plan inspection as an adoption outcome. |
| A valid evidence registry has no marker, no resumable intent, and no authenticated artifacts | Confirm the classification with `cfctl auth evidence-key adopt-preview --json`; it must report `marker_present: false`, `initialized: true`, and zero authenticated descriptors and proofs. Then run `cfctl auth evidence-key reset --yes --json`. Reset discards that authority through the managed platform teardown and initializes a fresh one; it claims no lineage and no continuity with the discarded authority, so it needs no installed-identity receipt. | Never hand-delete the platform registry to reach this state. The keyring stores managed values as an inventory, generation manifest, and chunk set, so removing the root item alone orphans the chunks and corrupts the store. Never reset an authority with a present marker, more than one generation, or any authenticated artifact; rotate, retire, or stop instead. If a reset is interrupted mid-discard, reads report `platform keyring credential deletion is incomplete`; that is a resumable managed state, not corruption. Rerun the same `reset --yes` to finish it forward. Never hand-remove the remaining items. The evidence integrity key has no file fallback by design, so unlike credentials it cannot route around the platform boundary: all cfctl Keychain operations are noninteractive, including explicit repair and reset. A locked or unauthorized platform item produces an error without opening a password dialog. Preserve the existing authority and diagnose its custody; do not replace or rotate it merely to clear an access error. |
| The sole canonical evidence registry is malformed while the marker is absent | Run `cfctl auth evidence-key recover-preview --json`. Recovery is admissible only when the direct platform backend has no managed transition and local storage has zero authenticated descriptors or proofs. The preview is classification-only and read-only: it returns a byte count but no raw value, digest, secret-derived identity, quarantine identity, or execution handle. Create the protected private intent with `cfctl auth evidence-key recover-plan create --json`; inspect or revoke its random opaque ID with `recover-plan status|revoke` without another confirmation prompt. Only the protected quarantine-and-replacement transition requires `cfctl auth evidence-key recover <plan-id> --yes --json`. | Never print or export the registry, hand-edit Keychain, initialize over it, derive an execution identity from secret material, retire quarantine in the same transaction, restore malformed bytes after quarantine begins, or delete historical V1 evidence. A marker, authenticated artifact, unmanaged custody drift, or conflicting readback remains a hold; after a crossed quarantine transition, resume only the same private plan forward. |
| `plans run` succeeded but the envelope reports `attestation.state: unattested_reversible_effect` | The evidence authority did not qualify and the plan's effect was replayable, so cfctl executed it and said so instead of refusing. Read `attestation.reason` for why the authority did not qualify, then repair it with `cfctl auth evidence-key status --json` and the rows above. Expect the plan to be `RectificationRequired`: the crossing is durable but its receipt is not authenticated, so run `cfctl plans status <operation-id> --json` and reconcile from the boundary response the envelope names. | Do not treat the marker as proof the operation was attested. It is unauthenticated telemetry written by the same installation whose authority was unavailable, so it proves nothing against an adversary able to suppress evidence. Do not replay the plan to obtain a receipt; the boundary was already crossed. Irreversible, destructive, identity, external-communication, spend, and unknown effects never reach this state — they refuse instead, and a refusal there is the authority failing, not the plan. |
| Catalog sync, coverage, or a stored catalog fails | Run `cfctl catalog sync --json`, then `cfctl catalog coverage --json`. Preserve `previous_catalog` and the returned error code; a discarded invalid current catalog is evidence of safe replacement, not evidence that earlier plans are valid. | Never edit a catalog body or content hash, restore a stale snapshot as current, or reuse a plan whose catalog pin drifted. |
| A capability or write is blocked | Run `cfctl guide <capability-id> --json` and follow the exact `next_action`. Report the capability ID and `blocking_gaps` when the guide cannot close the contract. | Never route around `CFCTL_CAPABILITY_BLOCKED` with raw HTTP, Wrangler, dashboard changes, a broader token, or hand-edited plan JSON. |
| A run crashed, timed out, or may have crossed the provider boundary | Run `cfctl plans status <operation-id> --json`. Use `cfctl plans rectify <operation-id> --json` when verification is unsupported or the boundary outcome is uncertain; review any derived compensation as a new transaction. | Do not replay `plans run`, approve a replacement operation speculatively, or call the provider directly. A consumed or uncertain plan remains non-replayable. |

These responses are safe defaults, not authority to inspect an account or run a
mutation. Escalate a suspected credential disclosure, approval bypass, secret
sink failure, or provenance mismatch through `SECURITY.md`; ordinary usage and
product questions require the launch owner to name a public support channel
and response owner before launch.

## Health and discovery

```bash
cfctl version --json
cfctl doctor --json
cfctl catalog sync --json
cfctl catalog coverage --json
cfctl docs changes --json
cfctl agents doctor --json
```

Require `build_identity_healthy: true` and the PATH entry reported by both
doctors to resolve to the running executable. Checkout builds claim a commit
only when tracked and untracked non-ignored files are clean; otherwise
`cfctl version --json` reports `identity_source: unknown` and both doctors fail
closed. Release builds may use the verified full-commit release override. A
doctor never launches a different PATH executable to inspect it; invoke that
binary directly with `cfctl version --json` if its self-reported identity is
needed. Unknown source identity, missing or different PATH executables, and
managed-instruction drift are unhealthy installation states.

Source bootstrap applies that same tracked-and-untracked non-ignored
cleanliness invariant before verification or installation. Its current `cargo
install --force` flow still replaces the install-root binary before checking
the new binary's exact commit. A failed post-install identity check can
therefore leave that PATH binary unhealthy; recover by rerunning bootstrap from
an exact clean checkout. Staging the executable without losing Cargo's
install-root tracking, then promoting it atomically only after identity
verification, remains a separate installer hardening boundary.

If a command reports `catalog content hash mismatch`, do not edit the stored
hash. Run `cfctl catalog sync --json` to fetch a fresh official snapshot and
inspect `previous_catalog`. `discarded_invalid` means the corrupt current file
was replaced without overwriting the last valid previous snapshot; ordinary
catalog reads and plans remain fail-closed until that explicit repair succeeds.

Use `mutation_contract_gap_counts` to distinguish unknown risk, effect, cost,
verification, rollback, permissions, and entitlement debt. Counts overlap;
`capabilities_with_mutation_contract_gaps` counts affected operations once,
while `blocked_adapters_without_contract_gaps` identifies separate adapter or
workflow blockers. Search a stable gap name such as `verification_missing` or
its spaced form (`verification missing`) to list matching operations before
choosing a repair slice.

A blocked capability hit at execution time fails closed with error code
`CFCTL_CAPABILITY_BLOCKED`. The envelope carries the `capability_id`, the
`blocking_gaps` list, and a `next_step` that routes to
`cfctl guide <capability-id> --json`; follow the guide's `next_action` instead
of retrying the call or routing around cfctl.

Choosing a repair slice: read `mutation_contract_gap_counts` from
`cfctl catalog coverage --json`, pick one gap code, and list its operations
with `cfctl catalog search "<gap_code> <product>" --json`. Close the slice in
source (catalog classifier plus, when a new verification strategy is declared,
its support arm in `cfctl-core`), then prove it with before/after coverage
counts from `cfctl catalog sync` and `cfctl catalog coverage --json`.

Find and inspect an operation:

```bash
cfctl resolve "<natural-language intent>" --json
cfctl catalog search "<intent>" --json
cfctl catalog show <capability-id> --json
cfctl guide <capability-id> --json
```

`cfctl resolve` deterministically maps a goal to a capability and emits the exact
governed `call`/`approve`/`run` commands, failing closed with ranked candidates
when the match is ambiguous. Treat the guide as an executable safety contract,
not prose. Run `call_argv`
only when `contract_state` is `available`. When it is `blocked`, resolve every
named `blocking_gaps` entry through the supplied safe `next_action`; the
`post_resolution_call_argv` field is a template and is deliberately not an
execution recommendation. It is `null` when no safe future execution surface
exists. Commands are argv arrays so agents never have to guess shell quoting.

For a zone mutation with `check_entitlement` marked `live_read_required`, the
generated `next_action.argv` performs a Billing Read of the exact zone
subscription before it creates a plan. The plan binds that normalized receipt,
and execution rechecks it. Do not substitute account subscription output or
manually edit `observed_plan`; ambiguous, inactive, unavailable, and drifted
entitlements remain blocked.

For account-, global-, or user-scoped plan gates, `check_entitlement` remains
`blocked` when the official schema has no product-scoped subscription join key.
The generated next action explains the missing join and opens the matching
official plan documentation. An arbitrary active entry from
`GET /accounts/{account_id}/subscriptions` is not entitlement proof.

For an executable zone mutation, `select_account` is also
`live_read_required`. The exact call reads `GET /zones/{zone_id}` and requires
the returned zone and `account.id` to match the target and selected account.
That ownership receipt is re-read before plan consumption; do not infer
ownership from a profile label, workspace pin, or local IaC.

## Exit codes

Every invocation returns one of three exit codes. `0` is success. `1` is a
handled failure that renders a `ResultEnvelopeV2`; every failure envelope
carries a `next_step`. `2` is a clap usage error: the rejected arguments print
as raw clap output, and an envelope appears only under `--json`, with error
code `CFCTL_USAGE`.

An hourly analytics publisher should run `keys renew-analytics-profile` before
its read. Exit `0` means the managed child is outside its renewal window or a
complete rotation passed staged and active reads plus old-child revocation.
Exit `1` is the observable failure signal: do not suppress it. In particular,
`CFCTL_ANALYTICS_ROTATION_OLD_REVOKE_PENDING` persists across later hourly
checks until the one-time bootstrap revoke operation is approved, run, and
verified. The same persistent signal guards any later lineage-bound revoke
that did not reach verified closure; the scheduler cannot silently return to
healthy or mint another child while two children may remain active. A
post-activation revoke-planning failure is also durable and nonzero; later
checks retry only plan creation through the explicit minter profile.

## Authentication

Day-to-day auth is a scoped API token imported out-of-band. Pipe it through
stdin, or hand cfctl a mode-0600 file with `--value-in` when a build wrapper
(such as the in-repo `./cfctl` shim, which routes stdin through `cargo`) would
otherwise swallow stdin:

```bash
printf '%s' "$CLOUDFLARE_API_TOKEN" | \
  cfctl auth import-api-token --account <account-id> --stdin --json

# or, stdin-free (survives ./cfctl):
( umask 077; printf '%s' "$CLOUDFLARE_API_TOKEN" > token.tok )
cfctl auth import-api-token --account <account-id> --value-in token.tok --json
rm -f token.tok
```

OAuth login (optional) uses PKCE and an explicit client id until public cfctl
OAuth is promoted:

```bash
cfctl auth login --profile default --client-id <client-id> \
  --account <account-id> --json
```

Open the returned authorization URL, then pipe the callback's one-time
`STATE CODE` value into the same command with `--complete`. Use `auth status`,
`profiles`, `use`, and `logout` for profile lifecycle. Import an emergency
global key only through stdin; cfctl never selects it silently.

If `doctor` reports an unsupported `wrangler_session` profile, it is inert
metadata left by a pre-release experiment. `auth profiles` and `doctor` remain
readable, but `auth status`, `auth use`, planning, and execution reject that
profile. Remove it with the exact `remove_argv` reported by `doctor`, then
create a supported OAuth or API-token profile. Legacy-profile removal does not
read, delete, or reinterpret any credential-store entry; cfctl does not revive
Wrangler authentication as an API or delegated-CLI credential lane.

## Workspace boundaries

```bash
cfctl workspace add /absolute/root --account <account-id> --json
cfctl workspace remove /absolute/root --json
cfctl workspace discover --json
cfctl workspace graph --json
cfctl workspace audit --json
```

Only registered roots are scanned. `workspace remove` retires a root and its
account pin from future discovery without deleting historical graph or evidence
records. Discovery skips directories by exact name, not by category: `.build`,
`.cache`, `.git`, `.swiftpm`, `.terraform`, `.wrangler`, `Carthage`,
`DerivedData`, `Pods`, `__fixtures__`, `cargo-home`, `coverage`, `dist`,
`fixtures`, `node_modules`, `target`, `test-data`, `test_data`, `testdata`,
`var`, and `vendor`. A generated directory whose name is absent from that list
is still walked — `DerivedData` was missing, and twenty vendored Swift package
checkouts under one app's `build/DerivedData` were adopted as workspace
repositories. `build` is deliberately walkable because it is also a legitimate
source directory name. Register an excluded directory directly to opt it into
discovery.
Fix account ambiguity or dirty overlap before planning writes.

## Local registry

```bash
cfctl registry scopes discover --json
cfctl registry sync --json
cfctl registry status --json
cfctl registry coverage --json
cfctl registry diff --json
```

The SQLite registry uses WAL, foreign keys, versioned migrations, integrity
checks, atomic backups, and per-resource locks. It is a rebuildable projection:
the catalog remains capability authority, successful Cloudflare reads plus
their evidence remain observed-state authority, and approved JSON declarations
under `CFCTL_HOME/config/registry/declarations/` remain desired-state authority.
Source configuration and events never become live observations. Partial or
blocked provider coverage is reported as partial rather than complete.

## Admission bundles and bounded token authority

```bash
cfctl policy admission stage --file ./bundle.json --json
cfctl policy admission approve <bundle-id> --yes --json
cfctl policy admission activate <bundle-id> --json
cfctl keys policy create --account <account-id> --name-prefix <prefix> \
  --permission <reviewed-group-id> --max-child-ttl-hours <hours> \
  --max-runs-per-day <count> --json
cfctl keys policy approve <authority-id> --yes --json
```

Bundle approval and activation are separate. The atomically selected active
bundle may only tighten the compiled hard safety floor. `rollback` selects a
previously approved bundle; it does not restore unapproved content. The only
standing-authority exception is the bounded token lifecycle. Admission policy,
event consumption, membership, ownership, billing, registrar, and arbitrary
token mutation remain on ordinary plan and explicit-approval paths.

New mutations persist a PlanV2 pin set beside the compatible PlanV1 body.
Build, catalog, credential generation, active policy, authority, workspace,
observation, and cost drift fail closed. Historical PlanV1 records remain
readable, but pre-PlanV2 unconsumed mutations must be replanned.

### Ordered deployment plan sets

`plans bundle` compiles a body-free, immutable review receipt from child plans
that already exist. It does not approve or run them. Each child keeps its own
operation ID, explicit approval, consumption state, expiration, provider
preconditions, and rollback transaction.

Create the specification as a new absolute mode-`0600` JSON file outside every
repository:

```json
{
  "schema_version": 1,
  "name": "isolated dark deployment",
  "repositories": [
    { "root": "/absolute/clean/provider-repository" },
    { "root": "/absolute/clean/application-repository" }
  ],
  "children": [
    {
      "operation_id": "00000000-0000-4000-8000-000000000001",
      "depends_on": []
    },
    {
      "operation_id": "00000000-0000-4000-8000-000000000002",
      "depends_on": ["00000000-0000-4000-8000-000000000001"]
    }
  ],
  "explicit_exclusions": [
    "credential minting",
    "live email probes",
    "production traffic promotion"
  ]
}
```

```bash
cfctl plans bundle create \
  --source-file /absolute/private/dark-deployment-plan-set.json --json
cfctl plans bundle show <bundle-id> --json
cfctl plans bundle verify <bundle-id> --json
```

The source file is read without following symlinks and is represented only by
its SHA-256. Receipts replace repository roots with digests while retaining
normalized repository identity, exact HEAD/tree, child plan and pin hashes,
account and zone targets, permissions, known cost, risk/effect, provider
snapshot hashes, dependency order, warnings, compensation steps, and rollback
contracts. `verify` performs fresh provider reads but no write, approval, or
execution. Any named source, build, catalog, profile, credential generation,
admission policy, child plan, local artifact, or provider-precondition drift
invalidates the set.

Children must share the selected profile, cfctl build, catalog, and credential
generation. Compiled safety-floor decisions and impact-scoped workspace graphs
may differ by capability; the bundle records deterministic aggregate hashes and
retains each child's exact policy and workspace pins in the review receipt.
Every child is revalidated against its own pins and live preconditions. Distinct
active admission-policy bundles still fail closed.

A dependency edge is review ordering, not output interpolation. When an early
create returns an identifier required to plan a later child—for example, a new
D1 UUID needed by migrations and Worker bindings—the complete downstream set
cannot honestly exist before that create is applied and read back. Prepare and
approve a bootstrap plan set for the resource creates, apply it only under its
own explicit approvals, generate the ignored private runtime configuration from
the verified returned identifiers, and then compile a new dark-deployment plan
set for migrations, projection, and deployments. Never put placeholders into a
single bundle or treat bootstrap approval as authority for the later set.

## Event ledger and reconciliation

```bash
cfctl events sources --json
cfctl events status --json
cfctl events history --limit 100 --json
cfctl events bridge inspect --json
cfctl events bridge prepare --json
cfctl call events-consume-queue-batch \
  --selector account_id=<account-id> --selector queue_id=<queue-id> \
  --selector subscription_id=<subscription-or-webhook-id> \
  --body-json '{"batch_size":100,"visibility_timeout_ms":60000}' --json
cfctl plans approve <operation-id> --yes --max-cost USD:0.00016 --json
cfctl plans run <operation-id> --json
```

`events-consume-queue-batch` is the only live Queue pull/ack adapter. Each
batch receives an ordinary PlanV2 that binds the account, catalog hash,
credential generation, queue, subscription, batch size, visibility timeout,
workspace, active policy, observations, and cost ceiling. Queue JSON bodies
are decoded from the documented base64 wire format; unknown content types and
invalid provider signatures fail closed without acknowledgement.

For every message, cfctl writes redacted EventReceipt evidence and atomically
commits the event plus all derived reconciliation jobs before sending the
Queue acknowledgement. A crash after commit causes safe redelivery and durable
deduplication. Events may enqueue bounded live reads, but they never write the
observed resource projection themselves. Periodic inventory remains required
because Event Subscriptions and Audit Logs v2 are not complete state feeds.

The inbound RealtimeKit verifier lives at `bridge/event-ingress` and uses the
exact signed request bytes. It is Bun-only:

```bash
cd bridge/event-ingress
bun install --frozen-lockfile
bun run check
```

`events bridge prepare` stages a local manifest only. Worker, Queue, webhook,
and Event Subscription deployment remain separate cataloged mutation plans.

## Reads and writes

Per-capability procedure — exact selectors, readbacks, secret sinks, and
compensation for each governed read and write — is in
[capability-procedures.md](capability-procedures.md).

For any single capability, prefer the generated workflow:

```bash
cfctl guide <capability-id> --json
```

It is rendered from the catalog, so it cannot drift from the contract the way a
hand-written procedure can.

## Agent entry

```bash
cfctl agents install --all-detected --json
cfctl agents doctor --json
cfctl "<natural-language Cloudflare request>"
```

Natural language launches one configured local agent. The agent must translate
intent to deterministic commands; it cannot approve or directly mutate state.
Quote natural language: a bare single token that is not a known command fails
closed with a usage error instead of launching an agent.

## Local proof

```bash
cargo xtask verify
```

Do not report completion without the applicable source-config, live-read,
preview, apply, and post-change verification evidence.

## Known limitations

- **Version 3 workspace D1 transitions compile source only.** The complete frozen
  schedule and exact SQL segments are checked, while provider execution stays
  disabled. See [the V3 source and receipt contract](../workspace-d1-transitions-v3.md).

- **Manifest-selected workspace D1 migrations remain fail-closed until
  qualification is produced.** Every create, apply, restore, delete,
  deployment, and other provider mutation remains its own immutable PlanV2:
  generate it with `cfctl call`, show the exact operation to Prime, approve
  only that reviewed ID, run it once, and retain its post-change evidence.
  After the isolated success, declared DDL-failure, declared ledger-failure,
  distinct before/after zero-delta reads bracketing each exact failed operation,
  an exact-database 404 not-found cleanup read, fresh Worker
  deployment/version/settings reads, and the Founder-owned semantic canary have
  authenticated child identities, call `workspace-d1-qualification-produce`
  with the PlanV2/proof identities and the existing Founder canary EvidenceV1
  hash. The producer performs no Cloudflare or Wrangler boundary, derives
  delta predicates from the two semantic-state observations, accepts no raw
  receipt body, SQL, successful cleanup detail, caller-selected canary hashes,
  or caller disposition, and creates, approves, or runs no provider plan.
  Production planning stops until
  one `workspace_d1_provider_atomicity_v1` PostChangeVerification receipt and
  one `workspace_d1_old_worker_canary_v1` workspace receipt pass the closed
  validators. The atomicity receipt binds an isolated database, exact cfctl and
  Wrangler identities, child PlanV2 hashes, success and both failure paths,
  zero schema/ledger deltas, and cleanup. The canary binds the existing Worker
  deployment/version/settings operational-proof envelopes and keeps workspace
  semantics opaque behind one digest without retaining the semantic body. Both
  receipt hashes, the three Worker live-read
  hashes, and the Worker deployment-plan hash become PlanV2 resource
  observations. The canary is owned and authenticated by Founder under the
  exact `mln-web.workspace-d1-old-worker-canary-v1` version-1 cross-repository
  contract; cfctl consumes and validates that receipt rather than authoring or
  re-signing its behavioral semantics. The canary self-hash is the canonical JSON receipt hash with
  `canary_receipt_sha256` set to the empty string; the Worker-identity join is a
  separate canonical hash over the deployment-plan and three live-read hashes
  plus deployment/version UUIDs. Exact index and trigger definitions are compared for equality;
  `schema_contains` is not accepted as migration verification. Provider proof,
  production planning, and automatic restore are not implied by the source
  interface. Before any qualifying receipt is written, run
  `cfctl auth evidence-key init-preview --json`; review its backend, generated
  key and local marker custody classes, state-root transition,
  verification-generation behavior, and recoverability. Only a separate
  explicit `cfctl auth evidence-key init --json` performs initialization.
  A valid sole canonical platform registry with a missing local marker is an
  adoption case, not initialization or resume-init. `adopt-preview` performs a
  read-only, body-free classification and requires direct platform custody and
  zero authenticated artifacts. `adopt-plan current` and ID-addressed
  `adopt-plan status` preserve read-only historical inspection; receipt-less
  records are non-executable. `adopt-plan revoke` remains available only for a
  plan whose protected crossing never began.

  `adopt-plan create` and `adopt <plan-id> --yes` are release HOLDs. Each returns
  `CFCTL_AUTH_INSTALLED_IDENTITY_RECEIPT_REQUIRED` before any private plan or
  pointer write, marker creation, crossing-seal publication, or terminal event.
  Raw caller-provided source-candidate, installed-artifact, architecture,
  CDHash, algorithm, and provenance fields are no longer accepted by the command
  grammar because they cannot authenticate independent review or installation.
  Signed publication and installation may proceed independently; adoption must
  wait for a separately reviewed authenticated installed-identity receipt
  producer and consumer.

  The preserved private state machine remains fail-closed for historical and
  interrupted state. A record-backed `allocating` pointer may be inspected or
  recovered only as allocation state; it cannot publish a crossing seal, project
  `marker_crossed`, complete, or re-enable ordinary evidence authentication. A
  matching marker without an exact active-plan seal is conflict, not evidence of
  adoption. No adoption outcome or Cloudflare provider effect is claimed.
  A malformed sole canonical platform registry is not an initialization case:
  `cfctl auth evidence-key recover-preview --json` only classifies the state and
  reports its byte count and local artifact counts. It writes nothing and
  exposes no registry bytes, digest, secret-derived identity, or execution
  handle. `cfctl auth evidence-key recover-plan create --json` separately
  writes a short-lived private Keychain intent bound to the exact bytes,
  classification, artifact inventory, fresh replacement, root, expiry, and
  lifecycle, while returning a random opaque plan ID. The confirmed `recover
  <plan-id> --yes` copies the original bytes to private quarantine, verifies
  them, publishes a fresh chunked authority, writes the marker, and records
  single-use completion. An interrupted plan resumes forward from private
  custody and never restores malformed bytes to the canonical identity. It
  never upgrades legacy proof rows or exposes registry bytes.

- **Access application and identity-provider plan storage uses schema-aware
  redaction.** Secret-shaped JSON Schema property names such as
  `client_secret`, `token`, and `password` are public catalog metadata only
  beneath schema name maps such as `properties` and `$defs`. Submitted payloads
  and every other plan field still pass through generic fail-closed redaction,
  and malformed schema entries carrying plaintext secret values remain blocked.
  Regression coverage proves both request-schema persistence and rejection of
  an actual submitted `client_secret`.

- **Arbitrary KV namespace deletion stays blocked.**
  `workers-kv-namespace-remove-a-namespace` cannot be called directly: Cloudflare
  does not document whether deleting a *populated* namespace bills its contained
  key deletions, so its cost is unbounded. Deletion is available only as the
  reviewed rollback of a cfctl-created namespace, and only when the namespace is
  proven empty — `plans rectify` on a KV-create plan derives a delete gated on a
  live key-list read requiring an empty `result`, `result_info.count == 0`, and a
  complete cursor. That proof bounds the cost to zero (no keys to bill); a
  populated or truncated result fails closed, and the emptiness is re-read live
  before the boundary is crossed. The four production namespaces were not created
  by cfctl and can never enter this path.


### Maildesk policy evidence from an adopted workspace

A clean registered workspace may declare `<namespace>.d1-evidence-read` in
`.cfctl/operations/d1-evidence.toml` with `projection = "maildesk_v1"`. The
namespace uses lowercase repository-style identifiers; the original
`star-maildesk-cf.d1-evidence-read` remains supported. The operation retains its
exact committed pack, config template, production config, database binding and
Wrangler version checks. The workspace cannot supply SQL.

The aggregate exposes `revision_r2_key` from `policy_revisions.r2_object_key`
and `projection_policy_sha256` from the projection state's active policy digest.
Both are independent observations; disagreement with the runtime state remains
visible for the consumer to reject. Current reads require both bounded values.
Historical aggregates lacking them remain readable, with those observations
absent rather than inferred. Route-health and audit counts do not prove actual
inbox receipt; that requires separately qualifying delivery evidence.

## Explicit private local setup and transition

Use this route for an ordinary source-installed CLI that must operate without
platform password dialogs. Run `cfctl auth evidence-key private-preview --json`
and inspect the exact carried, missing and excluded profile IDs, retained
history location, unsupported standing-authority references and OS-user trust
boundary. The preview creates a private local transition plan; it does not
create an evidence key or select a new runtime. Then run the returned
`cfctl auth evidence-key private-activate <plan-id> --yes --json` command.

Before activation, finish other cfctl operations and stop older installed
executables that do not honor the new selection guard. New ordinary commands
hold shared guards, so they can run concurrently; activation requires the
exclusive guard and fails promptly if another invocation is active. A changed
source profile, selected credential, configuration or plan history invalidates
the preview. Pending OAuth logins and running executions must be resolved first.

Activation preserves the old state and platform keys, creates a new random
signing authority and publishes the persistent location only after verification.
An interrupted activation resumes the same staged authority. Repeating a
completed activation reports already active. No old approval, standing grant,
proof cache or plan becomes executable in the new runtime. Inspect old operation
IDs with `cfctl auth evidence-key private-history --json`; old files remain at
the reported archive location. Renew standing authority separately when needed.

The same commands work under an explicit `CFCTL_HOME` for isolated setup;
they affect only that home's selection. Keep using that original home for
subsequent invocations. Ordinary use needs no environment override because the
default installation follows its persistent selection. A fresh setup can then
import its first account-pinned scoped token through stdin, run `auth status`,
`auth evidence-key status`, `doctor`, and `catalog sync` without Keychain access.

Both evidence authority and selected private credentials require owned 0700
directories and owned 0600 regular files, with symbolic links, hard links and
oversized entries rejected. Writes sync the file and parent directory before
completion. This protects against other OS users; another process running as
the same user can read credentials and signing keys. Keep that local trust
boundary distinct from Cloudflare's account pins and least-privilege token
permissions.
