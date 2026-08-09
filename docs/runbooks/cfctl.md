# cfctl v2 operator runbook

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
records. Nested generated and cache paths (`var`, `cargo-home`, `.cache`,
`coverage`, and `dist`) plus fixtures, dependency/build output, vendor, and
nested repository metadata are excluded from a broader root; register an
excluded directory directly to opt it into discovery.
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

## Reads

```bash
cfctl call <capability-id> \
  --selector account_id=<account-id> \
  --query per_page=100 --json
```

The typed transport validates selectors and bodies against the pinned schema,
paginates, backs off on rate limits, uses conditionals when supplied, and emits
structured Cloudflare errors.

Broad telemetry language returns a domain overview instead of choosing a
configuration or enforcement mutation:

```bash
cfctl resolve "telemetry overview" --json
cfctl catalog coverage --json
```

Prefer the governed workflow ranked for an investigation or audit. Calling a
workflow is a local preview: it expands component selectors and emits commands
only for currently available, contract-ready components while showing
workflow-relative proof freshness without crossing the Cloudflare boundary.
Blocked, incomplete, or cyclic components expose blocking gaps and a guide but
no runnable call. Run each bounded read explicitly. A mutating component always
remains a separate `call` plan followed by its own approve/run/status lifecycle.

Coverage reports both declared catalog coverage and a bounded projection of the
local `operational_proof` index. Inspect its retained/total counts and
`truncated` flag before interpreting counts. Do not collapse coverage and proof
into one success claim: contract-complete is not account-proven, a receipt is
not dataset completeness, and freshness is evaluated only under the selected
workflow policy. Proof scope includes the credential generation captured before
the read boundary. Re-login or re-import advances that generation: earlier rows
remain auditable but report `credential_drifted`, while rows created before the
generation contract report `credential_unbound`. Repeat the bounded read before
using a drifted row as current evidence. A profile with no generation represents
pre-generation metadata or an interrupted credential replacement; log in or
import the credential again before performing a proof-bearing read.

The evidence-packet workflow exports read-receipt identities and safe mutation
lifecycle checkpoint metadata. It omits plan inputs, targets, transaction
artifacts, credentials, and raw telemetry; an absent apply, verification, or
compensation class remains absent evidence rather than an inferred success.

Registered roots with an explicit account pin receive the same proof posture as
a separate overlay in `cfctl workspace audit --json`. An unpinned repository is
reported as `unscoped`; cfctl never joins it to the newest or only available
account. Use a governed workflow when time freshness matters.

GraphQL Analytics capabilities carry fixed documents; provide only their
declared variables. Analytics Engine and Log Explorer accept typed query
objects that cfctl compiles into one bounded `SELECT`—never raw SQL. Large
declared JSON/NDJSON/CSV results can use `--out <new-path>`; stdout contains a
hash receipt rather than the rows. See
[`telemetry-control-plane.md`](../telemetry-control-plane.md) for exact IDs and
contracts.

D1 schema checks use the native `d1-schema-introspection` read. The caller
provides one exact account, one exact database, and one closed assertion object;
cfctl compiles the only SQL sent to Cloudflare and returns a bounded boolean
result with ordinary redacted live-read evidence:

```bash
printf '%s' \
  '{"assertion":"trigger_exists","trigger":"document_render_jobs_terminal_generation_guard"}' |
  cfctl call d1-schema-introspection \
    --selector account_id=<account-id> \
    --selector database_id=<database-id> \
    --body-stdin --json
```

MLNavigator migration 0143 has a narrower product-bound proof capability:
`mln-0143-data-invariants`. It is pinned to the reviewed MLNavigator account
and Founder database and accepts only migration `0143` plus one phase:
`pre_import`, `post_import`, or `post_restore`. Post-import requires the
content hash of a successful pre-import receipt. Post-restore requires both
that pre-import hash and a post-import receipt that names the same baseline.
Version 2 receipts also carry a validator-contract hash and the fixed-query
hash; parent lookup rejects older or synthetic receipts that omit the current
schema, packet, assertion, bounds, or validator identities.

The capability owns its SQL, probes with `COUNT(*) OVER()` and `LIMIT 257`,
and accepts at most 256 complete evidence rows. It hashes the exact
ten-column ordered projection in volatile memory, then discards raw rows,
MLNavigator identifiers, and document hashes before stdout, errors, logs, or
durable evidence. A saturated or ambiguous result fails with
`invariant_not_feasible_under_safe_bounds`; generic D1 SQL remains blocked.
The same read projects the complete ordered packet-kind table with a 513-row
probe and accepts at most 512 rows. Evidence retains only full and non-target
packet digests/counts: post-import permits exactly the reviewed advisor delta,
and post-restore must reproduce the pre-import full-table digest and count.

```sh
printf '%s' '{"migration_id":"0143","phase":"pre_import"}' |
  cfctl call mln-0143-data-invariants \
    --selector account_id=ca30e922fda7f5578e49873542e4aaca \
    --selector database_id=7c282983-2e48-4ea4-9f0d-09b0d718fe65 \
    --body-stdin --json
```

The allowed assertions are `table_exists`, `column_exists`, `index_exists`,
`trigger_exists`, `schema_contains`, and `foreign_key_check_empty`. Caller SQL,
parameters, arbitrary PRAGMAs, multiple statements, and database retargeting
are not inputs. The generic `d1-query-database`, `d1-raw-database-query`, and
`wrangler.d1` capabilities remain blocked.

Use `d1-full-export` to capture a full schema-and-data SQL snapshot immediately
before a separately governed migration:

```bash
cfctl call d1-full-export \
  --selector account_id=<account-id> \
  --selector database_id=<database-id> \
  --out <new-mode-0600-sql-path> --json
```

This is a read/export-only capability. It accepts no body, SQL, parameters,
table filters, schema-only/data-only switches, apply input, or restore target.
cfctl owns the provider polling body, bounds each polling response, and streams
the completed signed download into a newly created mode-0600 file. Output paths
must be normalized, have an existing real-directory parent chain, contain no
traversal or symlink components, and name a file that does not already exist.
On Unix the final create also uses `O_NOFOLLOW`. The parent check and final open
are separate filesystem operations, so callers must use a directory not writable
by an untrusted concurrent local process. Any failure after file creation removes
only that newly created file; a cleanup failure is surfaced instead of producing
a success receipt. The live-read
evidence binds the account and database identity, exact output path, SHA-256,
byte count, file-exists/hash-match verification, and the provider filename and
time-travel bookmark when returned. Cloudflare may temporarily make the
database unavailable while producing a large export, so capture the snapshot
in the migration window. The receipt proves only the local pre-migration
snapshot; importing or applying it is a separate protected workflow.

OSINT Research Center migrations 0028 through 0034 use the narrower
`d1-import-approved-osint-research-migration` adapter. It pins account
`ca30e922fda7f5578e49873542e4aaca`, database
`1c1ce476-73ab-4dd6-a2e2-de0c155ade61`, repository
`github.com/rogu3bear/osint-research-center`, release HEAD, and every migration
path/blob/SHA-256/MD5/size. The caller selects only one migration ID, supplies
the corresponding reviewed absolute `--source-file`, and binds a current
governed `d1-time-travel-get-bookmark` evidence hash plus the SHA-256 of its
exact bookmark string. This bookmark lane is required because Cloudflare full
export rejects databases containing FTS5 virtual tables; it still provides the
exact rollback target consumed by `d1-restore-exact-bookmark`.

```bash
printf '%s' \
  '{"migration_id":"0028","pre_recovery_anchor_evidence_hash":"sha256:<live-read-evidence>","pre_recovery_anchor_bookmark_hash":"sha256:<bookmark-string-hash>"}' |
  cfctl call d1-import-approved-osint-research-migration \
    --profile osint-research-d1 \
    --account ca30e922fda7f5578e49873542e4aaca \
    --selector account_id=ca30e922fda7f5578e49873542e4aaca \
    --selector database_id=1c1ce476-73ab-4dd6-a2e2-de0c155ade61 \
    --source-file /absolute/reviewed/repository/migrations/d1/0028_founder_people_handoff.sql \
    --body-stdin --json
```

Create, review, approve, run, and verify one plan at a time in numeric order.
The import state machine never replays init, upload, ingest, or an uncertain
poll. After provider completion, cfctl runs one compiler-owned marker query for
the selected migration and closes only when that read returns exactly
`present = 1`. Caller SQL, import protocol controls, alternate repositories,
dirty source trees, and retargeted accounts or databases fail closed.

Approved MLNavigator imports use `d1-import-approved-mln-migration`. If its
bounded provider polling ends while the import is still active, do not rerun
that consumed plan: init, upload, and ingest are one-shot boundaries. Create a
new `d1-resume-approved-mln-import-poll` plan whose body contains only the
parent operation ID, immutable parent PlanV2 hash, canonical exhaustion
evidence hash, accepted-ingest evidence hash, and accepted-bookmark hash.
cfctl re-derives the migration, source, target, profile, credential generation,
catalog, and plaintext bookmark from managed parent authority. The separately
approved child sends only bounded zero-retry `poll` requests. One exact
exhaustion admits at most one child; a child that crossed consumption or any
provider boundary permanently consumes that exhaustion even if later
cancelled. A later canonical child exhaustion can admit the next child in the
same linear root lineage. Provider completion remains pending until the
migration-specific governed post-import proof closes the root import.

Restore only through the native `d1-restore-exact-bookmark` recovery
capability. Raw D1 query/restore operations and Wrangler remain blocked:

```bash
cfctl call d1-restore-exact-bookmark \
  --selector account_id=<account-id> \
  --selector database_id=<database-id> \
  --body-stdin --json
```

The stdin body is a closed object with exactly `target_bookmark`,
`expected_current_bookmark`, `source_operation_id`, and
`source_evidence_hash`. It accepts no timestamp, SQL, import, or raw URL. The
call creates a destructive Recovery/DataWrite plan and never restores during
planning. Review and explicitly approve the exact operation ID before
`plans run`.

At execution, cfctl reads the database's current time-travel bookmark and
fails before the mutation unless it exactly equals
`expected_current_bookmark`. It then sends exactly one restore POST containing
only `{"bookmark":"<target_bookmark>"}`. A rate limit, provider error,
timeout, or uncertain transport outcome is not retried; inspect the original
operation with `plans status`/`plans rectify`. A successful provider response
must include non-empty `bookmark`, `message`, and `previous_bookmark`. cfctl
then reads the current bookmark again and verifies that it equals the returned
restore bookmark.

The receipt binds target, expected, pre-restore, returned, previous, and
post-restore bookmarks; source operation/evidence linkage; the closed request
digest; provider response metadata; and performed/verified truth. Cloudflare
documents no incremental restore operation charge, but restoring overwrites
the database and cancels in-flight queries. Undo is never automatic: create a
new `d1-restore-exact-bookmark` plan targeting the prior receipt's
`previous_bookmark`, bind a fresh expected current bookmark, review it, and
approve it separately.

Logs Engine retrieval is the one reserved-header exception and remains
operation-specific. Supply a mode-0600 JSON bundle containing exactly
`access_key_id` and `secret_access_key`, plus a new output path:

```bash
cfctl call logpull-retrieve-logs \
  --selector account_id=<account-id> \
  --query start=<rfc3339> --query end=<rfc3339> \
  --query bucket=<r2-bucket> --query prefix=<log-prefix> \
  --credential-in <mode-0600-json-path> \
  --out <new-output-path> --json
```

The bundle values are injected only as the two pinned R2 headers and never
enter argv, `CallInput`, stdout, plans, or evidence. The read fails closed
without both the private bundle and file output.

## Writes

`call` creates a plan for a mutating capability. Review it, then:

```bash
cfctl plans show <operation-id> --json
cfctl plans approve <operation-id> --yes --json
cfctl plans run <operation-id> --json
cfctl plans status <operation-id> --json
```

Use `--max-cost CURRENCY:AMOUNT` for paid plans. Use `plans resume` only for a
draft or approved plan; consumed/running plans are deliberately non-replayable.
Use `plans rectify` to inspect compensation and verification steps after an
uncertain or unsupported result.

WebSockets use a dedicated zone-setting read/write pair rather than the
unbounded generic zone-setting mutation:

```bash
cfctl call zone-settings-get-websockets-setting \
  --selector zone_id=<zone-id> --json

cfctl call zone-settings-configure-websockets \
  --selector zone_id=<zone-id> \
  --body-json '{"value":"on"}' --json
cfctl plans show <operation-id> --json
cfctl plans approve <operation-id> --yes --json
cfctl plans run <operation-id> --json
cfctl plans status <operation-id> --json
```

Use `"off"` to disable it. The mutation accepts no other value or body field,
targets the literal `/zones/{zone_id}/settings/websockets` path, and captures
the exact prior value for drift detection and a separately reviewed restoration
plan. Cloudflare documents WebSockets as available on all plans. The generic
`zone-settings-edit-single-setting` capability remains blocked; do not route
around the dedicated contract.

The DNS record lifecycle is governed end to end — create, update, patch, and
delete — with deletion verified by a not-found readback of the exact record.

Telemetry-derived security actions require an evidence receipt, actor, reason,
normalized target, finite expiry, current-state/conflict checks, and exact
removal. Managed Challenge is the default; broad targets cannot silently become
permanent blocks. Inspect the exact capability and its generated 15-stage guide
before drafting a plan:

```bash
cfctl guide security-response-create-expiring-waf-rule --json
cfctl guide security-response-add-expiring-list-member --json
```

Raw Ruleset and asynchronous List bulk writes remain blocked by design. Use the
single-action capabilities so verification can correlate one returned identity
and compensation cannot delete an inferred or caller-selected resource.

Queue consumers are likewise governed end to end: create and update accept the
worker and `http_pull` variants, verification reads the exact consumer back by
its returned id, and consumer create binds a reviewed delete as compensation.
Update does not snapshot prior settings; restoring them is a separately
reviewed update.

Access application creation is governed: its request body is a 13-way
polymorphic union with no universally required field, so verification is bound
to a curated set — `name` and `type`, present in every application type — read
back by the returned id, with a reviewed delete as compensation. Variant fields
like `domain` are part of the create but not verified. Access application
*update* is deliberately left blocked: the union has no honest universal field
contract to verify an update against. Creating or deleting an application is
identity-affecting and always requires explicit approval.

Worker script deletion is governed: verification reads the script's `/settings`
sub-path, which returns not-found once the script is gone (the script's own GET
returns the raw module body, not a JSON envelope). cfctl never passes
Cloudflare's `force` bypass, so a script bound as a queue consumer or hosting
Durable Objects keeps Cloudflare's in-use refusal — remove those bindings
through their own governed capabilities first. Deletion is irreversible and
destroys any Durable Object storage the script hosts; redeployment is a
separate `wrangler.deploy` plan.

A KV namespace created through cfctl can be rolled back: `plans rectify` on the
create plan derives a delete that runs only if the namespace is still provably
empty (an empty, fully-listed key set), which bounds its otherwise-unknown cost
to zero. Arbitrary namespace deletion and deletion of populated namespaces stay
blocked.

Note that Cloudflare canonicalizes record names to FQDNs: pass the fully
qualified name (`_token.example.com`, not `_token`) or field verification will
correctly refuse the mismatch after the record is created.

An approved plan is standing permission to mutate until it is consumed or
expires. When the change is no longer wanted, retire that authority
immediately instead of waiting out the TTL:

```bash
cfctl plans cancel <operation-id> --json
```

Cancellation mirrors authority revocation: it is immediate, works on draft and
approved plans even when their content has drifted, is safe to retry, and is
monotonic — a cancelled plan can never be approved, run, or resumed.
Consumed and completed plans are history, not authority, and cannot be
cancelled.

Secret outputs require `--value-out /new/secure/path`; cfctl refuses an
existing destination.

For `wrangler.deploy`, pass an absolute `config` selector. An optional `var`
selector binds one plain-text `KEY:VALUE` Worker variable into the plan and
evidence; never pass a secret through `var`. Both the deploy subprocess and the
deployment-status verifier run from the reviewed config file's own directory,
because Wrangler resolves dotenv credentials relative to its working directory
— a plan reviewed against one config must not publish with a token discovered
from wherever cfctl happened to be invoked. Both processes receive the
plan-selected account ID and use cfctl's platform cache directory for Wrangler
state; governed deploys never write account-selection cache files into a
Worker's `node_modules`. Other delegated CLI capabilities keep their existing
working directory. `cfctl doctor --json` projects this boundary under
`result.delegated_cli_environment` so deploy wrappers can fail closed when an
older cfctl build does not preserve it.

For Worker code-only publication, keep artifact creation and production
traffic promotion as two independently reviewed plans. The upload verifier
reads the returned Worker version and requires both its exact ID and reviewed
message; it does not change production traffic:

```bash
cfctl call wrangler.versions-upload \
  --query config=/absolute/path/to/wrangler.toml \
  --query message='release <full-source-sha>' \
  --json
```

After reviewing that verified version ID, create a second plan that targets
exactly one version at all traffic. Other percentages, multiple targets, and
relative config paths fail closed:

```bash
cfctl call wrangler.versions-deploy \
  --query argument=<worker-version-uuid>@100 \
  --query config=/absolute/path/to/wrangler.toml \
  --query message='promote release <full-source-sha>' \
  --json
```

Promotion verification reads Wrangler's production deployment status and
requires the planned version at 100 percent. Rolling back remains a separate
reviewed `wrangler.versions-deploy` plan targeting a known prior version.

For a Cloudflare Pages direct upload, use the exact
`wrangler.pages-deploy` capability rather than the aggregate
`wrangler.pages` command. Bind the built directory, existing project,
production branch, and exact source commit in the plan:

```bash
cfctl call wrangler.pages-deploy \
  --query argument=/absolute/path/to/site \
  --query project_name=example-web \
  --query branch=main \
  --query commit_hash=<full-source-sha> \
  --query commit_message='<reviewed message>' \
  --json
```

The governed subprocess receives only the selected account and cfctl's
Wrangler cache plus the selected credential. Verification lists production
deployments and requires the exact project, branch, commit hash, and a
successful deployment stage. Automatic rollback is not implemented; restoring
a prior artifact is a separate reviewed deployment plan.

Custom-domain attachment is the separate `pages-domains-add-domain` dynamic
API capability. Its verifier reads the returned domain by exact name; its
compensation path is a new, independently reviewed delete plan. A created
domain resource is not proof that DNS and TLS have converged, so release proof
must still include live hostname readback.

Worker custom-domain attachment is the distinct `workers.domains.update`
dynamic API capability. cfctl narrows Cloudflare's request alternatives to one
exact `hostname`, Worker `service`, and 32-character `zone_id`; it does not
infer `www`, accept `zone_name` substitution, or displace an existing CNAME.
The target must already be an active Cloudflare zone and the named Worker must
already exist; those live prerequisites are read and pinned before planning.
The apply response must return a domain ID, and verification reads that exact
ID back and matches all three planned fields. Detachment is never automatic:
compensation is a separately reviewed and explicitly approved
`workers.domains.delete` plan. The attach operation has no direct charge, but
traffic routed through the Worker retains plan-specific request and CPU usage
exposure. A successful resource readback still does not prove certificate,
DNS, route, or application-content convergence; those remain release readback
gates.

Mint an account token only through the dedicated key workflow. The generic
`account-api-tokens-update-token` and `user-api-tokens-update-token`
capabilities stay blocked by design, not by a schema gap: their request
bodies ingest completely (name, status, policies, condition, expiry), but
token mutation is reserved to the inventory-bound `keys` workflow so every
permission change is resolved against a fresh live permission inventory and
hash-bound. A generic update path would bypass that governance, so it is not
promoted. The catalog now says this machine-readably: both capabilities carry a
`blocked_reason` beginning `blocked by design:`, which is deliberately not the
`operation contract incomplete:` prefix used for schema gaps. Supplying risk,
effect, and cost would not unblock them, and a catalog resync cannot.

```bash
cfctl keys permissions --account <account-id> --json
cfctl keys mint --name <name> --permission <reviewed-group-id> \
  --account <account-id> --ttl-hours <hours> \
  --value-out /new/secure/path --json
```

Mint planning repeats the live permission inventory and binds the exact group
metadata and resource policy. Running the approved plan repeats that inventory
read before consumption; drift requires a new plan. Do not use generic `call`
for account API-token creation.

Scope a token to one zone instead of the whole account with `--zone`, for
zone-owned groups like Cache Purge or DNS Write:

```bash
cfctl keys mint --name <name> --permission <reviewed-group-id> \
  --account <account-id> --zone <zone-id> --ttl-hours <hours> \
  --value-out /new/secure/path --json
```

Zone-scoped groups are discoverable through the same
`cfctl keys permissions --account <account-id>` inventory; each group reports
the scopes it supports. Zone minting is account-owned, so `--zone` requires
`--account` and is rejected with `--user`.

Selected groups are partitioned by what each one actually supports: a group
that declares zone scope binds to
`com.cloudflare.api.account.zone.<zone-id>`, and one that only declares
account scope binds to `com.cloudflare.api.account.<account-id>`. A single
mint can therefore carry both bindings — a Worker deploy token needing
account-owned script permissions plus zone-owned route permissions is one
governed call, not two. A group supporting neither scope fails the plan.

Mint a user-owned token for one explicit account with the parallel governed
workflow:

```bash
cfctl keys permissions --user --account <account-id> --json
cfctl keys mint --user --name <name> --permission <reviewed-group-id> \
  --account <account-id> --ttl-hours <hours> \
  --value-out /new/secure/path --json
```

The `--user` flag changes token ownership and the permission-inventory
endpoint, not the policy scope: every selected group must declare account scope
and the policy remains pinned to the one `--account` value. Use the same flag
for `keys rotate` and `keys revoke`; those plans select the user token endpoint
while preserving the explicit account authority context.

### Standing authority

Recurring token-lifecycle work can run unattended under a bounded standing
policy instead of per-operation approval. Draft one from a fresh permission
inventory, then inspect what already exists:

```bash
cfctl keys policy create --account <account-id> --name-prefix <prefix> \
  --permission <reviewed-group-id> --max-child-ttl-hours <hours> \
  --max-runs-per-day <count> --json
cfctl keys policy list --json
```

Add `--zone <zone-id>` to let children bind that one zone as well as the pinned
account, which is what recurring zone-scoped rotation needs. Without it an
authority is account-scoped only. Every child mint is checked against the
authority's bound resources: the pinned account always, the pinned zone only if
one was reviewed, and nothing else — a child naming another account or another
zone is refused before mutation.

`keys policy create` drafts a hash-bound standing authority (pinned account,
optional pinned zone, name prefix, permission-group allowlist, max child TTL,
and per-day run ceiling); it is inert until activated. `keys policy list` inspects existing
authorities and reports effective status, remaining budget, lineage, and next
action. Activate one reviewed authority ID only with explicit approval, and
close it immediately when the work is done:

```bash
cfctl keys policy approve <authority-id> --yes --json
cfctl keys policy revoke <authority-id> --json
```

Standing approval moves authority to that bounded policy; it is not blanket
mutation authority, and external sends and spend are never standing-authorized.
Load `cfctl guide --topic standing-authority --json` before drafting one.

Create an Access service token through its separate exact account or zone
lifecycle. The input is intentionally limited to `name` and optional
`duration`; version and grace-period fields belong to rotation, not initial
creation. The new sink is JSON with exactly `client_id` and `client_secret`.
For an account-scoped token:

```bash
printf '%s' '{"name":"deployment automation"}' | \
  cfctl call access-service-tokens-create-a-service-token \
    --selector account_id=<account-id> --body-stdin \
    --value-out /new/secure/access-service-token.json --json
```

For a zone-scoped token, use the distinct operation and selector rather than
retargeting the account operation:

```bash
printf '%s' '{"name":"zone deployment automation"}' | \
  cfctl call zone-level-access-service-tokens-create-a-service-token \
    --selector zone_id=<zone-id> --body-stdin \
    --value-out /new/secure/zone-access-service-token.json --json
```

Review, approve, and run the returned operation ID normally. A successful run
requires the mode-0600 sink plus an exact readback of the returned service-token
ID, name, and duration within the same account or zone scope. `plans rectify`
may create a separate reviewed exact-scope delete plan; it never deletes
automatically. Keep
`access-service-tokens-rotate-a-service-token` blocked while its official
operation schema omits the required permission lane.

Rename a service token or choose a new duration without entering the rotation
lane:

```bash
printf '%s' '{"name":"deployment automation","duration":"17520h"}' | \
  cfctl call access-service-tokens-update-a-service-token \
    --selector account_id=<account-id> \
    --selector service_token_id=<service-token-id> --body-stdin --json
```

For a zone-scoped token, use the distinct zone operation and selector:

```bash
printf '%s' '{"name":"zone deployment automation","duration":"17520h"}' | \
  cfctl call zone-level-access-service-tokens-update-a-service-token \
    --selector zone_id=<zone-id> \
    --selector service_token_id=<service-token-id> --body-stdin --json
```

cfctl reads the exact token back and compares every planned field. It rejects
`client_secret_version` and `previous_client_secret_expires_at`: Cloudflare
documents those as secret-rotation and old-secret grace controls. A duration
update resets expiration, so restoring the exact prior expiration is not a
valid rollback claim; correction requires a separate reviewed update plan.

Extend an existing service token by the one-year interval Cloudflare documents:

```bash
cfctl call access-service-tokens-refresh-a-service-token \
  --selector account_id=<account-id> \
  --selector service_token_id=<service-token-id> --json
```

The call is body-free and irreversible. After apply, cfctl requires HTTP 200,
the exact planned token identity, a valid future `expires_at`, and an immediate
detail readback with the same identity and expiration. It never presents the
extension as restorable; a lifetime correction is a separate reviewed plan.

Turnstile secret rotation requires an explicit cutover choice. `false` keeps
the prior secret valid for two hours and prevents another rotation during that
window; `true` invalidates it immediately. In both cases the new secret is
written only to a new sink:

```bash
printf '%s' '{"invalidate_immediately":false}' | \
  cfctl call accounts-turnstile-widget-rotate-secret \
    --selector account_id=<account-id> --selector sitekey=<sitekey> \
    --body-stdin --value-out /new/secure/path --json
```

Rotate an OAuth client secret as a staged two-secret cutover. Planning and
execution both require the exact client to report that no overlap secret exists;
the new value is sink-only:

```bash
cfctl call oauth-clients-rotate-secret \
  --selector account_id=<account-id> \
  --selector oauth_client_id=<oauth-client-id> \
  --value-out /new/secure/oauth-client-secret --json
```

Update and verify every dependent while the old value remains valid. Only then
create, review, approve, and run the separate irreversible deletion plan:

```bash
cfctl call oauth-clients-delete-rotated-secret \
  --selector account_id=<account-id> \
  --selector oauth_client_id=<oauth-client-id> --json
```

The first phase must read back `has_rotated_secret=true`; the second requires
that state before planning and must read back `false`. A second rotation, a
delete from one-secret state, target drift, and a stale approval all fail before
the mutation boundary.

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
