# cfctl capability procedures

> Authority: this file records the **operator procedure for individual
> capabilities** — the exact selectors, readbacks, sinks, and compensation each
> governed read and write uses in practice. It is a companion to
> [cfctl.md](cfctl.md), which owns the lifecycle: triage, health, exit codes,
> authentication, boundaries, and recovery.
>
> `cfctl guide <capability-id>` generates the current workflow for any
> capability from the catalog. Prefer it. This file explains procedures that
> span several capabilities, or that carry operator judgement the generated
> guide does not.
>
> Split out of `cfctl.md`, which had reached 99,569 bytes across 1,743 lines.
> Reads and Writes were 68% of it, which meant the lifecycle a new operator
> actually needs was buried behind per-capability material they did not.

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
`trigger_exists`, `schema_contains`, `foreign_key_check_empty`, and the bounded
ordered `migration_ledger_equals`. Caller SQL, arbitrary PRAGMAs, multiple
statements, and database retargeting are not inputs; parameters exist only in
the closed ledger contract, never as caller-selected SQL controls. The generic
`d1-query-database`, `d1-raw-database-query`, and `wrangler.d1` capabilities
remain blocked.

### Repository-bound D1 changes

Application repositories may declare ordered migration operations in
`.cfctl/operations/d1-migrations.toml`, private policy projections in
`.cfctl/operations/d1-policy-projections.toml`, and fixed body-free readiness
reads in `.cfctl/operations/d1-evidence.toml`. Maildesk may additionally declare
the closed `star-maildesk-cf.reply-admission-activate` and
`star-maildesk-cf.reply-admission-read` pair in
`.cfctl/operations/d1-reply-admission.toml`. Activation accepts one exact
mode-0600 compiler input through `--source-file`, stages the exact committed
compiler bytes, executes them with the version-and-digest-pinned Bun runtime,
stages only the compiled candidate,
derives its SQL internally, and places only hashes and body-free bindings in
PlanV2 and evidence. The companion non-mutating read accepts the same private
compiler input plus the exact transaction, activation-record,
identity-projection, and controller activation-operation selectors. It executes
only cfctl's fixed two-row-bounded query, discards provider rows, and proves only
one exact still-admitted record. The logical D1 admission ID, controller
activation-operation ID, and cfctl PlanV2 UUID remain distinct; each is bound
and reported without rewriting one to impersonate another.

Maildesk's separately documented `star-maildesk-cf.reply-subdomain-ingress-read`
is also workspace-owned and non-mutating. It accepts only `account_id`,
`reply_domain`, and `worker_script_name`. cfctl resolves the nearest exact active
parent zone in the selected account and reads
`/zones/{zone_id}/email/routing/dns` with the exact reply domain in the
`subdomain` query. It then enumerates the complete account Email Routing rule
inventory through `GET /accounts/{account_id}/email/routing/rules`. The typed
projection hashes each rule's domain and parent-zone identities, retains only
validated Worker action targets, and discards raw rule values. Exactly one
enabled rule whose domain hash matches the reply subdomain, whose parent hash
matches the resolved zone, whose sole matcher is `all`, and whose sole action
targets the selected Worker closes the routing plane. The closed
`workspace_reply_subdomain_ingress_v1` projection: hashed reply-domain and
Worker identities, typed `ok`, `drift`, or `missing` DNS and routing states,
and explicit `provider_output_retained:false` and `body_returned:false`.
A separate reply-domain zone, the parent-zone catch-all, incomplete account
pagination, ambiguous exact rules, or a merely similar Worker never satisfy
the contract.

The paired `star-maildesk-cf.reply-subdomain-ingress-activate` capability is
the only write lane for a missing Maildesk reply-subdomain catch-all. It first
uses the complete `listWorkers` projection to resolve one exact Worker tag,
then calls Cloudflare's account-scoped Email Routing plan endpoint with one
`*@reply-domain` target. Only one exact non-destructive `added` or `updated`
change is admissible. A zero change, conflict, delete, duplicate zone,
duplicate change, malformed plan, or target mismatch stops before PlanV2
creation. The provider-returned zone must equal the nearest exact active parent
zone resolved through the complete zone read; an optional planner `zone_name`
must name that parent zone, not the reply subdomain. Execution acquires the
same cross-process lock used by the catalog-native catch-all PUT, keyed by the
exact account and provider parent-zone ID, and holds it
through final reads, the apply receipt, and readback. Inside that lock cfctl
repeats the active-parent-zone read, reads and hash-binds the direct catch-all
state, refreshes the complete Worker inventory, and runs the exact account
plan; every target, catch-all state, Worker tag, payload digest, and change type
must still match the approved PlanV2. The one catch-all body preserves the same
Worker ownership tag used by the planner and runs with automatic retries
disabled. Apply success is insufficient: the plan closes only when both the
direct catch-all shape/source read and the existing body-free reply-subdomain
account-inventory read prove the intended one-all-matcher Worker rule and DNS.
Any fresh-state drift, ambiguous apply, or failed readback requires
reconciliation and a fresh plan; the consumed plan is never replayed.

Cloudflare's documented catch-all API exposes an unconditional PUT and no
compare-and-swap token. The provider-zone lock prevents competing cfctl processes on
this machine and the final reads minimize the provider race, but they do not
make the provider write atomic against dashboard, Wrangler, Terraform, or
direct-API writers. Keep those external writers quiescent for this one change
window. A successful shape/source readback proves final state, not that no
external actor wrote between the last plan response and the PUT.

An account-scoped API-token profile remains the normal read credential. If the
provider denies that exact account inventory to an otherwise correctly scoped
token, an explicitly named emergency global-key profile may perform this one
non-mutating workspace read. Global-key profiles are intentionally not selected
implicitly and carry no stored account pin, so the caller must pass one exact
`--account` and the same exact `account_id` selector. The adapter still binds
the active credential generation and rejects ordinary unbound profiles,
mismatched accounts, or any mutation attempt. This exception does not grant the
global key standing authority for plans, applies, token minting, or deployment.

The repository must already be
an explicit cfctl workspace registration, clean at a canonical HEAD, and carry
the operation pack and tracked Wrangler template at that HEAD. Migration packs
also close the ordered migration directory with exact per-file SHA-256 values.

All mutating repository operations bind an exact Wrangler version, the ignored production-config
path and D1 binding, a fresh pre-change bookmark, and a separately approved
exact-bookmark recovery capability. The production config must be a regular
mode-restricted file and may differ from its tracked template only in the
closed private fields plus the operation's exact selected Worker/D1 identity.
The planned database binding selects that one entry for both planning and
launch: its production Worker name and `database_name` may differ from template
sentinels, while its canonical `database_id` and optional equal
`preview_database_id` remain the selected operational identity. Nonselected
bindings and other selected-entry fields remain exact. A deployable production Worker binding
may omit `preview_database_id`; an isolated preview database belongs in its own
repository-declared Wrangler config and operation. If a production binding
does declare `preview_database_id`, cfctl requires a canonical UUID equal to
that binding's `database_id` and never treats it as authority for a different
preview database. Repository operations may bind canonical role-specific root
names such as `wrangler.mail-router.production.toml` in addition to the
conventional `wrangler.production.toml`.

Prepare a migration by its repository-owned operation id:

```sh
cfctl call <repository-migration-operation-id> \
  --selector account_id=<account-id> \
  --selector database_id=<database-uuid> \
  --query config=/absolute/path/to/wrangler.production.toml \
  --json
```

For a policy projection, the reviewed SQL is supplied only through a private
mode-0600 source file. Its bytes are copied to a new mode-0600 managed stage;
the plan and receipts retain the exact digest and size, but never the SQL or
private policy rows:

```sh
cfctl call <repository-policy-projection-operation-id> \
  --selector account_id=<account-id> \
  --selector database_id=<database-uuid> \
  --query config=/absolute/path/to/wrangler.production.toml \
  --query policy_sha256=sha256:<digest> \
  --query desired_state_sha256=sha256:<digest> \
  --query projection_sha256=sha256:<digest> \
  --query expected_route_count=<count> \
  --source-file /absolute/private/projection.sql \
  --json
```

Planning requires exactly one successful `d1-time-travel-get-bookmark`
operational proof from the preceding ten minutes, bound to the same catalog,
profile, account, credential generation, and database target. Approval is
one-use. Execution revalidates repository, config, stage, and recovery
authority before invoking the pinned Wrangler. Migration verification requires
the exact ledger plus compiler-owned schema assertions returned through one
bounded `VALUES`-backed result set. A failing readback reports only its exit
status and content-addressed output hashes; inspect governed provider evidence
rather than replaying a migration that may already have crossed the boundary.
When a durable workspace-migration boundary response exists,
`cfctl plans rectify <operation-id>` performs only the exact migration-ledger
and compiler-owned schema assertion reads. It never invokes `wrangler d1
migrations apply`; a matching readback closes the original plan and a mismatch
leaves it `rectification_required`.
Policy projection verification returns only the route count and the active policy,
desired-state, and projection digests through compiler-owned queries.

A D1 evidence declaration is read-only and has no caller SQL surface. It pins
one committed, parameter-free `SELECT` or `WITH` query by SHA-256 and requires
the exact Maildesk evidence columns. The adapter executes that query internally
and discards the provider rows after projecting `MaildeskD1EvidenceV1`: policy,
desired-state, and semantic-projection digests; immutable object key; expected
and projected domain/route counts; approved schema/table flags; bounded audit
counts; and Queue/DLQ correlations. Addresses, subjects, recipients, message
content, arbitrary columns, output paths, parameters, PRAGMAs, and mutating SQL
are not representable. A dirty repository, wrong HEAD/origin/config/binding,
query drift, extra column, malformed map, or non-singleton result fails closed.

The result also contains additive `route_health` schema V2 while keeping the
V1 `evidence` object unchanged. Each record contains only cfctl-computed SHA-256
references for route and domain identity, the active policy digest, closed
route/provider/readiness codes, enabled state, four body-free proof timestamps,
a bounded error code, and `updated_at`. The projection is accepted only when at
most 1,000 unique route records exactly cover the aggregate active route count.
Missing health rows, route-kind or policy-revision drift, disabled active rows,
truncation, duplicates, unknown codes, malformed timestamps, or unexpected
fields reject the entire read. Raw route IDs,
addresses, domains, operators, account IDs, and provider payloads never enter a
route record; `provider_output_retained:false` and `body_returned:false` remain
explicit.

```sh
cfctl call <repository-d1-evidence-operation-id> \
  --selector account_id=<account-id> \
  --selector database_id=<database-uuid> \
  --query config=/absolute/path/to/wrangler.production.toml \
  --query binding=DB \
  --json
```

Do not substitute raw D1 query or direct Wrangler execution. If execution may
have crossed the provider boundary but fails before verified readback, preserve
the receipt and rectify. Recovery is a new, independently approved
`d1-restore-exact-bookmark` plan using the captured pre-change bookmark.

### Private R2 objects and lifecycle replacement

Upload immutable private policy bytes only through the create-only R2 object
contract. The source must be an absolute normalized mode-`0600` regular file;
the plan persists its SHA-256, MD5, and size, not its path or bytes:

```bash
cfctl call r2-put-object \
  --selector account_id=<account-id> \
  --selector bucket_name=<policy-bucket> \
  --selector object_key=config/policy/sha256-<digest>.json \
  --selector Content-Type=application/json \
  --if-none-match '*' \
  --source-file /absolute/private/policy.json \
  --json
```

Cloudflare readback must prove the exact object target, size, and digest without
returning policy content. If the provider outcome is ambiguous, cfctl preserves
the private stage for rectification and never retries the PUT automatically.
Rollback of a new object is a separate exact-object delete plan; an existing
immutable key is never overwritten.

For later readiness checks, use the digest-only read. It streams the exact
object only inside cfctl, refuses objects above 300 MB, requires one ETag, and
returns `R2PrivateObjectDigestV1` with target identity, byte count, ETag,
SHA-256, and `body_returned:false`. It has no `--out` path and never serializes
object bytes. Generic `r2-get-object` remains blocked.

```bash
cfctl call r2-get-private-object-digest \
  --selector account_id=<account-id> \
  --selector bucket_name=<policy-bucket> \
  --selector object_key=config/policy/sha256-<digest>.json \
  --json
```

R2 lifecycle PUT is a destructive complete replacement, not a patch. Read the
current complete lifecycle first, preserve its hash-bound snapshot, then plan
the full replacement body returned by `cfctl guide`:

```bash
cfctl call r2-get-bucket-lifecycle-configuration \
  --selector account_id=<account-id> \
  --selector bucket_name=<spool-bucket> --json
cfctl catalog show r2-put-bucket-lifecycle-configuration --json
cfctl guide r2-put-bucket-lifecycle-configuration --json
cfctl call r2-put-bucket-lifecycle-configuration \
  --selector account_id=<account-id> \
  --selector bucket_name=<spool-bucket> \
  --body-json '<complete-reviewed-rules-object>' --json
```

Review the full `planned_after` and prior snapshot before approval. Restoration
is a separate plan containing the complete prior configuration; objects already
expired under the applied rule are unrecoverable. Lifecycle verification binds
the exact rule-ID set and recursively compares each rule; provider-controlled
rule ordering is not drift, while duplicate, missing, extra, or changed rules
fail closed.

### Email Sending and Email Routing subdomains

Read Email Routing inventory through the typed projection before evaluating
any routing change:

```bash
cfctl call email-routing-routing-rules-list-routing-rules \
  --selector zone_id=<zone-id> \
  --profile <account-bound-profile> \
  --account <account-id> --json
```

The result is `EmailRoutingRuleSetV1`, not Cloudflare's raw rule array. cfctl
owns explicit 50-item page enumeration, requires an empty terminal page within
100 reads, accepts both field-bound and type-only matchers, hashes field-bound
matcher values into `value_sha256`, and retains plaintext values only for
validated Worker action targets. Values belonging to forwarding or other
non-Worker actions are represented only by `value_count`; matcher plaintext and
non-Worker values do not enter stdout or evidence. A malformed, oversized,
partial, or unterminated response
returns `CFCTL_RESPONSE_CONTRACT_MISMATCH` with `performed: true`, failed
verification, and a bounded diagnostic code. Do not parse around that failure
or fall back to raw API output.

Start every email-provider transaction with read-only discovery and the exact
current catalog contracts:

```bash
cfctl resolve "preview Email Sending DNS for example.com" --json
cfctl catalog show email-sending-subdomains-preview-sending-subdomain --json
cfctl guide email-sending-subdomains-preview-sending-subdomain --json
cfctl call email-sending-subdomains-preview-sending-subdomain \
  --selector zone_id=<zone-id> \
  --body-json '{"name":"example.com"}' --json
```

Preview is a read-only dry run. It neither onboards the sending domain nor
repairs DNS. Before planning create or repair, inspect the preview for foreign
record conflicts and obtain a fresh live entitlement read proving the current
Workers Paid availability, quota, and downstream Email Service pricing.

The mutation sequence uses independent PlanV2 operations:

1. `email-sending-subdomains-create-sending-subdomain` with the exact candidate
   domain;
2. provider readback by the returned `subdomain_id` (`tag` in the create
   response);
3. `email-sending-subdomains-fix-sending-subdomain-dns` only if the reviewed
   preview requires it;
4. `email-sending-subdomains-update-sending-subdomain` with
   `{"preview_enabled":false}`;
5. `email-sending-subdomains-get-sending-subdomain-dns-status` and detail
   readback proving authentication ready and preview disabled.

Creation, DNS repair, preview preference, and deletion have different rollback
semantics. Deleting a sending domain or restoring DNS is never implied by the
create approval, and provider acceptance does not prove inbox or external
receipt.

Enable routing for one explicit subdomain without touching apex MX:

```bash
cfctl catalog show email-routing-settings-enable-email-routing-dns --json
cfctl guide email-routing-settings-enable-email-routing-dns --json
cfctl call email-routing-settings-enable-email-routing-dns \
  --selector zone_id=<zone-id> \
  --body-json '{"name":"reply.maildesk.example.com"}' --json
```

The mandatory `name` is included in the plan and repeated as the `subdomain`
query on DNS readback. An absent, empty, or apex target fails closed. Create or
update the catch-all Worker rule only through its separately resolved Email
Routing capability, bind the exact Worker target, and preserve the prior rule
and subdomain DNS snapshots for separate rollback plans. Cloudflare exposes no
proven subdomain-scoped provider delete here: rollback is exact DNS-record and
routing-rule restoration, never zone-wide Email Routing disable. Apex MX and
routing must remain untouched. The public catch-all REST path is zone-scoped
and does not document a subdomain selector; cfctl must not use that path for a
subdomain merely because the subdomain DNS setup succeeded. Until a catalog
contract can bind the subdomain on both mutation and readback, the scoped
catch-all remains blocked rather than silently targeting the apex.

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

Use `d1-import-database` for one reviewed migration owned by any registered
application repository. Planning accepts exactly one absolute `--source-file`
ending in `.sql`; the file must be tracked, byte-identical to the clean Git
`HEAD`, and inside the canonical worktree. cfctl copies those bytes to a new
private mode-0600 stage file and binds the repository, origin, full commit,
relative path, Git blob, SHA-256, byte count, account, database, selected
profile generation, catalog, and the exact pre-import full-export recovery
anchor into the immutable plan:

```bash
printf '%s' \
  '{"pre_recovery_anchor_operation_id":"<export-operation-uuid>","pre_recovery_anchor_evidence_hash":"sha256:<export-evidence>","pre_recovery_anchor_output_sha256":"sha256:<export-file>","pre_recovery_anchor_bookmark_hash":"sha256:<bookmark-string>"}' |
  cfctl call d1-import-database \
    --profile <d1-write-profile> \
    --account <account-id> \
    --selector account_id=<account-id> \
    --selector database_id=<database-id> \
    --source-file /absolute/clean/repository/migrations/0001.sql \
    --body-stdin --json
```

The recovery anchor must be a current successful `d1-full-export` for the same
account, database, profile generation, and catalog. Callers cannot supply an
import action, upload URL, filename, ETag, bookmark, or polling body. Execution
revalidates the Git authority and private stage before init/upload/ingest, and
provider completion verifies only that Cloudflare applied the exact reviewed
bytes to the immutable target. Schema meaning remains a separate governed
`d1-schema-introspection` receipt. If bounded polling exhausts, continue only
with `d1-resume-database-import-poll`; never replay the consumed import root.

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
like `domain` are part of the create but not verified. Generic Access
application *update* remains blocked: the union has no honest universal field
contract. The specialized
`access-applications-update-owned-self-hosted-whole-host` capability admits only
one complete, exact-ID, self-hosted whole-host application. It reads the exact
application plus the terminally paginated collection, rejects overlapping
hostname/name ownership and every unclassified field, binds the complete prior
snapshot including optional absence, and verifies every intended field by exact
ID. Restoration is a separate snapshot-bound update plan.

Generic polymorphic Access policy create/update also remain blocked. The
specialized operator-group capabilities accept only `allow`, exactly one
`include.group.id`, empty `exclude` and `require`, and the closed optional field
set. Create requires zero exact-name or group-overlap candidates and can derive
only deletion of the returned policy ID as compensation. Update binds one exact
non-reusable policy and its complete prior snapshot; restoration is a separate
plan. Creating, updating, or deleting Access authority always requires explicit
approval.

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
existing destination. OAuth client creation is stricter: the destination must
be absolute, its parent must already exist with mode `0700`, and no ancestor
may be a Git repository. The output file, when Cloudflare actually returns a
secret, is created with mode `0600`.

For `wrangler.deploy`, pass an absolute `config`, the exact Worker `name`, and
the exact identity message cfctl reports after hashing the clean repository's
source SHA and every file under the config's `main` bundle directory and
`assets.directory`. The plan binds those artifact roots, the aggregate artifact
hash, the Wrangler config hash, the clean Git HEAD, and either exact Worker
absence or both the current live Worker settings and complete active-deployment
identity. Execution rereads both local artifacts and both live Worker views
before crossing the upload boundary. An optional `var` selector
binds one plain-text `KEY:VALUE` Worker variable into the plan and evidence;
never pass a secret through `var`. Both the deploy subprocess and the
deployment-status verifier run from the reviewed config file's own directory,
because Wrangler resolves dotenv credentials relative to its working directory
— a plan reviewed against one config must not publish with a token discovered
from wherever cfctl happened to be invoked. Both processes receive the
plan-selected account ID and use cfctl's platform cache directory for Wrangler
state; governed deploys never write account-selection cache files into a
Worker's `node_modules`. Other delegated CLI capabilities keep their existing
working directory. `wrangler.deploy` has a bounded ten-minute subprocess
timeout because a reviewed Worker deployment may include a UI or WASM build;
other capabilities using the generic delegated-CLI runner retain its two-minute
bound. Specialized workspace D1 adapters retain a two-minute query/readback
bound and a five-minute mutation-apply bound for migrations, policy projection,
and reply admission. A timeout after the
mutation-capable deployment subprocess starts is an uncertain boundary crossing:
inspect the consumed plan with `plans status` and `plans rectify`, and never
replay the mutation. `cfctl doctor --json` projects this boundary under
`result.delegated_cli_environment` so deploy wrappers can fail closed when an
older cfctl build does not preserve it.

The selected config ordinarily must be an exact tracked `HEAD` blob. A private
role config named `wrangler.<role>.production.toml` may instead remain ignored
only when it is a regular mode-`0600` file next to the exact tracked
`wrangler.<role>.toml` template. The two parsed documents must become identical
after normalizing exactly this closed overlay: canonical lowercase
`d1_databases[].database_id` values to their matching tracked bindings; bounded
canonical `send_email[].allowed_sender_addresses`; the separate
`MAILDESK_INBOUND_RELAY_MODE` and `MAILDESK_REPLY_RELAY_MODE` values when each
is exactly `disabled` or `enabled`; and
`vars.MAILDESK_VERIFIED_SENDER_DOMAINS`. The tracked template must explicitly
declare that last key as `""`, while the private production file must materialize
a non-empty comma-separated list of no more than 256 canonical lowercase DNS
domains and 4,096 bytes. Wildcards, addresses, schemes, paths, ports,
whitespace or control characters, leading or trailing dots, empty or malformed
labels, empty members, and duplicates after lowercase normalization are
rejected. Worker name, entry point, assets, all unrelated variables and
bindings, queues, buckets, compatibility settings, and every other field
remain exact tracked authority.

Normalization is used only for the final parsed-document equality check. The
plan's config, settings, and bindings identities continue to derive from the
actual materialized private production document; the target retains only its
hash plus the tracked-template path/hash. Private database IDs, sender
addresses, verified-sender domains, and split-relay values never enter retained
subprocess output. The plan labels config authority explicitly as
`exact_head_blob` or `private_d1_identity_overlay`; execution never infers that
authority from a filename. Immediately before private launch, cfctl opens the
config and exact planned template with no-follow semantics, captures each
bounded byte set once, and hashes and parses only those bytes. Both must match
their planned identities before cfctl writes a private temporary config beside
the original so Wrangler preserves
relative path semantics without reopening the mutable source pathname. The
temporary config remains owned until the complete child is reaped and is then
removed.

For that private execution lane, stdout and stderr are never persisted or
returned, regardless of encoding or subprocess exit status. cfctl projects only
the typed fields required by the operation: a canonical lowercase UUID Worker version identity,
the exact deployment-status match, the exact version/message match, or the
closed workspace-D1 query rows. Apply receipts retain only categorical status,
exit disposition, config hash, and the explicit fact that provider output was
not retained. Parse failures remain value-opaque. Generic delegated reads,
tracked public configs, and configless service verification retain their
ordinary diagnostic behavior. A workspace-D1 plan's separately governed
selected database ID remains an operational target identity; this promise
covers private subprocess representations, not that explicit plan selector.
Execution fails before Wrangler when the captured bytes do not match the
reviewed content identity, the closed overlay is invalid, the source commit or
artifact drifted, or the private execution file cannot preserve the captured
bytes. An arbitrary ignored config, a broader private difference, permissive
file mode, missing or non-empty template sentinel, empty private domain list,
or noncanonical closed-overlay value remains blocked.

Artifact roots may be shared directories outside the config directory only
when their canonical paths remain inside the same registered repository as the
config. Hash manifests are repository-relative, so identical repository
artifacts retain one identity regardless of config nesting. Canonical paths
that escape the registered repository remain blocked before planning.

For Worker code-only publication, keep artifact creation and production
traffic promotion as two independently reviewed plans. The upload verifier
reads the returned Worker version and requires both its exact ID and reviewed
message; it does not change production traffic:

```bash
cfctl call wrangler.versions-upload \
  --query config=/absolute/path/to/wrangler.toml \
  --query name=<exact-worker-name> \
  --query message='source=<full-source-sha> artifact-sha256=<artifact-sha256>' \
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
requires the planned version at 100 percent. The promotion plan also binds the
exact clean source commit, config bytes, service, Worker settings, and complete
active-deployments state. Execution recomputes the local target before and
after the live reads; any intervening local or provider drift leaves the
approved plan unconsumed. The delegated promotion removes the mutable config
path, passes the reviewed service explicitly, and runs from a private
configless directory so a later config edit cannot retarget Wrangler. The
deployment-status verifier uses that same exact service in a separate private
configless directory and records it in the readback receipt.

Rollback uses the native, approval-required `worker-version-rollback`
capability, never `wrangler rollback` and never the generic deployment POST.
Name the current deployment observed during review, one exact prior version,
and a reason:

```bash
cfctl call worker-version-rollback \
  --selector account_id=<account-id> \
  --selector script_name=<exact-worker-name> \
  --body-json '{"target_version_id":"<prior-version-uuid>","expected_current_deployment_id":"<current-deployment-uuid>","message":"<reviewed rollback reason>"}' \
  --json
```

Planning reads Worker settings, the retained deployment history, and the exact
target-version detail. It requires one current version at 100 percent, rejects
an already-active target, proves the target was the sole version at 100 percent
in a prior retained
deployment, and binds the complete redacted provider state. Execution rereads
all three views while holding the same account/Worker-scoped local execution
lock used by `wrangler.deploy` and `wrangler.versions-deploy`, and consumes the
plan only if their hash is unchanged. GET-only rectification also holds that
lock until evidence and closure are durable. cfctl compiles the provider
body to one version at 100 percent, adds the operation UUID to the deployment
annotation, omits both the undocumented idempotency header and the `force`
query, attempts the POST exactly once, and verifies that the returned
deployment is now the latest deployment with the exact target and operation
marker. A lost response, HTTP 429, or HTTP 5xx is classified as an ambiguous
outcome and reconciled only through `cfctl plans rectify`, which performs a
projected GET and never replays the POST. Provider incompatibility
blockers fail closed; cfctl never retries with `force=true`. Storage and effects
outside traffic routing are not reverted. Restoring the pre-rollback version is
a new reviewed rollback plan using the pre-change version captured in the
first plan. Cloudflare documents no expected-current or conditional field on
deployment creation, so the local lock cannot serialize dashboard, Wrangler,
or another external deployer: the release owner must hold a proven
single-writer change freeze from the final reread through verification.

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

Planning first admits one regular, symlink-free artifact root owned by a clean,
registered repository on a named branch. It records every uploadable and
multipart-control file by normalized path, byte size, and SHA-256, rejects an
empty tree, path ambiguity, Wrangler-ignored sources, more than 20,000 assets,
and files above the 25 MiB provider limit. It also binds the canonical Wrangler
launcher, its exact interpreter, and a deterministic path/size/SHA-256 manifest
of Wrangler's complete installed production/optional dependency graph. The
bounded graph includes `wrangler-dist/cli.js`, the `blake3-wasm` implementation
that determines provider asset hashes, `esbuild`, and the selected
platform-native builder used for `_worker.js`, along with the version that
generated the catalog carrier. When `_worker.js` is present, cfctl uses that
bound builder before the provider boundary, requires its metafile to show that
every resolved module is already inside the admitted artifact, and binds the
closed bundle's size and SHA-256. Bare imports or ancestor `node_modules`
resolution fail planning. A runtime `import(...)` that survives bundling also
fails closed because esbuild does not report every non-literal dynamic import
in its metafile. A live exact-project read must then establish direct-upload
mode, and the requested branch must equal the project's production branch.
Explicit `source: null` remains authoritative. A provider response that omits
`source` is compatible only when the same response also carries matching
canonical and latest production deployments with one exact UUID, project, and
branch; a successful `ad_hoc` deployment whose repository clone/build stages
remain idle; no nested Git source; and no configured repository build command
or root. A direct-upload output directory such as `target/site` is retained as
project configuration, not misclassified as repository-build evidence.
Partial, contradictory, or Git-source evidence remains blocked before
operation creation. The corroborating deployment ID and inference basis are
hash-bound into the same project-mode receipt and must reproduce at the
execution-boundary read. Existing deployments are read before planning; the
same project/branch/commit identity is treated as a replay and rejected.

Execution recomputes the repository, complete producer closure, exact
interpreter, and complete artifact manifest before credential access and again
after the live concurrency read. Because private staging can take time, cfctl
then hashes the staged transport and recomputes the complete mutable producer
closure once more, in that order, immediately before subprocess construction.
Any drift stops before a provider process starts. Only then may the bound
interpreter and producer run from a private configless directory with the selected
account, cfctl's Wrangler cache, and the selected credential. Wrangler remains
the authoritative multipart producer: it performs the content-addressed asset
upload and sends the provider-required `manifest` form field. cfctl stages
only the planned bytes and tells Wrangler not to rebundle the already-closed
worker, so no second project dependency resolution can alter the request.
There are no implicit
`wrangler.toml`, Functions, dotenv, or current-directory inputs. Wrangler's
governed structured-output file must return one canonical deployment ID with
the exact project, production branch, environment, and commit. The verifier
requires that ID to be absent from the pre-plan deployment set, waits for the
same ID and identity to appear in the collection, and polls only that exact
detail resource. Only terminal `success` passes; ambiguity,
identity drift, provider error, timeout, failure, or cancellation requires
rectification and never authorizes replay. Automatic rollback is not
implemented. Restoring a prior artifact is a separate reviewed deployment and
does not erase the failed deployment or Functions side effects or refund usage.

For an existing Git-integrated Pages project, the provider-native
`pages-deployment-create-deployment` capability starts a build from the
production branch without accepting an artifact body:

```bash
cfctl call pages-deployment-create-deployment \
  --account <account-id> \
  --selector project_name=example-web \
  --json
```

The catalog exposes this mutation only while the exact Pages Write operation,
returned deployment ID, terminal-stage response shape, and exact deployment
GET and DELETE companions remain intact. The plan records a zero direct
API-operation ceiling and separately names downstream build, Functions, and
bandwidth exposure. After apply, verification polls only the returned
deployment ID and requires the same project, the production environment, and
terminal `success`. A failure, canceled deployment, identity drift, or unknown
stage requires rectification and never authorizes replay. Automatic rollback
is deliberately unsupported: restoring production traffic requires a separate
reviewed Pages rollback to a known successful deployment, and that rollback
does not erase the new deployment, reverse Pages Functions side effects, or
refund usage.

Before a bodyless Git trigger can become a plan, cfctl reads the exact project
and requires a Git source object. A direct-upload project (`source: null`) is
rejected with guidance to use the artifact-bound `wrangler.pages-deploy`
carrier; cfctl never sends the invalid bodyless request to such a project.

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
The catalog separately validates Cloudflare's raw `Workers Scripts Write`
attach operation, then exposes the governed lifecycle as the exact all-of
permission set `Workers Scripts Write` plus `DNS Read`. The latter authorizes
the mandatory exact-host DNS conflict read; `DNS Write` is neither requested
nor implied by attachment.
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

Create an OAuth client only after preparing a dedicated operator-secret
directory outside every repository. Creation is an identity/ownership change,
so `call` creates an approval-gated plan and does not create the client:

```bash
install -d -m 700 /absolute/operator-secrets
printf '%s' '{
  "client_name":"example client",
  "grant_types":["authorization_code","refresh_token"],
  "redirect_uris":["https://example.com/oauth/callback"],
  "response_types":["code"],
  "scopes":["<exact-live-scope-id>"],
  "token_endpoint_auth_method":"none"
}' | cfctl call oauth-clients-create \
  --selector account_id=<account-id> --body-stdin \
  --value-out /absolute/operator-secrets/oauth-client.json --json
```

The plan binds the exact request, all-plan entitlement, zero direct creation
cost, a returned `/client_id` identity, and the exact all-of permission set
`OAuth Client Write` plus `OAuth Client Read`. The catalog still requires the
raw mutation operation itself to declare Write and its exact companion GET to
declare Read; it projects both onto the governed lifecycle so a token prepared
from the reviewed plan can complete preconditions and verification. After
execution, cfctl reads that
exact client through `oauth-clients-get` and compares every planned non-secret
field. It never automatically deletes a failed client; deletion is a separate
destructive plan. Cloudflare may return `client_secret` only once. If one is
returned, cfctl writes only `{client_id,client_secret}` to the new mode-0600
JSON sink and removes the secret from output, journal, plan, and evidence. For
`token_endpoint_auth_method=none`, an omitted optional secret records
`secret_returned:false` and leaves the fresh sink path absent. For
secret-authenticated methods, an omitted secret requires rectification.

OAuth metadata updates first read and hash-bind the exact current client, then
re-read it immediately before execution. Restore metadata only with another
snapshot-bound update. Public promotion is a distinct, permanent one-field
change and cannot be combined with metadata edits:

```bash
printf '%s' '{"client_name":"updated example client"}' | \
  cfctl call oauth-clients-update \
    --selector account_id=<account-id> \
    --selector oauth_client_id=<oauth-client-id> --body-stdin --json

printf '%s' '{"visibility":"public"}' | \
  cfctl call oauth-clients-update \
    --selector account_id=<account-id> \
    --selector oauth_client_id=<oauth-client-id> --body-stdin --json
```

The second plan is eligible only from a live `private` snapshot. Cloudflare
does not support demotion, so its review must treat public promotion as
irreversible and verify that every other field and the client ID remain
unchanged.

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

