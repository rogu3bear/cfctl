# Governed telemetry and security-response control plane

This document describes cfctl's typed telemetry surface. The live catalog is
authoritative: run `cfctl catalog sync --json`, then inspect
`cfctl catalog coverage --json`. Its `telemetry_ledger` is the machine-readable
coverage ledger; this document explains the architecture and stable capability
families without freezing schema-dependent counts.

## Architecture

Telemetry operations use the same control-plane contracts as every other cfctl
operation, with protocol-specific adapters where REST is not an honest model.

| Layer | Contract |
| --- | --- |
| Discovery | Stable capability IDs, aliases, ranked resolution, and a broad-intent domain overview that never selects a mutation |
| REST | Generated OpenAPI identity plus small fail-closed overlays for exceptional wire behavior |
| GraphQL | Fixed documents and variable maps, schema fingerprints, bounded windows/rows/bytes/timeouts, and continuation only when the selected ordering key is schema-proven unique |
| SQL | Compiler-rendered single-statement `SELECT`; callers provide typed fields and values, never raw SQL |
| Multi-format output | Declared JSON, NDJSON, or CSV negotiation, bounded parsing/streaming, truncation and partial-failure metadata, and mode-0600 file receipts |
| Permissions and entitlement | Exact token permission metadata and live-safe product probes; a denied probe never pretends to distinguish permission from plan entitlement |
| Mutations | Immutable plan, current-state and entitlement preconditions, risk/effect/cost, approval, apply, exact verification, and separate compensation/removal plan |
| Security response | Evidence, actor, reason, normalized scope, expiry, conflict/self-block guards, Managed Challenge default, verification, and auditable removal |
| Evidence | Content-addressed live-read identities and the mutation lifecycle checkpoints that durably exist across plan, approval, apply, verification, compensation, and closure; secrets, plan payloads, and sensitive response fields stay omitted or redacted |

Arbitrary HTTP, GraphQL documents, SQL, headers, dashboard actions, and Wrangler
commands are not public escape hatches. A source operation remains blocked when
its typed contract drifts or cannot prove the requested lifecycle.

## Bounded analytics reads

First-class GraphQL Analytics capabilities:

- `graphql-analytics-zone-http-requests` — zone requests, data transfer, cache
  status, response status, hostname, and path dimensions.
- `graphql-analytics-account-http-requests` — the same bounded view across an
  explicit list of zones in one account.
- `graphql-analytics-zone-firewall-events` — one bounded, sampled firewall and
  Security Events page. Cloudflare can emit multiple events for one request,
  so `(datetime, rayName)` is not unique. cfctl deliberately issues no
  continuation cursor and never claims this read is exhaustive; narrow the
  requested window or use a retained log pipeline when completeness matters.
- `graphql-analytics-zone-dataset-settings` — retention/lookback, page-size,
  field, and dataset availability settings reported by Cloudflare.

Each document is fixed in the catalog. Callers can supply only the selectors
and variables declared by the request schema. GraphQL mutations, fragments or
fields supplied by a caller, unbounded introspection, and arbitrary documents
are rejected. Cloudflare's dynamic GraphQL schema is represented by a
content-addressed contract fingerprint; response-shape drift fails closed.

Typed query capabilities:

- `analytics-engine-sql-query-get` — compiler-rendered Analytics Engine SQL
  over one dataset, time field/window, selected columns, bounded filters,
  aggregates, grouping, ordering, and limit. Supports declared JSON, NDJSON,
  and CSV output.
- `accounts-logs-explorer-query-post` and
  `zones-logs-explorer-query-post` — compiler-rendered Log Explorer `SELECT`
  queries. The raw GET SQL variants remain blocked by design.
- `telemetry.keys.list`, `telemetry.values.list`, and `telemetry.query` —
  bounded Workers observability discovery and query reads, despite their
  upstream POST transport.
- `logpull-retrieve-logs` — one explicit Logs Engine time window from one R2
  bucket. This is file-only and requires `--credential-in` as described below.

The response envelope records negotiated format, row and byte bounds, bytes
observed, truncation, partial-stream status, limit saturation, a
`dataset_completeness: not_proven` coverage classification, freshness/sampling
statements, and the query receipt. A file output is created as a new mode-0600 file
and stdout receives only its path, content hash, size, row count, and
transport-completeness flag.

### R2 Logs Engine retrieval

Cloudflare's retrieval operation requires an API token plus two R2 credential
headers. Those headers remain globally reserved in cfctl. Only
`logpull-retrieve-logs` can materialize them, from a closed mode-0600 JSON
bundle that contains exactly `access_key_id` and `secret_access_key`.

```bash
cfctl call logpull-retrieve-logs \
  --selector account_id=<account-id> \
  --query start=2026-07-21T16:00:00Z \
  --query end=2026-07-21T16:05:00Z \
  --query bucket=<r2-bucket> \
  --query 'prefix=http_requests/example.com/{DATE}' \
  --credential-in <mode-0600-json-path> \
  --out <new-output-path> --json
```

The credential values never enter `CallInput`, the request URL/body, a plan,
stdout, logs, or evidence. The adapter permits at most a one-hour window, a
256 MiB response, a 120-second request, and a finite catalog-declared
lookback. The receipt hashes the bucket and prefix rather than echoing them.
Logs Engine is an upstream legacy surface being replaced by Log Explorer, so
new analytics integrations should prefer the typed Log Explorer capabilities.

## Governed configuration lifecycles

Telemetry and observability configuration:

- `web-analytics-create-site`, `web-analytics-update-site`, and the generated
  exact site delete/read capabilities.
- `web-analytics-create-rule` and `web-analytics-delete-rule`; the upstream
  update/bulk surfaces remain blocked where an exact typed readback is absent.
- `web-analytics-toggle-rum`.
- `workers-observability-settings-update`.
- `worker-tail-logs-start-tail` and `worker-tail-logs-delete-tail`. The
  returned bearer WebSocket URL is written only to a new mode-0600 value sink.
- `post-accounts-account_id-logpush-jobs` and
  `post-zones-zone_id-logpush-jobs` for creation,
  `logpush-account-job-settings-update` for the verified safe update subset,
  plus the generated exact job read/delete capabilities.
- `notification-policies-create-a-notification-policy` and its governed
  update/delete lifecycle.

Security-response lifecycles:

- `security-response-create-expiring-ip-access-rule` and
  `security-response-remove-expired-ip-access-rule`.
- `security-response-create-empty-custom-ruleset`, followed by
  `security-response-create-expiring-waf-rule` and
  `security-response-remove-expired-waf-rule`.
- `rate-limits-for-a-zone-create-a-rate-limit` and its generated exact
  read/update/delete lifecycle (deprecated upstream; prefer Ruleset Engine for
  new deployments).
- `lists-create-a-list` and its generated container lifecycle.
- `security-response-add-expiring-list-member` and
  `security-response-remove-expired-list-member`. The raw asynchronous bulk
  list item endpoints remain blocked by design.

An asynchronous List member plan is limited to one item. Apply returns a bulk
operation ID; verification polls only the pinned status route, accepts only
the declared state machine, traverses the complete cursor-paginated
collection, and correlates exactly one member through cfctl's audit comment.
Only that verified member ID can seed a removal/compensation plan.

## Security-action safeguards

Telemetry-derived enforcement is not an identity system. cfctl records an
evidence receipt reference but never interprets an anonymous IP, fingerprint,
session, or analytics row as identifying a person.

Every governed security action requires:

- explicit zone/account and target selectors;
- normalized IP, prefix, ASN, country, hostname, path, or JA4 scope supported
  by that exact capability;
- evidence reference, operator identity, and reason;
- a finite expiry (Managed Challenge is the default recommendation);
- current-state, duplicate, and conflict reads;
- broad-scope confirmation and conservative TTL/action bounds;
- self-block and critical-target guards where cfctl can prove them;
- immutable review diff, explicit approval, exact post-apply readback, and a
  separately reviewed removal or compensation plan.

Permanent blocks are never inferred from telemetry. Exact public-IP blocking
requires explicit escalation; broad prefixes and ASNs remain challenge-only
under short TTLs. Unknown state cannot satisfy a precondition.

## Composable workflows

Workflows are workflow-first operator previews. Calling one expands its
component graph, required selectors and bodies, approval boundaries, and any
locally indexed proof observations. It emits an exact governed component
command only when that component is currently available and contract-ready;
blocked, incomplete, missing, or cyclic components expose a guide command and
blocking gaps but no runnable `call_argv`. A workflow does not execute the
components or aggregate their authority. Each bounded read is run explicitly,
and each mutating component still creates its own plan and consumes its own
approval.

- `workflow.telemetry.bootstrap-worker-observability`
- `workflow.telemetry.bootstrap-web-analytics-rum`
- `workflow.telemetry.privacy-bounded-pipeline`
- `workflow.telemetry.worker-traces-logpush`
- `workflow.security.investigate-source`
- `workflow.security.propose-expiring-managed-challenge`
- `workflow.telemetry.verify-freshness`
- `workflow.telemetry.audit-account`
- `workflow.telemetry.audit-governance`
- `workflow.security.remove-expired-enforcement`
- `workflow.telemetry.export-evidence-packet`

`cfctl resolve "telemetry overview" --json` returns the four telemetry domains,
workflow-first ranked capabilities, bounded reads, contract-ready mutation
candidates, and separately labeled blocked or unclassified gaps. It emits no
mutation command until the operator names and guides a specific capability.

`workflow.telemetry.export-evidence-packet` expands nested workflow components
and returns a receipt-only manifest. Read receipts carry account/profile scope,
input and catalog identities, observation time, outcome, workflow-relative
freshness, and the immutable evidence reference. Targeted mutation receipts
carry safe plan identity, approval metadata, status, verification posture, and
content-addressed transaction checkpoints classified as plan, approval,
execution admission, apply, verification, compensation, or closure. A class is
present only when the durable journal contains it. The packet contains no plan
input, target, transaction artifact, credential, or raw telemetry. Plan expiry
metadata is not a resource-expiry receipt, and freshness never proves
retention, sampling completeness, or mutation readiness.

## Coverage ledger and honest boundaries

`cfctl catalog coverage --json` returns one ledger row per targeted domain
operation with:

- Cloudflare product/domain and API operation or GraphQL dataset;
- capability ID, read/mutation kind, adapter and contract state;
- permission ownership/mode and exact permission names;
- entitlement and cost models;
- verification and rollback/removal methods;
- fixture, live-read, and live-mutation-drill status;
- the remaining upstream or local blocker.

The same response includes `operational_proof`, a bounded projection of the 512
most recently indexed local live-read receipts. It reports the retained count,
total index rows, limit, and whether the projection was truncated. Counts never
silently claim full history when truncated. Profile, account, and redacted input
identity all remain part of the observation key. Catalog coverage and
operational proof remain separate: a capability may be contract-complete
without ever having been read successfully on this account, and a prior
successful receipt may be stale or bound to an older catalog, profile, account,
or input. Workflow previews apply their explicit freshness policy; the catalog
does not invent one universal window.

Known upstream boundaries remain explicit:

- Cloudflare exposes no public Pages analytics results API in the current
  authoritative schema.
- There is no universal telemetry-dataset localization API; controls are
  product-specific.
- Product availability, retention, sampling, and limits vary by plan and
  dataset. A live successful read proves access; a denial remains ambiguous
  between token permissions, entitlement, and account configuration unless a
  product-specific probe can distinguish them.
- GraphQL Analytics is sampled and is not billing truth.
- Logs Engine is being replaced by Log Explorer.
- Features without a public API remain inspection-only or upstream-blocked;
  cfctl does not substitute an ungoverned dashboard action.

No live mutation is part of catalog or release verification. A mutation drill
requires a separate, exact authorization for disposable resources, followed by
post-apply verification and removal receipts.

### Explicit mutation canary lane

A live canary is an operator-authorized operational exercise, never a hidden CI
step. Before a drill, name one exact mutation capability, account, disposable
target, cost ceiling, expiry/removal contract, and stop condition. Then:

1. Read current state and inspect the capability guide.
2. Create and review the hash-bound plan.
3. Approve only that operation ID and cost ceiling.
4. Run it once and retain the apply receipt.
5. Perform the declared independent readback.
6. Create and approve the exact compensation/removal plan when required.
7. Retain post-removal verification and report uncertain boundaries honestly.

Until all receipts exist, catalog coverage continues to report the mutation
drill as not authorized or incomplete. No standing authority, broad target, or
production resource is inferred from this procedure.
