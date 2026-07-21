---
artifact: edge-cases
version: "1.0"
created: 2026-07-21
status: draft
---

# Edge Cases: Governed telemetry and security-response control plane

## Feature Overview

`cfctl` exposes catalog-backed telemetry discovery, bounded analytics and log
reads, governed observability configuration, and expiring security-response
actions. The public flow spans `resolve`, `catalog`, `guide`, `call`, and
`plans`; it deliberately has no arbitrary HTTP, GraphQL, SQL, header, Wrangler,
or dashboard escape hatch.

This catalog covers operator-visible validation, bounds, failures, concurrency,
and recovery across the typed telemetry surface. It treats catalog or contract
drift as a blocking error, sampled data as non-exhaustive, and a receipt as
evidence rather than proof of dataset completeness.

Priority means:

- **P1:** could leak a secret, mutate the wrong target, create persistent or
  overly broad enforcement, lose evidence, or claim false completeness.
- **P2:** likely operator failure or misleading result with a bounded blast
  radius.
- **P3:** uncommon, low-impact degradation that must still fail clearly.

**Related Documents:**

- [Telemetry control plane](telemetry-control-plane.md)
- [Runtime policy](runtime-policy.md)
- [Upstream schema gaps](upstream-schema-gaps.md)
- [cfctl runbook](runbooks/cfctl.md)

## Edge Case Categories

### Input Validation

| Scenario | Expected Behavior | Priority | Notes |
|---|---|---:|---|
| Broad input such as `telemetry overview` could match reads and writes | Return the four-domain overview and withhold mutation commands | P1 | Operator must select and guide one typed capability |
| Missing, empty, duplicated, or wrong-scope account/zone/resource selector | Reject before transport; do not infer a target | P1 | Includes cross-zone or cross-account receipt reuse |
| Analytics body is absent, not an object, or has undeclared properties | Reject against the closed request schema | P2 | No raw request pass-through |
| Dataset is absent, empty, duplicated, too long, or not a plain identifier | Reject before rendering or transport | P1 | Workers: 1–20 unique datasets; SQL identifiers use the pinned identifier grammar |
| Caller provides raw SQL, a raw GraphQL document, mutation, subscription, fragment, arbitrary field, header, or Wrangler command | Reject; only the fixed or compiler-rendered contract may execute | P1 | Prevents query injection and bypass of catalog identity |
| SQL query has zero columns, more than 50 columns, over 20 aggregates/filters/groups, or over 10 sort keys | Reject against schema bounds | P2 | Columns and group fields must be unique where declared |
| SQL field, dataset, or alias contains punctuation, whitespace, a quote, comment, or statement separator | Reject as not a plain identifier | P1 | Values remain typed parameters/literals; they are not identifiers |
| Unsupported aggregate, filter operator, ordering direction, or output format | Reject and name the capability contract mismatch | P2 | Analytics Engine allows declared JSON/NDJSON/CSV; other adapters may be JSON-only |
| Missing, malformed, equal, or reversed start/end timestamps | Reject before transport | P2 | GraphQL uses RFC3339; Workers observability uses Unix milliseconds |
| End time is more than five minutes in the future | Reject as outside the bounded time contract | P2 | Small clock skew remains tolerated |
| Row limit or timeout is missing where required, zero, negative, non-integer, or above the capability maximum | Reject before transport | P2 | Never silently widen a query |
| `--out` points to an existing path, symlink, non-regular target, or location that cannot be created mode 0600 | Refuse to overwrite or follow the target; preserve any existing file | P1 | Successful output is create-only and private |
| R2 credential bundle is absent, not mode 0600, malformed JSON, contains extra/missing keys, or has empty values | Reject before network access and never echo values | P1 | Exactly `access_key_id` and `secret_access_key` are accepted |
| R2 credentials, reserved headers, bucket, or prefix are supplied in argv/body instead of the specialized inputs | Reject the ordinary execution path | P1 | Bucket and prefix appear only as hashes in receipts |
| R2 bucket violates bucket naming rules or prefix is missing/invalid | Reject before transport | P2 | Retrieval remains target-bound to one bucket/prefix |
| Security action omits actor, evidence receipt, reason, target, or required scope confirmation | Reject before plan creation | P1 | Evidence must be `sha256:` plus 64 lowercase hex characters |
| Security actor is empty/over 80 chars, reason is under 4/over 160 chars, or target is empty/over 253 chars | Reject against the closed governance schema | P2 | Extra governance fields are rejected |
| Security target is malformed, private, local, documentation, multicast, reserved, or the operator's own IP | Refuse the action and identify the unsafe target class | P1 | Applies to IPv4 and IPv6 where supported |
| IPv4 prefix is broader than `/24`, ASN is outside 1–4294967295, hostname is invalid, or JA4 is malformed | Reject or require the narrower capability-specific path | P1 | `/24` through `/32` are the bounded prefix range |
| `block` lacks explicit confirmation, broad scope lacks confirmation, JA4 entitlement is unacknowledged, or a list consumer scope is unreviewed | Reject before plan creation | P1 | Managed Challenge is the default |
| Caller asks for `skip`, a permanent action, or a broad block that the capability forbids | Reject unsafe escalation; do not downgrade or reinterpret it silently | P1 | Permanent blocks are never inferred from telemetry |

### Boundary Conditions

| Scenario | Expected Behavior | Priority | Notes |
|---|---|---:|---|
| Analytics Engine limit is 1 / 5,000 / 5,001 | Accept 1 and 5,000; reject 5,001 | P2 | Max 30-day lookback, 24-hour window, 32 MiB, 30 seconds |
| Log Explorer limit is 1 / 10,000 / 10,001 | Accept 1 and 10,000; reject 10,001 | P2 | Max 90-day lookback, 7-day window, 64 MiB, 60 seconds |
| Workers observability datasets count is 0 / 1 / 20 / 21 | Accept 1–20 unique entries; reject 0 and 21 | P2 | Max 7-day lookback, 1-hour window, 2,000 rows, 16 MiB, 30 seconds |
| Zone HTTP GraphQL rows are 1 / 5,000 / 5,001 | Accept 1 and 5,000; reject 5,001 | P2 | Max 31-day lookback and 24-hour window |
| Account HTTP GraphQL zone count is 0 / 1 / 10 / 11 | Accept 1–10 unique zone IDs; reject 0 and 11 | P1 | One explicit account scope is still required |
| Security Events rows are 1 / 1,000 / 1,001 | Accept 1 and 1,000; reject 1,001 | P2 | One sampled page only; no continuation cursor |
| Time window equals maximum versus exceeds it by one second | Accept the exact maximum; reject the excess | P2 | End must still be after start and within future skew |
| Start equals maximum lookback versus exceeds it by one second | Accept the exact boundary; reject older input | P2 | Product retention may be shorter than cfctl's bound |
| Response has exactly the row/byte maximum versus one more row/byte | Return the bounded content and mark truncation or incompleteness; never claim a complete dataset | P1 | File receipts record bytes, rows, hash, and transport completeness |
| Empty successful analytics response | Return a successful empty result with `dataset_completeness: not_proven` | P2 | Empty does not prove no events exist |
| R2 retrieval window is 1 hour versus 1 hour plus one second | Accept the bounded hour; reject the excess | P1 | Max 10-year declared lookback, 256 MiB, 120 seconds |
| Security expiry omitted / now / 24 hours / 7 days / over 7 days | Default omission to 24 hours; reject non-future or over-7-day expiry | P1 | Expiry is preserved in the plan and removal lineage |
| List security action contains 0 / 1 / 2 members | Accept exactly one; reject zero or multiple | P1 | Required for exact async correlation and compensation |
| Rate-limit threshold is 0 / 1 / 1,000,000 / 1,000,001 | Accept 1–1,000,000; reject outside the range | P2 | Deprecated upstream; new work should prefer Ruleset Engine |

### Error States

| Scenario | Expected Behavior | Priority | Notes |
|---|---|---:|---|
| No active auth profile, ambiguous account, expired token, or invalid credentials | Fail before or at the read; direct the operator to auth/profile recovery | P1 | Never silently select the global-key lane |
| Cloudflare returns 401 or 403 | Preserve the structured denial and state that permission vs entitlement vs disabled product may remain ambiguous | P1 | Do not relabel a denial as an entitlement fact |
| Product/dataset is unavailable, disabled, outside retention, or returns no rows | Return bounded evidence with honest uncertainty | P2 | Use product-specific settings/probes where available |
| Catalog identity, permission, schema fingerprint, response shape, or lifecycle contract drifts | Mark capability blocked/fail closed and direct the operator to `guide`/catalog refresh | P1 | No raw API or UI bypass |
| Network/DNS/TLS failure before a response | Return a structured transport error; preserve inputs and allow safe retry | P2 | No plan is consumed by a failed read |
| 429 or transient 5xx | Apply bounded backoff where supported; otherwise return structured failure with retry guidance | P2 | Respect upstream retry information |
| Timeout occurs before any response bytes | Return timeout failure; no success receipt | P2 | Operator can narrow the window/limit and retry |
| Stream fails or contains malformed NDJSON/CSV after valid rows | Return only validated bounded rows, mark `partial: true`, and set success false | P1 | Do not discard evidence or present partial data as complete |
| Response exceeds byte or row limit | Stop at the bound and mark `truncated: true`; file completeness is false when transport is cut | P1 | Never continue unbounded in memory |
| Content type differs from the capability's negotiated response contract | Reject or return a typed response-contract error | P2 | Do not parse HTML/error text as telemetry rows |
| GraphQL returns errors, missing expected fields, wrong dataset shape, or non-unique cursor state | Fail closed; preserve redacted error evidence and issue no unsafe cursor | P1 | Security Events intentionally has no cursor |
| Output file creation/write/fsync fails | Return failure, never report a complete file receipt, and leave no claim of verified output | P1 | Any partial file remains private and explicitly incomplete |
| Plan current-state, entitlement, cost, target, receipt, or verification precondition is unknown | Keep plan blocked; require fresh state or rectification | P1 | Unknown state cannot satisfy a precondition |
| Apply succeeds remotely but the client crashes before recording/verification | Mark the operation uncertain and require `plans status` then `plans rectify` | P1 | Do not replay the mutation blindly |
| Post-apply readback is missing, ambiguous, or does not match the planned resource | Verification fails; do not call the mutation complete | P1 | Removal cannot use an inferred identity |
| Removal target has expired locally but is already absent remotely | Record idempotent absence only when the exact target read proves it | P2 | Never delete a nearest match |
| Feature has no public API or remains upstream-blocked | Return `CFCTL_CAPABILITY_BLOCKED` with the generated next action | P2 | Governed UI is allowed only when the catalog explicitly provides it |

### Concurrency

| Scenario | Expected Behavior | Priority | Notes |
|---|---|---:|---|
| Operator submits the same read twice | Both reads may execute, but each produces its own bounded evidence; neither implies deduplicated upstream events | P3 | Ray IDs are not assumed unique across Security Events rows |
| Operator submits the same mutation twice or retries after an uncertain result | Plan/run identity and consumed-plan state prevent blind replay | P1 | Inspect status/rectify before another plan |
| Two operators plan from the same current-state receipt | Only a plan whose preconditions still match may run; the stale plan fails closed | P1 | Approval does not override drift |
| Two actions target overlapping IP/prefix/ASN/hostname/list scope | Duplicate/conflict reads block or require explicit resolution before a new plan | P1 | Broad scope must not shadow a narrower active action silently |
| Two processes create or update the same durable plan/evidence path | Storage lock and create-only/guarded save prevent clobbering; nonce ownership protects lock release | P1 | Crash-stale locks expire after 15 minutes |
| Catalog sync occurs between resolve/guide and call | Call validates the current contract and fails on identity/schema drift | P1 | Re-resolve and re-guide after sync |
| Async List operation completes while status is being polled | Accept only the declared state machine, then fully paginate and correlate exactly one audit-commented member | P1 | Unknown states or multiple matches fail verification |
| Resource changes or disappears between apply and verification | Verification fails or records exact absence only for the declared lifecycle | P1 | Compensation is not inferred from stale input |
| Expiry removal races with manual removal | Prove exact target absence or retain an unresolved removal state; never delete another resource | P1 | Removal is lineage-bound to verified identity |

### Integration Failures

| Scenario | Expected Behavior | Priority | Notes |
|---|---|---:|---|
| Cloudflare GraphQL schema changes while the pinned document remains unchanged | Fingerprint/shape validation blocks the capability pending catalog repair | P1 | Fixed documents are not silently regenerated at call time |
| GraphQL sampling or duplicate event keys prevents lossless pagination | Return one bounded sampled page without continuation and explain the completeness limit | P1 | Use retained Logpush/Log Explorer data when completeness matters |
| Workers observability ingestion is delayed or sampling changes | Report upstream freshness/sampling statements; do not treat temporary emptiness as failure or proof | P2 | Verify settings separately |
| Logs Engine is unavailable or retired | Return the upstream failure; recommend typed Log Explorer where it satisfies the use case | P2 | Do not route credentials to a different endpoint |
| Logpush destination validation fails or a destination secret cannot be read back | Keep the mutation unverified/blocked and preserve secret-sunk semantics | P1 | Verification must use safe observable fields |
| Web Analytics RUM or rule state changes outside cfctl | Current-state precondition or exact readback detects drift and invalidates the stale plan | P1 | Cross-zone state receipts are rejected |
| Notification, Ruleset, List, or rate-limit endpoint returns an undocumented async state | Fail closed and retain the operation ID for diagnosis | P1 | Do not guess success from HTTP status alone |
| Official schema lacks Pages analytics or universal localization controls | Keep the ledger row upstream-absent/blocked | P2 | Documentation cannot create the capability |

### Workflow Preview and Operational Proof

| Scenario | Expected Behavior | Priority | Notes |
|---|---|---:|---|
| Native workflow is called | Return a local component preview with `performed: false` and `cloudflare_boundary_crossed: false` | P1 | A workflow call never implies its reads or mutations ran |
| Workflow contains a contract-ready mutating component | Show the component call and approval boundary, but never aggregate authority or infer readiness from prior reads | P1 | Component retains its own plan/approve/run/status lifecycle |
| Workflow component is blocked, missing, mutation-contract-gapped, or cyclic | Set `available: false`, withhold `call_argv`, and emit the guide plus exact blocking gaps | P1 | A preview never turns catalog debt into a runnable command |
| Required selector or request body is missing from a workflow preview | Show the exact placeholder and body requirement; do not infer an account, zone, target, or payload | P1 | Operator runs the component explicitly |
| Workflow contains another workflow | Expand nested steps while detecting cycles | P2 | A cycle becomes a blocking composition gap |
| No indexed proof exists for a read component | Report `not_recorded` | P2 | Catalog contract completeness is unchanged |
| Indexed proof used a different catalog hash | Report `catalog_drifted` regardless of its age | P1 | Re-resolve and repeat the bounded read |
| Indexed proof exceeds the selected workflow's maximum age | Report `stale` | P1 | Freshness policy is workflow-specific, not universal |
| Indexed proof is recent but the read failed | Report `failed`, never `fresh` | P1 | A failure receipt is useful evidence but not positive proof |
| Multiple profiles, accounts, or redacted input hashes have proof for one component | Preserve separate scoped observations | P1 | Never collapse distinct credentials or select an unrelated account/input as authority |
| Proof-index row bytes no longer match their content-addressed filename | Refuse to load or reuse the row | P1 | Formatting or field tampering is detectable before aggregation |
| Evidence path is outside this state store, missing, symlinked, or hash-mismatched | Refuse to index or load it | P1 | The proof index cannot launder fabricated receipt metadata |
| Live read succeeds but proof-index persistence fails | Preserve the live-read evidence and return `CFCTL_OPERATIONAL_PROOF_INDEX_FAILED` | P1 | Do not let coverage or workflows claim the read is indexed |
| Evidence packet is requested | Export read identities plus safe mutation plan/approval/apply/verify/compensation/closure checkpoint metadata that actually exists | P1 | No plan inputs, targets, transaction artifacts, raw telemetry, or credentials are embedded; absent receipt classes stay absent |
| Operational-proof history exceeds the projection limit | Load only the 512 most recently indexed rows and report `truncated: true` with total/retained counts | P2 | Coverage, workflows, and workspace audit never silently present a bounded projection as full history |
| Coverage is requested before any account-backed reads | Return declared coverage plus an empty operational-proof projection | P2 | “Executable” must not become “proven on this account” |
| Workspace repository has no explicit account pin | Report operational proof as `unscoped` | P1 | Never join source config to the newest or only available account |
| Workspace repository is nested under multiple registered pins | Use the most-specific containing root | P1 | Exact account scope remains visible in the audit output |

## Error Messages

| Error State | User Message | Additional Action |
|---|---|---|
| Broad telemetry intent | "Telemetry spans analytics, logs and observability, security response, and data governance. Choose one typed capability; no mutation has been selected." | Show ranked reads, workflows, and separately labeled mutation candidates |
| Invalid bounded query | "The telemetry query is outside this capability's declared dataset, time, row, byte, timeout, or format bounds." | Show `cfctl guide <capability-id> --json` |
| Unsafe query escape hatch | "Only the catalog-pinned read-only query contract is permitted; raw SQL, GraphQL, headers, and arbitrary requests are rejected." | Show the accepted typed fields |
| Ambiguous denial | "Cloudflare denied this request. This response alone cannot distinguish token permission, plan entitlement, disabled configuration, or product availability." | Offer auth status and product-specific safe probes |
| Partial/truncated result | "The result is partial or truncated at cfctl's safety bound and must not be treated as complete telemetry." | Suggest a narrower time window or smaller scoped query |
| Operational-proof index failure | "The bounded read completed, but its operational-proof index row was not durably recorded." | Preserve the live-read receipt, repair local storage, and repeat before relying on workflow freshness |
| Private output failure | "cfctl could not create a new private output file; no complete file receipt was recorded." | Choose a new path and retry |
| R2 credential failure | "Logs Engine retrieval requires a mode-0600 credential bundle with exactly `access_key_id` and `secret_access_key`; credential values were not retained." | Link the governed retrieval example |
| Catalog/contract drift | "This capability no longer matches its pinned catalog contract and is blocked." | Run catalog sync/coverage and inspect `guide` next action |
| Unsafe security target | "The proposed security target is invalid, protected, self-blocking, too broad, or unsupported by this capability." | Narrow/normalize the target and review scope |
| Missing security governance | "Security response requires an evidence receipt, actor, reason, finite expiry, and all capability-specific confirmations." | Preserve the draft input and list missing fields |
| Stale mutation plan | "Current Cloudflare state no longer matches the approved plan. Create and review a fresh plan." | Read current state, then re-plan |
| Uncertain apply | "The mutation may have crossed the remote boundary, but completion is unproven. Do not retry it blindly." | Run `plans status`, then `plans rectify` |
| Verification failure | "The exact post-change resource could not be verified; this operation is not complete." | Inspect status/evidence and plan exact compensation if possible |
| Unsupported capability | "This operation is blocked because cfctl has no safe public contract for it." | Follow the capability's generated `next_action` |

## Recovery Paths

### Invalid or over-broad read

**User sees:** A validation error naming the failed selector, dataset, time,
row, timeout, format, or schema bound.

**Recovery options:**

1. Inspect `cfctl guide <capability-id> --json` and correct only the rejected
   typed field.
2. Narrow the time range, zone set, dataset set, columns, or row limit and retry
   as a new read.

**Data preservation:** No remote mutation occurs. The rejected body is not
turned into a raw query or evidence claim.

### Permission, entitlement, or empty-data ambiguity

**User sees:** A structured Cloudflare denial or an empty bounded result with
an explicit `not_proven` completeness classification.

**Recovery options:**

1. Check the active profile and exact catalog permissions without switching to
   a broader credential silently.
2. Run the product-specific settings or availability probe when one exists;
   otherwise report the ambiguity.

**Data preservation:** The redacted read/error receipt is retained. No inferred
entitlement or absence claim is written.

### Partial, malformed, timed-out, or truncated response

**User sees:** Valid rows collected so far plus `partial`/`truncated` metadata,
or a timeout error when no usable response completed.

**Recovery options:**

1. Treat the current artifact as incomplete evidence.
2. Retry with a narrower window or lower limit and compare separate receipts;
   use a retained log pipeline when exhaustive coverage is required.

**Data preservation:** Valid bounded rows and private partial files remain
available with hashes; their receipts never mark transport completeness true.

### Private output or R2 credential failure

**User sees:** A preflight or write error without credential values.

**Recovery options:**

1. Repair bundle ownership/mode and exact keys, or choose a new output path.
2. Retry the same bounded read through the specialized capability.

**Data preservation:** Existing files are never overwritten. Secrets do not
enter argv, plans, stdout, logs, or evidence.

### Catalog or upstream contract drift

**User sees:** A blocked capability with a drift reason and generated next
action.

**Recovery options:**

1. Sync and inspect catalog coverage and the capability guide.
2. Repair the owning catalog/adapter contract and run local proof; do not use a
   raw API or ungoverned dashboard fallback.

**Data preservation:** Prior evidence remains inspectable; no incompatible
request is sent.

### Unsafe or conflicting security action

**User sees:** A validation/precondition failure naming the missing governance,
unsafe scope, duplicate, conflict, self-block, or entitlement condition.

**Recovery options:**

1. Narrow the target, choose Managed Challenge, supply a finite expiry, and
   resolve duplicate/conflicting state.
2. Create a fresh plan with current evidence and explicit required
   confirmations; escalate exact public-IP blocking separately when justified.

**Data preservation:** The rejected proposal never becomes a Cloudflare rule or
list member. Its evidence receipt remains unchanged.

### Stale, uncertain, or unverified mutation

**User sees:** A stale-precondition failure, uncertain status, or failed exact
readback.

**Recovery options:**

1. Inspect `cfctl plans status <operation-id>` and all apply evidence.
2. Use `plans rectify` for uncertain boundary crossings; otherwise create a
   fresh exact compensation/removal plan from verified identity.

**Data preservation:** The original immutable plan, approval, apply attempt,
and verification result remain separate. A consumed plan is never replayed.

### Expiry or removal race

**User sees:** Exact absence, a stale removal precondition, or unresolved target
identity.

**Recovery options:**

1. Re-read the exact lineage-bound resource.
2. Record proven absence, or produce a new removal plan only for the verified
   identity.

**Data preservation:** No nearest-match or caller-selected resource is deleted.

## Test Scenarios

### Must Test (P1)

- [ ] Broad telemetry resolution returns domains and never a mutation command.
- [ ] Raw SQL, caller GraphQL, mutation/subscription documents, arbitrary
  headers, and catalog identity grafts fail before transport.
- [ ] Cross-account/zone selectors and rehashed cross-target state receipts are
  rejected.
- [ ] Row/byte overflow, malformed NDJSON/CSV, and interrupted streams produce
  bounded partial/truncated receipts without completeness claims.
- [ ] Output is create-only mode 0600; existing paths and symlinks are not
  overwritten or followed.
- [ ] R2 credentials are accepted only through the exact private bundle and do
  not appear in argv, request bodies, stdout, debug output, plans, or evidence.
- [ ] Security Events with duplicate timestamp/Ray ID rows expose no
  continuation cursor.
- [ ] Reserved/private/self IPs, prefixes broader than `/24`, unsafe block/skip,
  missing confirmations, and expiry over seven days fail before plan creation.
- [ ] Duplicate/conflicting security state and stale current-state receipts
  invalidate the plan.
- [ ] A second run of a consumed or uncertain plan cannot replay the mutation.
- [ ] Async List verification rejects unknown states, traverses every cursor
  page, and correlates exactly one member before deriving removal.
- [ ] Post-apply verification and compensation use only the returned,
  lineage-bound resource identity.
- [ ] Catalog permission/schema/fingerprint drift changes the capability to
  blocked or fails closed.

### Should Test (P2)

- [ ] Each dataset, time, row, timeout, field-count, zone-count, and expiry
  boundary accepts min/max and rejects one below/above.
- [ ] Equal/reversed timestamps and end times over five minutes in the future
  fail with actionable messages.
- [ ] Empty results preserve `dataset_completeness: not_proven`.
- [ ] 401/403 errors retain ambiguity among permission, entitlement,
  configuration, and availability.
- [ ] Bounded retry/backoff handles 429/transient 5xx without widening inputs.
- [ ] Timeout, DNS, TLS, wrong content type, and output write failure preserve
  honest failure state and safe retry.
- [ ] Workers sampling/freshness and GraphQL sampling statements survive into
  the response envelope.
- [ ] External drift between plan, apply, and verify blocks completion.
- [ ] Upstream-absent Pages analytics and localization controls remain blocked
  in the coverage ledger.

### Nice to Test (P3)

- [ ] Repeated identical reads generate distinct content-addressed evidence
  without claiming upstream event deduplication.
- [ ] Unicode, whitespace, case normalization, and maximum-length actor,
  reason, hostname, dataset, and prefix inputs behave consistently.
- [ ] Crash-stale storage locks recover after the documented 15-minute lease
  without allowing a non-owner to release a live lock.
- [ ] Error messages and `next_action` remain stable in both human and JSON
  `ResultEnvelopeV2` output.
