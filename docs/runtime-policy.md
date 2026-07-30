# cfctl v2 runtime policy

The policy engine, never an agent, classifies a plan as `auto_execute`,
`approval_required`, or `blocked`.

> Authority: this file is the runtime policy — it is authoritative for plan
> classification (`auto_execute` / `approval_required` / `blocked`), approval
> and standing-authority mechanics, and the adapter boundary. For the
> credential-storage, secret-sink, catalog and journal hashing, redaction, and
> per-capability safety invariants it references, `docs/v2-security.md` is
> authoritative. The two documents overlap by design and must agree — defer to
> the security contract on a secret, journal, or redaction detail, and to this
> file on a classification or approval detail.

## Automatic execution

Automatic execution is limited to operations with all of these properties:

- known semantics and exact selectors
- one scoped target
- reversible behavior
- no dependent configuration or dirty overlap
- no external communication or identity effect
- no ownership, security, registrar, or billing effect
- no incremental or unknown cost

## Approval

All other executable writes require a reviewed `PlanV2` and this exact
mutation:

```bash
cfctl plans approve <operation-id> --yes
```

Paid plans also require `--max-cost CURRENCY:AMOUNT`. Unknown cost is blocked.
Approval binds the operation ID, account, catalog hash, permission lane,
selectors, request body hash, workspace graph, source-config hashes, local and
Cloudflare diffs, cost, verification, compensation, and non-reversible
warnings. It expires within 24 hours and any relevant drift invalidates it.

An approved plan is latent authority until consumed, and expiry is only
enforced when something tries to consume it. `cfctl plans cancel
<operation-id>` retires that authority immediately — the plan-level
counterpart to revoking a standing authority. Cancellation is monotonic: a
cancelled plan can never be approved, run, or resumed.

API-token mint plans additionally bind a fresh owner-specific live
permission-group inventory receipt and the normalized metadata for only the
selected groups. Account-owned tokens use the account inventory; user-owned
tokens use the user inventory and require an explicit account resource. Each
selected group binds the exact resource its scope allows — the pinned account,
or with `--zone`, that one zone — and cfctl re-reads the same inventory before
durable consumption. Permission, owner, or scope drift invalidates the plan
without crossing the token-create boundary.

Zone-scoped writes whose only remaining gap is official plan entitlement use a
fresh `GET /zones/{zone_id}/subscription` read during planning. cfctl binds the
exact active plan, normalized plan tier, availability decision, target zone,
and official matrix hash, then repeats the read before durable consumption.
An ambiguous account subscription list is not treated as equivalent zone-plan
proof.

Every executable zone-scoped mutation requires a fresh
`GET /zones/{zone_id}` ownership read during planning. The normalized receipt
binds the requested zone, selected account, returned zone, and returned
`account.id`; execution repeats the read before durable consumption. A profile
or workspace account pin selects authority but is not accepted as ownership
proof.

The plan is durably consumed before cfctl crosses the API, subprocess, or UI
boundary. A crash after consumption cannot automatically replay the action.
Crash-stale local locks expire after 15 minutes; nonce ownership prevents an
older process from deleting a newer lock.

## Always approval-required

- deletes and purges
- security, identity, access, or ownership changes
- external sends
- multi-resource or cross-repository changes
- registrar and billing actions
- irreversible data mutations
- paid actions
- unknown write semantics or risk

## Standing authority — the one bounded exception

Recurring token-lifecycle operations may consume an unapproved plan under a
`StandingAuthorityV1`: a hash-bound grant that is itself created from a fresh
live permission inventory and activated only by an explicit
`cfctl keys policy approve <authority-id> --yes`. Approval moves from
per-operation to per-policy; it never disappears.

The grant is defensible because its bounds are strict and enforced against
the exact execution input at run time: children must carry the pinned name
prefix, request only allowlisted permission groups, bind only resources the
authority pinned — its account, plus its one zone when created with `--zone` —
and expire within the maximum child TTL; revocations are lineage-bound to
tokens the authority itself minted; runs are rate-limited per rolling 24h
window; the authority expires on its own TTL. `cfctl keys policy revoke
<authority-id>` closes admission immediately and unconditionally; it does not
cancel work that was already durably admitted.

Standing mint admission applies two independent validations to one fresh,
owner-specific permission-inventory response. The child plan's normalized
selected subset must still match its plan hash, and normalized metadata for
the authority's complete approved allowlist must still match the authority's
permission-inventory hash. Inventory reordering and additions unrelated to the
approved allowlist remain valid. A missing or duplicated allowlisted group, or
allowlisted name, scope, or category drift, blocks the mint. Standing deletes
remain available without mint-inventory validation because they create no new
token; their authority, lineage, TTL, and rate bounds still apply.

Standing admission uses the fixed lock order `plan -> authority`. Under the
authority lock, cfctl reloads the grant, rechecks its status and budget,
durably reserves the run, and saves the authority before consuming the plan.
That durable run reservation is the revocation linearization point: a revoke
committed before reservation blocks admission, while a run whose reservation
already committed may finish. Plan consumption and the boundary-attempt
checkpoint become durable before the authority lock is released for network
activity. Later lineage updates reload the authority and preserve `Revoked`;
recording lineage never reactivates a grant.

For a standing mint, each validated `BoundaryResponsePersisted` journal
receipt bound to the same authority is token-lineage truth. After the secret
sink attempt, including when the sink fails, cfctl reconciles any successfully
created token ID into `minted_token_ids` under the authority lock before
verification. The field remains an idempotent reconciled index: later standing
runs and `plans rectify` recover a missing entry from the receipt, repeated or
concurrent recovery does not duplicate it, and recovery preserves revocation.
Recovery never replays the Cloudflare mutation. Malformed, unsuccessful, or
authority-mismatched receipts cannot add lineage.

Every standing consumption records the authority id and content hash in the
plan's transaction journal and leaves `standing_apply` evidence, so each
unattended run is attributable to the exact approved grant. Post-approval
drift of any bound fails closed.

External sends, spend, and everything else in the list above remain
per-operation approval forever; standing authority covers only the
token-lifecycle capabilities named in the approved grant.

### Managed analytics profile rotation

`cfctl keys renew-analytics-profile` is the closed consumer-credential bridge
for an unattended analytics publisher. It requires a distinct minter profile,
an approved account-and-zone standing authority, exact child permissions, a
finite TTL, one hostname, and an existing publisher profile. The command does
not accept or print token material.

A mint first writes its one-time value to a private internal sink. cfctl then
stores it in a UUID-addressed immutable secret slot and creates a temporary
profile projection. Account RUM settings, zone dataset settings, and the
hostname-filtered RUM query must all succeed through that projection. Only then
does one atomic `profiles.json` replacement point the publisher profile at the
new slot and credential generation. The same reads run again through the
publisher profile before any old-child revocation.

Until activation, the old profile and child remain untouched. A failed
post-activation read atomically restores the exact prior profile projection
before the fresh child is revoked. Old-child revocation is unattended only
when the standing authority's durable lineage contains that ID. A bootstrap
child outside lineage produces a normal revoke plan and a persistent nonzero
failure state until the exact approved plan reaches verified not-found
closure. If planning itself fails after activation, the old-child identity is
persisted without an operation reference; later hourly checks retry only
explicit-minter-profile plan creation and refuse another mint. A failed
lineage-bound revoke persists the same old-child overlap and operation
reference until that exact operation is reconciled to `Verified`. Successful
later rotations use two standing run reservations: mint and old-child revoke.

Profile metadata contains only opaque slot, token identity, expiry, authority,
and pending-revocation references. Secret slots remain in the platform
credential store or its private mode-0600 fallback. Slot activation is
old-or-new atomic. A healthy managed-profile check repeats all three live reads
and retires any unreachable legacy profile-keyed credential left by the
one-time migration without touching the active immutable slot. On macOS,
Keychain reads and deletes use a bounded native subprocess so an interactive
access prompt becomes a nonzero scheduler failure instead of an indefinite
hang. No token value enters stdout, arguments, profiles, plans, evidence, or
repository files.

## Secrets

Credential material is written to the platform keyring first — Keychain on
macOS or Secret Service on Linux — and fails down to a governed mode-0600 file
store under cfctl's data directory (`auth/secrets`, a mode-0700 directory) when
the keyring is unavailable; reads reject any group- or world-readable secret
file, and `cfctl doctor` names the active backend. Secret request fields enter
through stdin and become opaque references.
Secret results require `--value-out`, which must not exist and is created mode
0600. Arguments, stdout, plans, logs, evidence, and delegated subprocess
receipts are redacted. When an API cannot read a newly issued credential back,
the truthful terminal proof is the successful Cloudflare response plus the
durable sink receipt; cfctl does not claim that a later read verified the value.

The per-capability secret-sink exceptions and verifiers — the Access
service-token creation/update/refresh contracts and the two-phase OAuth
client-secret rotation — are owned by [docs/v2-security.md](v2-security.md),
which this file defers to for every secret, journal, or redaction detail.

## Adapter boundary

Catalog status selects one adapter: `native`, `dynamic_api`, `delegated_cli`,
`governed_ui`, or `blocked`. Delegated processes receive only the selected
credential. UI actions are target/account-bound evidence and preserve the same
approval policy. Model output and adapter selection grant no authority.

## Evidence

Evidence is local, redacted, and content-addressed. Telemetry is off. A receipt
may be attached elsewhere only through an explicit operator action. Presence
of an artifact does not mean an action was performed or verified.
