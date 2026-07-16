# cfctl v2 runtime policy

The policy engine, never an agent, classifies a plan as `auto_execute`,
`approval_required`, or `blocked`.

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

All other executable writes require a reviewed `PlanV1` and this exact
mutation:

```bash
cfctl plans approve <operation-id> --yes
```

Paid plans also require `--max-cost CURRENCY:AMOUNT`. Unknown cost is blocked.
Approval binds the operation ID, account, catalog hash, permission lane,
selectors, request body hash, workspace graph, source-config hashes, local and
Cloudflare diffs, cost, verification, compensation, and non-reversible
warnings. It expires within 24 hours and any relevant drift invalidates it.

API-token mint plans additionally bind a fresh owner-specific live
permission-group inventory receipt and the normalized metadata for only the
selected groups. Account-owned tokens use the account inventory; user-owned
tokens use the user inventory and require an explicit account resource. cfctl
requires every group to declare account scope and re-reads the same inventory
before durable consumption. Permission, owner, or account-scope drift
invalidates the plan without crossing the token-create boundary.

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
prefix, request only allowlisted permission groups, and expire within the
maximum child TTL; revocations are lineage-bound to tokens the authority
itself minted; runs are rate-limited per rolling 24h window; the authority
expires on its own TTL. `cfctl keys policy revoke <authority-id>` closes
admission immediately and unconditionally; it does not cancel work that was
already durably admitted.

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

## Secrets

Credential material lives only in Keychain on macOS or Secret Service on
Linux. Secret request fields enter through stdin and become opaque references.
Secret results require `--value-out`, which must not exist and is created mode
0600. Arguments, stdout, plans, logs, evidence, and delegated subprocess
receipts are redacted. When an API cannot read a newly issued credential back,
the truthful terminal proof is the successful Cloudflare response plus the
durable sink receipt; cfctl does not claim that a later read verified the value.
Account- and zone-scoped Access service-token creation are the structured
exceptions to the opaque-text sink: cfctl recognizes only the two exact
operation/path/product/permission tuples, requires both non-empty response
fields, and writes only `client_id` and `client_secret` as one mode-0600 JSON
object. The same-scope exact resource readback proves the returned ID, name,
and duration, but never claims to re-read the one-time secret.

Account- and zone-scoped service-token updates are distinct exact
operation/path/product/selector contracts. Both accept only observable `name`
and `duration` fields. Secret-version and prior-secret-expiration inputs stay
outside that metadata-update path because they change credential cutover state.
Exact same-scope field readback proves the requested metadata, while the
irreversible expiration-clock reset is called out instead of being mislabeled
as automatically restorable.

Service-token refresh is an operation-specific irreversible verifier, not a
generic successful-POST check. The apply response and exact detail readback
must agree on both token identity and a valid future expiration. Neither the
value nor a success flag alone proves the refresh, and the prior expiration is
not represented as recoverable.

OAuth client rotation combines that sink receipt with a separate state proof:
the secret value itself remains unreadable, while an exact client-detail read
must prove the transition from one secret to two. Old-secret deletion is a
separate irreversible operation that requires and rechecks the two-secret
pre-state, then proves the transition back to one. The delete is not a rollback
for rotation because it retains the new value and destroys the old one.

## Adapter boundary

Catalog status selects one adapter: `native`, `dynamic_api`, `delegated_cli`,
`governed_ui`, or `blocked`. Delegated processes receive only the selected
credential. UI actions are target/account-bound evidence and preserve the same
approval policy. Model output and adapter selection grant no authority.

## Evidence

Evidence is local, redacted, and content-addressed. Telemetry is off. A receipt
may be attached elsewhere only through an explicit operator action. Presence
of an artifact does not mean an action was performed or verified.
