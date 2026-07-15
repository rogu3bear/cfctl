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

Account-token mint plans additionally bind a fresh live permission-group
inventory receipt and the normalized metadata for only the selected groups.
cfctl re-reads those groups before durable consumption; permission or account
scope drift invalidates the plan without crossing the token-create boundary.

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

## Secrets

Credential material lives only in Keychain on macOS or Secret Service on
Linux. Secret request fields enter through stdin and become opaque references.
Secret results require `--value-out`, which must not exist and is created mode
0600. Arguments, stdout, plans, logs, evidence, and delegated subprocess
receipts are redacted. When an API cannot read a newly issued credential back,
the truthful terminal proof is the successful Cloudflare response plus the
durable sink receipt; cfctl does not claim that a later read verified the value.
Access service-token creation is the structured exception to the opaque-text
sink: cfctl requires both non-empty response fields and writes only `client_id`
and `client_secret` as one mode-0600 JSON object. The exact resource readback
proves the returned ID, name, and duration, but never claims to re-read the
one-time secret.

Service-token update accepts only observable `name` and `duration` fields.
Secret-version and prior-secret-expiration inputs stay outside that generic
update path because they change credential cutover state. Exact field readback
proves the requested metadata, while the irreversible expiration-clock reset is
called out instead of being mislabeled as automatically restorable.

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
