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
receipts are redacted.

## Adapter boundary

Catalog status selects one adapter: `native`, `dynamic_api`, `delegated_cli`,
`governed_ui`, or `blocked`. Delegated processes receive only the selected
credential. UI actions are target/account-bound evidence and preserve the same
approval policy. Model output and adapter selection grant no authority.

## Evidence

Evidence is local, redacted, and content-addressed. Telemetry is off. A receipt
may be attached elsewhere only through an explicit operator action. Presence
of an artifact does not mean an action was performed or verified.
