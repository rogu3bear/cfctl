# Agent landing: cfctl v2

`cfctl` is the one public Cloudflare control plane. It catalogs current
Cloudflare APIs, official docs, Wrangler, cloudflared, and governed UI
fallbacks without an MCP dependency.

## Orient

```bash
cfctl doctor --json
cfctl catalog sync --json
cfctl catalog coverage --json
cfctl agents doctor --json
```

Coverage includes stable `mutation_contract_gap_counts`. The counts overlap by
design because one capability can lack risk, cost, permissions, verification,
rollback, and entitlement knowledge simultaneously.

Use the same gap name in search to find affected operations:

```bash
cfctl catalog search "verification_missing" --json
cfctl catalog search "cost unbounded" --json
```

Search derives these terms from the current catalog contract; it does not make
a blocked operation executable.

Search before acting:

```bash
cfctl catalog search "inspect production Worker routes" --json
cfctl catalog show <capability-id> --json
cfctl guide <capability-id> --json
```

The generated guide always covers 15 stages: discover, authenticate, select
account, check entitlement, inspect current state, load standards, map
dependencies, calculate cost, build plan, request approval if needed, acquire
locks, execute, verify, rectify, and close with evidence.

Each stage names its contract state, evidence class, and machine-safe argv
arrays. `call_argv` is present only when the catalog contract is executable;
blocked capabilities instead expose exact `blocking_gaps`, a safe next action,
and, when a safe execution surface exists, a non-runnable
`post_resolution_call_argv` template. Account API-token creation is routed
through `keys mint`, which refreshes and binds the live permission-group
inventory. User-token creation remains blocked and exposes no execution
template until it has an equivalent inventory-bound workflow.

Turnstile widget creation writes the returned secret only to an explicit new
mode-0600 sink, proves the returned sitekey through an exact detail read, and
offers deletion only as a separate reviewed compensation plan. Widget updates
use an exact same-resource readback and a zero-direct-incremental-cost contract.
Secret rotation requires an explicit `invalidate_immediately` choice and a new
mode-0600 sink. The plan explains that immediate invalidation is irreversible,
while the non-immediate path keeps the old secret for only two hours and blocks
another rotation during that grace period.

OAuth client secret rotation is a two-plan cutover. Before planning and again
before consumption, cfctl reads the exact client and requires one active secret
for rotation or two active secrets for old-secret deletion. Rotation writes the
one-time `client_secret` only to a new mode-0600 sink, then verifies the same
client reports `has_rotated_secret=true`. Deleting the old secret is a separate
irreversible plan, allowed only after dependents have been moved to the new
value; its readback must report `has_rotated_secret=false`. Neither phase is
presented as rollback for the other.

## Deterministic execution

Use `cfctl call` with the selectors declared by the capability:

```bash
cfctl call zones-get --query name=example.com --json
cfctl call dns-records-for-a-zone-list-dns-records \
  --selector zone_id=<zone-id> --json
```

Reads emit redacted live-read evidence. Writes emit `PlanV1` first. Review the
plan, then use the exact ID:

```bash
cfctl plans approve <operation-id> --yes --json
cfctl plans run <operation-id> --json
cfctl plans status <operation-id> --json
```

Paid work also requires `--max-cost CURRENCY:AMOUNT`; unknown cost is blocked.
Plans expire within 24 hours, approvals are invalidated by relevant drift, and
consumed plans cannot be replayed after a crash.

## Workspace impact

Discovery never escapes registered boundaries:

```bash
cfctl workspace add /absolute/repository/root --account <account-id> --json
cfctl workspace discover --json
cfctl workspace graph --json
cfctl workspace audit --json
```

Workspace account pins resolve ambiguity. Source configuration, routes,
hostnames, bindings, desired state, and cross-repository references become
preconditions in transaction plans. A source audit is not live Cloudflare
truth; use a live `call` for edge/account assertions.

## Authentication and secrets

- OAuth Authorization Code with PKCE and refresh tokens is the default.
- Profiles and workspaces pin accounts; ambiguity fails closed.
- API tokens are scoped profiles.
- The global-key profile is emergency-only and never selected silently.
- Keychain on macOS and Secret Service on Linux hold credentials.
- Secret inputs come from stdin and become opaque key-store references.
- Secret outputs require `--value-out` to a new mode-0600 file. Access
  service-token creation writes a JSON object containing exactly `client_id`
  and `client_secret`; other secret outputs remain opaque text.
- stdout, plans, logs, subprocess receipts, and evidence are redacted.

## Adapter rules

Capability status controls the execution boundary:

- `native`: cfctl implements operation-specific handling.
- `dynamic_api`: the pinned OpenAPI schema validates and executes the call.
- `delegated_cli`: governed Wrangler/cloudflared subprocess, cleared
  environment, one selected credential, timeout, and redacted receipt.
- `governed_ui`: target/account-bound UI action only after API/CLI
  insufficiency is established.
- `blocked`: discoverable but not executable, with an exact reason.

Never improvise around a blocker. UI `AgentActionV1` output is a handoff, not
authority or completion proof.

## Natural-language entry

```bash
cfctl "rotate the production Worker secret"
```

This launches the configured local agent. Agents must use deterministic cfctl
commands underneath. `CFCTL_AGENT_SESSION` prevents recursive agent launch.
Model output never approves or directly mutates Cloudflare.

## Completion evidence

Final claims must identify one of: source config, live Cloudflare read,
preview/plan artifact, apply artifact, post-change verification, local proof,
or agent action. Evidence presence alone is not verification. If a verifier is
unsupported, status remains rectification-required rather than “done.”
