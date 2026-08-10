# Agent landing: cfctl v2

`cfctl` is the one public Cloudflare control plane. It catalogs current
Cloudflare APIs, official docs, Wrangler, cloudflared, and governed UI
fallbacks without an MCP dependency.

## Orient

```bash
cfctl version --json
cfctl doctor --json
cfctl catalog sync --json
cfctl catalog coverage --json
cfctl agents doctor --json
```

`version` reports the invoked binary's build identity. `doctor` and `agents
doctor` trust the `cfctl` resolved on `PATH` only when it is the same
executable as the running build; they never launch a different PATH executable
to inspect it. Missing or different PATH executables and drifted managed
guidance are unhealthy — repair installation before relying on the operator
surface.

Coverage includes stable `mutation_contract_gap_counts`; the counts overlap by
design because one capability can lack several contract fields at once. Use
the same gap name in search — for example
`cfctl catalog search "verification_missing" --json` — to find affected
operations. Search never makes a blocked operation executable.

## Resolve intent first

```bash
cfctl resolve "inspect production Worker routes" --json
cfctl catalog show <capability-id> --json
cfctl guide <capability-id> --json
```

`resolve` deterministically maps the goal to a capability: it either commits
to a single confident match and emits the exact governed
`call`/`approve`/`run` commands, or fails closed with ranked candidates when
the match is ambiguous. To browse by keyword instead, use
`cfctl catalog search "<intent>" --json`.

The generated guide always covers 15 stages, discover through
close-with-evidence, and names each stage's contract state, evidence class,
and machine-safe argv arrays. `call_argv` is present only when the catalog
contract is executable; blocked capabilities instead expose exact
`blocking_gaps`, a safe next action, and at most a non-runnable
`post_resolution_call_argv` template. Account and user API-token creation are
routed through `keys mint`, which refreshes and binds the matching live
permission-group inventory; user-owned creation is explicit
(`--user --account <id>`), limited to one exact account resource, and never
offers arbitrary or wildcard token policies. Secret-producing lifecycles such
as Turnstile widgets, Access service tokens, OAuth client creation, and OAuth
client-secret rotation write one-time values only to a new mode-0600 sink,
verify through exact readbacks, and expose destructive follow-ups only as
separate reviewed plans; the per-capability invariants are in
[docs/v2-security.md](v2-security.md).

## Deterministic execution

Use `cfctl call` with the selectors declared by the capability:

```bash
cfctl call zones-get --query name=example.com --json
cfctl call dns-records-for-a-zone-list-dns-records \
  --selector zone_id=<zone-id> --json
```

Reads emit redacted live-read evidence. Writes emit a canonical `PlanV2` first. Review the
plan, then use the exact ID:

```bash
cfctl plans show <operation-id> --json
cfctl plans approve <operation-id> --yes --json
cfctl plans run <operation-id> --json
cfctl plans status <operation-id> --json
cfctl plans resume <operation-id> --json
cfctl plans rectify <operation-id> --json
cfctl plans cancel <operation-id> --json
```

Paid work also requires `--max-cost CURRENCY:AMOUNT`; unknown cost is blocked.
Plans expire within 24 hours, approvals are invalidated by relevant drift, and
consumed plans cannot be replayed after a crash. `plans resume` continues a
draft or approved plan; `plans rectify` reconciles durable receipts and
verification without replaying the Cloudflare mutation. `plans cancel` retires
a draft or approved plan immediately — mirroring authority revocation — when
the change is no longer wanted. See the operator runbook for the full
lifecycle.

## Workspace impact

Discovery never escapes registered boundaries:

```bash
cfctl workspace add /absolute/repository/root --account <account-id> --json
cfctl workspace remove /absolute/repository/root --json
cfctl workspace discover --json
cfctl workspace graph --json
cfctl workspace audit --json
```

Workspace account pins resolve ambiguity. Source configuration, routes,
hostnames, bindings, desired state, and cross-repository references become
plan preconditions, but a source audit is not live Cloudflare truth; use a
live `call` for edge/account assertions. Remove stale roots explicitly;
removal preserves historical graphs and evidence. Nested generated, cache,
fixture, dependency/build, vendor, and nested-repository paths are excluded;
register an excluded directory directly only when its contents should enter
the workspace graph.

Use `cfctl registry sync --json` to rebuild the local resource projection, then
inspect `cfctl registry coverage --json` before relying on it. Registry rows do
not collapse authority: catalog metadata says what is known, source config and
desired declarations say what is intended, and only evidence-backed live reads
say what Cloudflare currently returns. A partial registry must remain visibly
partial.

Inspect `cfctl policy admission list --json` before creating mutation plans.
An active admission bundle can tighten the compiled floor but never weaken it.
Bundle approval and activation are local, explicit, hash-bound, and distinct
from a Cloudflare apply. Do not approve or run an unconsumed historical PlanV1;
recreate it as a fully pinned PlanV2. The only standing-authority exception is
the bounded token lifecycle exposed by `cfctl keys policy`.

For event-driven reconciliation, inspect `cfctl events sources|status --json`
first. Queue pull and acknowledgement are private implementation operations
behind one ordinary `events-consume-queue-batch` PlanV2 per batch. Receipts and
reconciliation jobs commit atomically before acknowledgement. Events never
become observed resource state; only successful bounded Cloudflare reads do.
The inbound Worker bridge is a Bun project, and `events bridge prepare` is
local configuration staging rather than deployment.

## Authentication and secrets

- Profiles and workspaces pin accounts; ambiguity fails closed.
- API tokens are scoped profiles; the global-key profile is emergency-only and
  never selected silently.
- Credentials live in the platform keyring (Keychain on macOS, Secret Service
  on Linux), falling back to a mode-0600 file store under the cfctl data dir
  when the keyring is unavailable; `cfctl doctor` reports the active backend.
- Secret inputs come from stdin and become opaque key-store references; secret
  outputs require `--value-out` to a new mode-0600 file.
- stdout, plans, logs, subprocess receipts, and evidence are redacted.

## Adapter rules

Capability status controls the execution boundary: `native` means
operation-specific handling, `dynamic_api` means pinned-schema validation and
execution, `delegated_cli` means a governed Wrangler/cloudflared subprocess
with a cleared environment and redacted receipt, `governed_ui` means a
target/account-bound UI action only after API/CLI insufficiency is
established, and `blocked` means discoverable but not executable, with an
exact reason. Never improvise around a blocker. UI `AgentActionV1` output is a
handoff, not authority or completion proof.

## Natural-language entry

`cfctl "rotate the production Worker secret"` launches the configured local
agent. Agents must use deterministic cfctl commands underneath;
`CFCTL_AGENT_SESSION` prevents recursive agent launch, and model output never
approves or directly mutates Cloudflare. A bare single token that is not a
known command fails closed with a usage error — mistyped verbs never become
agent sessions.

## Completion evidence

Final claims must identify one of: source config, live Cloudflare read,
preview/plan artifact, apply artifact, post-change verification, local proof,
or agent action. Evidence presence alone is not verification. If a verifier is
unsupported, status remains rectification-required rather than "done."
