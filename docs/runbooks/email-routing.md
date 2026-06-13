# Email Routing

This runbook explains how Email Routing fits into `cfctl`, how inbound mail
reaches Workers, and how to prove the live state without bypassing the control
plane.

## Mental Model

Email Routing has four layers:

1. Zone state decides whether Cloudflare Email Routing is enabled for a domain.
2. Email Routing rules match recipient addresses such as `role@example.com`.
3. Rule actions hand matching mail to a Worker, forward it, or drop it.
4. The Worker owns product behavior such as fanout, Maildesk routing, storage,
   queueing, audit events, and reply policy.

Keep those layers separate. `cfctl` owns Cloudflare account state and evidence.
Maildesk or a Worker application owns mail product behavior. Legacy scripts may
still exist as backend implementation, but normal operator workflows should
start from `cfctl`.

## Public Surface

The first-class surface is `email.routing_rule`.

Read and inspect:

```bash
CF_TOKEN_LANE=global ./cfctl list email.routing_rule --zone example.com
CF_TOKEN_LANE=global ./cfctl get email.routing_rule --zone example.com --name role@example.com
CF_TOKEN_LANE=global ./cfctl verify email.routing_rule --zone example.com --name role@example.com
CF_TOKEN_LANE=global ./cfctl can email.routing_rule --zone example.com
CF_TOKEN_LANE=global ./cfctl can email.routing_rule upsert --zone example.com --name role@example.com --service maildesk-cf-router --all-lanes
```

Plan, apply, and verify a rule mutation:

```bash
CF_TOKEN_LANE=global ./cfctl guide email.routing_rule upsert \
  --zone example.com \
  --name role@example.com \
  --service maildesk-cf-router

CF_TOKEN_LANE=global ./cfctl apply email.routing_rule upsert \
  --zone example.com \
  --name role@example.com \
  --service maildesk-cf-router \
  --plan

CF_TOKEN_LANE=global ./cfctl apply email.routing_rule upsert \
  --zone example.com \
  --name role@example.com \
  --service maildesk-cf-router \
  --ack-plan <operation-id>

CF_TOKEN_LANE=global ./cfctl verify email.routing_rule \
  --zone example.com \
  --name role@example.com
```

The default upsert builds a literal `to` matcher and a Worker action. It updates
one existing matching recipient rule by id. It creates a new rule only when the
preflight read proves no matching recipient rule exists. If multiple existing
rules match the same recipient, the backend fails closed instead of creating
another ambiguous rule.

## Account-Wide Audit

Use the account sweep when the question is "what does the account look like?"
rather than "is one recipient wired?"

```bash
CF_TOKEN_LANE=global ./scripts/audit_email_routing.sh
```

The audit reads:

- account Email Routing destination addresses;
- all account zones;
- each zone's Email Routing status;
- each zone's Email Routing rules.

It writes JSON under:

```text
var/inventory/email-routing/email-routing-audit-<timestamp>.json
```

Use targeted `cfctl list email.routing_rule --zone <zone>` when an account-wide
sweep hits a transient Cloudflare `10429` rate limit for one zone.

## Legacy Shared Alias Helpers

Legacy shared-alias scripts are still useful for account-wide cleanup and
bulk fanout work. They are not the preferred path for a single rule change.

When retrying `normalize_secondary_shared_aliases.sh` for only a subset of
zones, pass `WORKER_DOMAINS_JSON` with the full Worker recipient-domain
allowlist. Without it, the generated Worker config uses the target zone list,
which can make a narrow retry accidentally shrink the domains the Worker accepts.

## Evidence Locations

`cfctl` and its backends leave evidence:

```text
var/inventory/runtime/        # public cfctl result envelopes
var/inventory/email-routing/  # Email Routing read artifacts
var/inventory/operations/     # mutation previews and apply receipts
var/logs/email-routing-audit/ # account-sweep logs
```

Treat `var/inventory` and `var/logs` as operator evidence. They are local and
gitignored. Do not delete them during cleanup unless the operator explicitly
asks for evidence pruning.

## Reading A Topology

For the latest local proof, read the newest Email Routing audit artifact and
any targeted retry artifacts produced immediately after it.

Useful summary command:

```bash
jq -r '
  .zones[]
  | [
      .name,
      (.email_routing.status // "unknown"),
      ((.rules // []) | length),
      (((.rule_errors // []) | length) + ((.email_routing.errors // []) | length)),
      (((.rules // [])
        | map(.actions[]? | select(.type == "worker") | .value[]?)
        | unique
        | sort) | join(","))
    ]
  | @tsv
' var/inventory/email-routing/email-routing-audit-<timestamp>.json
```

Interpretation:

- `ready` plus a nonzero rule count means Email Routing was readable and active
  for that zone at artifact time.
- `unconfigured` can be intentional when another provider owns root-domain MX.
- `unknown` with `10429` errors is a rate-limit gap, not proof of missing rules.
- destination `verified` values may be timestamps, not booleans.

## Worker Boundary

Worker script names are account-specific. Interpret rules by role:

- Maildesk router: policy-backed accepted-mail handling.
- Shared fanout: collaboration forwarding to verified destinations.
- Zone-specific forwarder: narrow forwarding exception for one domain.
- Ingest Worker: older or specialized capture path.

Do not infer product behavior from a rule alone. A rule proves that Cloudflare
hands a recipient to a Worker; the Worker code and product evidence prove what
happens after handoff.

## Troubleshooting

Default lane cannot read Email Routing:

- retry the read through `CF_TOKEN_LANE=global`;
- keep both artifacts when the default-lane failure explains why global was
  required.

Cloudflare returns `10429`:

- wait briefly and retry the narrowest affected zone;
- do not report the zone as empty or broken from the rate-limited artifact alone.

Need to change a rule:

- run `cfctl can` or `cfctl guide` first;
- run `cfctl apply ... --plan`;
- inspect the preview artifact;
- rerun with `--ack-plan <operation-id>`;
- verify with `cfctl get` or `cfctl verify`.
