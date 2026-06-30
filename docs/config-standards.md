# Configuration Standards

This repo now has a first-class standards layer.

Use it before designing or applying Cloudflare changes:

```bash
cfctl standards
cfctl standards dns.record
cfctl standards access.app
cfctl standards worker.errors
cfctl standards worker.runtime
cfctl standards audit
```

## Purpose

The standards layer exists to answer:

- how a Cloudflare resource should be configured here
- how recurring Wrangler config shapes in a workspace root should be configured here
- when desired state is preferred over ad hoc mutation
- what evidence should exist after a change
- which runtime path agents should use before they mutate anything

It is intentionally different from:

- `cfctl explain <surface>`
  runtime contract, selectors, and supported operations
- `cfctl classify <surface> <operation>`
  mutation safety, lane fit, and preview policy
- `cfctl guide <surface> <operation>`
  exact commands to run

The standards layer is the configuration doctrine.

## Core Standards

Universal standards currently include:

- `cfctl`-first control-plane use
- `dev`-first lane selection
- preview-before-apply for mutations
- readback verification after meaningful changes
- no secret material in the repo
- desired-state preference for repeatable drift-prone resources

## Surface Standards

The catalog currently defines deeper standards for:

- `access.app`
- `access.login_method`
- `access.policy`
- `dns.record`
- `edge.certificate`
- `hostname`
- `worker.errors`
- `worker.runtime`
- `worker.build`
- `worker.d1`
- `worker.routes`
- `worker.route`
- `worker.vars`
- `worker.observability`
- `worker.triggers`
- `worker.containers`
- `worker.services`
- `worker.storage`
- `tunnel`
- `worker.script`
- `pages.project`
- `turnstile.widget`
- `logpush.job`
- `waiting_room`
- `security.txt`

Examples:

- `dns.record`
  explicit TTL, explicit proxy posture, selector-complete classification, desired state for durable routing records
- `access.app`
  explicit identity-provider posture and desired state for durable apps
- `access.login_method`
  preview-gated reconciliation to exactly one existing Access identity provider with readback proof
- `tunnel`
  remote-managed default and desired state for long-lived topology
- `edge.certificate`
  explicit ACM hostname coverage, zone-apex inclusion, validation-method choice, and post-order verification
- `hostname`
  read-only composite verification across DNS, route, Access, TLS, Worker, response, and storage
- `security.txt`
  preview-gated Cloudflare-managed vulnerability disclosure contact, enabled only where a public contact is proven by repo or account evidence
- `worker.route`
  live zone route inventory and route-to-script verification
- `worker.runtime`
  explicit compatibility date, compatibility flags, workers_dev posture, and source-map policy
- `worker.errors`
  fail-closed behavior, deliberate 4xx/5xx posture, explicit observability, and explicit debuggability
- `worker.build`
  explicit build command, reproducible toolchain preference, and explicit asset handling

## Workspace Audit

Use the standards audit when the question is "what does the real Wrangler footprint in a workspace root look like relative to our standard?"

```bash
cfctl standards audit
cfctl standards audit /path/to/workspace
```

This audit scans active `wrangler.toml` and `wrangler.jsonc` files, matches them to the standards catalog, and reports:

- recurring config classes actually present
- source authority for each file: canonical repo config versus worktree, dry-run deploy copy, or baseline copy
- which config classes are covered by standards
- `compatibility_date` freshness against the catalog thresholds
- per-file findings such as placeholder vars, missing observability on active workers, dual exposure, or container-image issues

Workspace-wide scans keep noncanonical files visible, but split them from the
canonical signal. The total `warning_count` / `note_count` still includes every
discovered config file for auditability. The `canonical_warning_count`,
`canonical_note_count`, and `source_context_summary` fields are the right
operator signal when a repo forest contains worktrees or deploy-copy lanes.

Compatibility-date freshness is intentionally advisory until the target repo updates its config. The default thresholds are:

- note after 30 days
- warning after 90 days

If a date is old, either refresh it in the owning app repo or record why that runtime intentionally lags. File-local documentation such as "mirrors live project" or "do not bump casually" downgrades the stale-date warning to a note, so the audit stays actionable without pushing blind runtime bumps.

Container image zero digests remain warnings unless the config clearly documents the lane as scaffolded, experimental, not production, or waiting on a first pushed digest. Documented placeholders are still reported as notes and must be replaced before the lane becomes production.

The audit is about checked-in config; use live `cfctl` reads before claiming deployed edge posture.

## Source Of Truth

The machine-readable source is:

- [catalog/standards.json](catalog/standards.json)

The runtime entrypoint is:

- `cfctl standards`

Use the catalog and the command output as the canonical standards contract for arriving agents.
