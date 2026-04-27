# cfctl

`cfctl` is the primary public interface for this repo.

It is built for agent and operator use:

- `doctor` for runtime trust checks
- `previews` for preview-receipt inspection and cleanup
- `locks` for write-lock inspection and cleanup
- `wrangler` for wrapped Wrangler commands with logs and preview gating
- `cloudflared` for wrapped cloudflared commands with logs and preview gating
- `surfaces` for a fast surface inventory
- `docs` for the curated Cloudflare docs bank and incoming capability watchlist
- `standards` for canonical configuration guidance
- `lanes` for auth-lane health and availability
- `token` for token permission-group discovery and token minting
- `list` for collections
- `get` for exact resources
- `snapshot` for evidence-first read capture
- `classify` for write policy and lane fit
- `guide` for exact preview/apply commands
- `apply` for real mutations
- `verify` for post-change rechecks
- `can` for live capability and permission checks
- `explain` for the machine-readable contract of a surface
- `diff` for selective desired-state comparison

## Core Examples

```bash
cfctl doctor
cfctl doctor --strict
cfctl doctor --repair-hints
./scripts/verify_static_contract.sh
./scripts/verify_public_contract.sh
cfctl previews
cfctl previews purge-expired
cfctl locks
cfctl locks clear-stale
cfctl surfaces
cfctl docs
cfctl docs watch
cfctl docs ai-search
cfctl standards audit
cfctl standards dns.record
cfctl standards worker.errors
cfctl standards worker.runtime
cfctl wrangler --version
cfctl wrangler deploy --plan
cfctl cloudflared version
cfctl cloudflared tunnel create preview-tunnel --plan
cfctl token permission-groups --name "DNS"
cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --plan
cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --ack-plan <operation-id> --value-out /tmp/dns-editor.token
cfctl classify dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT
cfctl guide dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120
cfctl list surfaces
cfctl explain access.app
cfctl list pages.project
cfctl get access.app --domain docs.example.org
cfctl can dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --all-lanes
CF_TOKEN_LANE=global cfctl snapshot tunnel
CF_TOKEN_LANE=global cfctl diff dns.record --zone example.com
CF_TOKEN_LANE=global cfctl apply dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120 --plan
CF_TOKEN_LANE=global cfctl apply dns.record sync --zone example.com --plan
```

## Semantics

- commands emit a stable JSON result envelope
- every result includes active auth lane and auth scheme
- `standards` returns the canonical configuration standards catalog or one surface-specific standard set
- `docs` returns the curated official Cloudflare docs bank, either as a compact overview or one tracked topic
- `docs` includes freshness metadata so the bank does not masquerade as auto-refreshed truth
- `standards audit` scans the active Wrangler footprint under a root and reports standards coverage plus per-file findings
- `standards audit` reports `compatibility_date` aging and stale counts using the catalog thresholds
- `standards audit` is source-config evidence; use live reads for dashboard, Access, DNS, or edge-state claims
- `CF_TOKEN_LANE=global` switches `cfctl` onto the emergency token lane for that invocation
- `--all-lanes` compares lane-specific permission truth where supported
- `cfctl audit trust` is an alias for `cfctl doctor`
- `doctor --strict` exits non-zero for degraded trust state, not only unsafe state
- `doctor --repair-hints` emits exact cleanup and repair commands when trust is degraded
- `previews` lists actionable, legacy, and expired preview receipts
- `previews purge-expired` removes expired preview receipts only
- `locks` lists active write locks and their stale/orphaned state
- `locks clear-stale` removes stale/orphaned locks only
- `wrangler` and `cloudflared` wrap the repo helpers under `cfctl` so they emit runtime artifacts and log paths
- clearly read-only wrapped subcommands can run directly
- non-read-only wrapped subcommands must go through `--plan` then `--ack-plan <operation-id>`
- backend scripts are backend-only by default
- `--plan` produces a reviewed preview for a mutation
- preview-required operations must be rerun with `--ack-plan <operation-id>`
- `token mint --plan` prepares a token-mint request without creating a token
- real token mint execution must be rerun with `--ack-plan <operation-id>`
- `token mint --value-out <path>` writes the raw secret to a file and keeps it out of normal stdout JSON
- `token mint --reveal-token-once` remains policy-gated and is disabled in the default runtime policy
- `admin authorize-backend` issues a short-lived backend authorization file for maintainer/debug direct script use
- `admin authorizations` lists active and expired backend authorizations
- `admin revoke-backend --path ...` removes one authorization artifact
- `apply <surface> sync` performs selective desired-state reconciliation on supported surfaces
- destructive operations require explicit confirmation such as `--confirm delete`
- blocked surfaces fail with structured permission results instead of raw Cloudflare API blobs
- ambiguous target resolution is a hard failure

## Result Envelope

Every `cfctl` command writes a result artifact under `var/inventory/runtime/` or `var/inventory/auth/` with:

- `ok`
- `action`
- `surface`
- `operation`
- `operation_id`
- `auth`
- `target`
- `backend`
- `performed`
- `permission_status`
- `verification_status`
- `summary`
- `artifact_path`

## Backends

`cfctl` currently wraps the existing repo backends rather than replacing them:

- runtime modules under `commands/`, `lib/runtime/`, `lib/backends/`, and `lib/surfaces/`
- inventory scripts for live reads
- mutation scripts for supported writes
- direct Cloudflare API probes for capability checks
- repo-local evidence files for every command

## Desired State

Desired state is selective, not universal.

Supported surfaces:
- `access.app`
- `access.policy`
- `dns.record`
- `tunnel`

Supported commands:

```bash
cfctl diff dns.record --zone example.com
cfctl apply dns.record sync --zone example.com --plan
cfctl apply dns.record sync --zone example.com --ack-plan <operation-id>
```

Token commands:

```bash
cfctl token permission-groups --name "DNS"
cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --plan
cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --ack-plan <operation-id> --value-out /tmp/dns-editor.token
```
