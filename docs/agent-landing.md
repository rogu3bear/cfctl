# Agent Landing

When an agent lands in this directory, the default posture is:

1. Load `CF_DEV_TOKEN` from `~/dev/.env`.
2. Run `cfctl doctor`.
3. Use `cfctl` from `PATH` as the public interface. The local `./cfctl` is equivalent when standing in this directory.
4. Read current state before writing.
5. Classify writes before acting.
6. Switch explicitly to `CF_TOKEN_LANE=global` only when the `dev` lane is blocked or you need the wider emergency surface.
7. Leave behind runtime evidence in `var/inventory/runtime/` and backend evidence in `var/inventory/`.

If you are embedding this runtime as a dedicated tool-facing sub-agent rather than a general repo assistant, use [CFCTL_PROMPT.md](CFCTL_PROMPT.md) as the strict command-bus prompt.

## Decision Path

Start by naming the job class:

- Source-config audit:
  run `cfctl standards audit <repo>` and the target repo's own Cloudflare contract checks. Treat the result as checked-in config truth only.
- Live edge/account inspection:
  run `cfctl list`, `cfctl get`, `cfctl snapshot`, `cfctl can`, or `cfctl verify` and cite the runtime artifact.
- Mutation:
  read state, load standards, classify, guide, preview with `--plan`, apply with `--ack-plan <operation-id>`, then verify.
- Runtime development:
  change `cfctl`, catalogs, docs, and contract checks together; do not document a public capability before it exists in the catalog and command surface.
- Degraded trust:
  run `cfctl doctor --repair-hints`, inspect previews and locks, and clear only expired/stale artifacts.

Do not turn a source-config audit into a live Cloudflare claim. If the question is about what users see at the edge, take a live read.

## First Commands

```bash
cfctl doctor
cfctl surfaces
cfctl docs
cfctl docs watch
cfctl standards audit
cfctl standards dns.record
cfctl standards worker.errors
cfctl standards worker.runtime
cfctl wrangler --version
cfctl cloudflared version
cfctl explain access.app
cfctl classify tunnel create
CF_TOKEN_LANE=global cfctl can dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --all-lanes
cfctl snapshot tunnel
cfctl list pages.project
cfctl get access.app --domain docs.example.org
CF_TOKEN_LANE=global cfctl diff dns.record --zone example.com
./scripts/cf_compare_token_coverage.sh
./scripts/cf_auth_check.sh
CF_TOKEN_LANE=global ./scripts/cf_auth_check.sh
```

For a single read-only orientation pass:

```bash
./scripts/cf_agent_bootstrap.sh
```

For writes, start with a dry run:

```bash
cfctl guide access.app update --id <app-id> --body-file app.json
cfctl apply access.app update --id <app-id> --body-file app.json --plan
cfctl apply access.policy create --app-id <app-id> --body-file policy.json --plan
cfctl apply tunnel create --body '{"name":"example","config_src":"cloudflare"}' --plan
CF_TOKEN_LANE=global cfctl apply dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120 --plan
CF_TOKEN_LANE=global cfctl apply dns.record sync --zone example.com --plan
```

To actually execute a reviewed write:

```bash
cfctl apply access.app update --id <app-id> --body-file app.json --ack-plan <operation-id>
CF_TOKEN_LANE=global cfctl apply dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120 --ack-plan <operation-id>
```

## Tool Choice

- `cfctl ...`:
  preferred live interface for reads, standards, capability checks, exact targeting, mutations, verification, lane comparison, previews, and desired-state diffs.
- `CF_TOKEN_LANE=global cfctl ...`:
  explicit emergency lane when the primary token cannot reach a surface.
- Direct API scripts and mutation wrappers:
  backend implementation for account inventory, Access, DNS-adjacent config, tunnels, email routing, and supported writes. Mutation backends are backend-only by default and should be used directly only when extending/debugging with a scoped authorization from `cfctl admin authorize-backend`.
- `cfctl wrangler ...`:
  wrapped Wrangler-native commands with runtime artifacts, logs, and preview gating for non-read-only invocations.
- `cfctl cloudflared ...`:
  wrapped cloudflared commands with runtime artifacts, logs, and preview gating for non-read-only invocations.

## Output Contract

- Inventory: `var/inventory/<product>/...`
- Operations: `var/inventory/operations/...`
- Runtime: `var/inventory/runtime/...`
- Auth and token commands: `var/inventory/auth/...`
- Logs: `var/logs/<workflow>/...`
- Existing email-routing workflows remain valid and now sit inside the broader runtime.
