# cfctl

A local-first Cloudflare control plane that wraps `wrangler`, `cloudflared`, and the raw Cloudflare API behind a single, strict, catalog-driven CLI.

`cfctl` is built around three ideas:

1. **One public surface.** Everything an operator (or an autonomous agent) needs to do — read state, classify a write, mint a token, run a wrangler command — happens through `cfctl`. Backend scripts exist, but they are backend.
2. **Preview before apply.** Writes return a preview artifact and an `operation_id`; you re-run with `--ack-plan <operation_id>` to actually mutate. Tokens default to sink-only delivery, never stdout. Destructive operations require an explicit `--confirm delete`.
3. **Evidence, not memory.** Every meaningful read or write leaves a JSON envelope under `var/inventory/`. Conclusions cite artifacts; replays are reproducible.

If you've ever found yourself stitching together `wrangler`, `cloudflared`, raw `curl` against the Cloudflare API, and a wad of bash to make sense of it all — that's the gap this fills.

## Quickstart

See [QUICKSTART.md](QUICKSTART.md) for install, credential setup, and your first `cfctl` commands. The shortest path:

```bash
git clone https://github.com/your-org/cfctl.git
cd cfctl
./bootstrap.sh                    # checks tools, symlinks cfctl, scaffolds ~/.config/cfctl/.env, runs doctor
$EDITOR ~/.config/cfctl/.env      # fill in CF_DEV_TOKEN + CLOUDFLARE_ACCOUNT_ID
cfctl doctor
cfctl surfaces
```

`bootstrap.sh` is idempotent and never installs anything — it only checks, symlinks, and scaffolds. See `./bootstrap.sh --help` for flags.

## Why use this instead of plain wrangler?

Wrangler is excellent for Workers and Pages. `cloudflared` is excellent for tunnels. The Cloudflare API covers everything else. None of them coordinate.

`cfctl` adds the layer above all three:

- A single CLI verb-set across DNS, Access, tunnels, Workers, Pages, Email Routing, R2, KV, D1, Queues, Hyperdrive, Vectorize, Logpush, Turnstile, Waiting Rooms, Stream, Calls, AI Gateway, Workers AI, Browser Isolation, Zero Trust, and more.
- Capability classification (`cfctl can`, `cfctl classify`) so you know whether your current token can do an operation before you try it.
- Lane-aware auth (default scoped lane, emergency global lane) with explicit lane switching per command.
- Standards audits across your local Wrangler configs, including `compatibility_date` freshness.
- A desired-state engine for the surfaces where drift actually matters.
- Read-only API-security inventory for API Gateway discovery/schemas/operations and API Shield Vulnerability Scanner state.
- Wrapped `wrangler` and `cloudflared` so you get the same logs, artifacts, and preview gating you get on raw API calls.

## The contract

| Concern | How it's handled |
|---|---|
| Public CLI | `cfctl` (this repo) — local equivalent: `./cfctl` |
| Default auth lane | `CF_DEV_TOKEN` (scoped API token) |
| Emergency lane | `CF_GLOBAL_TOKEN` (global API key + `CLOUDFLARE_EMAIL`) |
| Lane selector | `CF_TOKEN_LANE=dev|global` |
| Account pin | `CLOUDFLARE_ACCOUNT_ID` |
| Env source | `~/.config/cfctl/.env` by default, or `CF_SHARED_ENV_FILE` (loader: [scripts/lib/cloudflare.sh](scripts/lib/cloudflare.sh)) |

Lane behavior:

- `dev` derives `CLOUDFLARE_API_TOKEN` for wrangler.
- `global` derives `CLOUDFLARE_API_KEY` and requires `CLOUDFLARE_EMAIL`.

## First commands

```bash
cfctl doctor                    # tooling, auth, runtime trust check
cfctl bootstrap permissions     # default read-profile operator-token plan
cfctl bootstrap permissions --profile hostname --zone example.com
cfctl surfaces                  # what cfctl can operate today
cfctl ownership check           # checked-in ownership registry integrity
cfctl docs                      # compact Cloudflare doc bank
cfctl docs watch                # incoming Cloudflare capability tracking
cfctl standards audit           # scan local Wrangler configs against standards
cfctl ownership list            # read the Cloudflare ownership authority registry
cfctl wrangler --version        # wrapped wrangler
cfctl cloudflared version       # wrapped cloudflared
cfctl explain access.app
cfctl classify dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT
cfctl guide dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120
cfctl guide edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com
cfctl hostname verify --file state/hostname/example.yaml
```

Before credentials exist, `cfctl doctor` reports `bootstrap_required` and points
at `cfctl bootstrap permissions`; `cfctl doctor --strict` still fails until a
healthy token lane exists.

Useful reads:

```bash
cfctl snapshot tunnel
cfctl list audit.log
cfctl list pages.project
cfctl get access.app --domain docs.example.org
cfctl list edge.certificate --zone example.com
cfctl list worker.route --zone example.com
cfctl list api_gateway.operation --zone example.com
cfctl list api_gateway.schema --zone example.com
cfctl list vulnerability_scanner.scan
CF_TOKEN_LANE=global cfctl diff dns.record --zone example.com
```

Useful safe write plans:

```bash
cfctl apply access.policy create --app-id <app-id> --body-file policy.json --plan
CF_TOKEN_LANE=global cfctl apply dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120 --plan
CF_TOKEN_LANE=global cfctl apply dns.record sync --zone example.com --plan
CF_TOKEN_LANE=global cfctl apply dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120 --ack-plan <operation-id>
CF_TOKEN_LANE=global cfctl apply edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --validation-method txt --certificate-authority lets_encrypt --validity-days 90 --plan
```

## Advanced Certificate Manager

Use `edge.certificate` when you need a Cloudflare Advanced Certificate Manager certificate pack for a zone, including a primary subdomain plus a deeper hostname such as `app.example.com` and `deep.app.example.com`.

Read and plan first:

```bash
cfctl standards edge.certificate
cfctl explain edge.certificate
cfctl guide edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com
cfctl list edge.certificate --zone example.com
CF_TOKEN_LANE=global cfctl can edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --all-lanes
CF_TOKEN_LANE=global cfctl apply edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --validation-method txt --certificate-authority lets_encrypt --validity-days 90 --plan
```

After reviewing the preview artifact, execute and verify:

```bash
CF_TOKEN_LANE=global cfctl apply edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --ack-plan <operation-id>
CF_TOKEN_LANE=global cfctl verify edge.certificate --zone example.com --host app.example.com --host deep.app.example.com
```

The runtime includes the zone apex automatically in the certificate-pack host list. The default auth lane may not have SSL certificate-pack permission; use `cfctl can ... --all-lanes` to prove whether the global lane is required before applying.

## Hostname lifecycle

Use `cfctl hostname verify|diff|plan` with specs under [state/hostname](state/hostname) when a hostname set needs DNS, Worker route, Access, Advanced Certificate Manager, Worker deployment, app response, D1, and R2 checked together.

```bash
cfctl hostname verify --file state/hostname/example.yaml
cfctl hostname diff --file state/hostname/example.yaml
cfctl hostname plan --file state/hostname/example.yaml
```

This tranche is read-only. `hostname plan` emits proposed component operations, but composite `hostname apply` is blocked until each component write path is present as a preview-gated public surface.

Token minting:

```bash
cfctl token permission-groups --name "DNS"
cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --plan
cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --ack-plan <operation-id> --value-out /tmp/dns-editor.token
cfctl token revoke --id <token-id> --plan
cfctl token revoke --id <token-id> --ack-plan <operation-id> --confirm delete
```

## Public verbs

Defined in [catalog/runtime.json](catalog/runtime.json):

```
doctor    audit     admin     bootstrap lanes     surfaces  docs      previews  locks
ownership wrangler  cloudflared standards token   list      get       can       classify
guide     apply     verify    explain   snapshot  diff
```

Bootstrap permission profiles are defined in [catalog/permissions.json](catalog/permissions.json).
Use the default `read` profile for inventory and audits, then choose a narrower
write profile such as `dns`, `hostname`, or `deploy` for preview-gated work.
The temporary bootstrap credential should only have token-minting permissions
long enough to mint the day-to-day `CF_DEV_TOKEN`, then use
`cfctl token revoke` to close the bootstrap or one-off deploy token early when
its token id is known.
Each profile also declares `allowed_surfaces` and `forbidden_permissions`; the
verifier fails when a profile gains a permission outside its declared boundary.

`cfctl ownership list|get|check` exposes [state/ownership/resources.json](state/ownership/resources.json)
as a read-only public control-plane interface. Use it instead of scraping the
JSON file directly when checking which repo owns a Cloudflare resource class,
for example `cfctl ownership get --resource-key cloudflare:dns.record:*`.

`./scripts/verify_static_contract.sh` validates the permission catalog schema
and deterministic profile command fixtures, including the public ownership
envelopes. `./scripts/verify_public_contract.sh`
adds a live drift check by comparing the catalog against Cloudflare's current
permission-group inventory. For a credentialless runtime-output check, run
`python3 scripts/verify_permission_catalog.py --cfctl ./cfctl`.

The GitHub Actions workflow in [.github/workflows/cfctl-contract.yml](.github/workflows/cfctl-contract.yml)
runs static contract checks on pull requests. Its scheduled and manual live
job runs through the `cfctl-live` protected environment and requires
`CF_DEV_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and `CFCTL_PUBLIC_CONTRACT_ZONE`, then
runs the live permission-group drift and public-contract smoke tests. The
operator policy for these credentials is in
[docs/permission-doctrine.md](docs/permission-doctrine.md).

See [docs/runbooks/cfctl.md](docs/runbooks/cfctl.md) and [docs/capabilities.md](docs/capabilities.md) for the full reference.

## Layout

```
cfctl              - thin entrypoint
commands/          - verb handlers
lib/runtime/       - auth, result envelopes, lanes, desired-state helpers
lib/backends/      - backend wrappers
lib/surfaces/      - runtime catalog access and surface metadata
catalog/           - surface registry, runtime policy, standards, doc bank
state/             - selective desired-state specs plus ownership and hostname lifecycle registries
compat/            - legacy script -> cfctl mapping
legacy/            - older workflows kept for reference
scripts/           - inventory, mutation, wrangler/cloudflared wrappers, email-routing helpers
workers/           - bundled Workers (template form)
var/inventory/     - runtime, auth, and operation evidence (gitignored)
var/logs/          - command logs (gitignored)
```

## Desired state

Desired state is selective, not universal — it exists where repeated drift justifies `diff` and `sync`, not as a blanket declarative layer.

Currently supported: `access.app`, `access.policy`, `dns.record`, `hostname` verify/diff/plan, `tunnel`.

Use:

```bash
cfctl diff <surface>
cfctl apply <surface> sync --plan
cfctl apply <surface> sync --ack-plan <operation-id>
```

Specs live under [state/](state/README.md). Support means the engine exists; managed specs are opt-in.

## Backends

Reach for backends directly only when extending the runtime or operating with an explicit `cfctl admin authorize-backend` lease.

Trust and repair helpers:

```bash
cfctl doctor --strict
cfctl doctor --repair-hints
./scripts/verify_static_contract.sh
./scripts/verify_public_contract.sh
cfctl previews
cfctl previews purge-expired
cfctl previews purge-inactive-legacy
cfctl locks
cfctl locks clear-stale
cfctl admin authorizations
cfctl admin revoke-backend --path <authorization-path>
```

- `cfctl doctor` is bootstrap-aware: zero configured token lanes is
  `bootstrap_required`, while configured-but-unhealthy lanes remain unsafe.
- `cfctl previews purge-inactive-legacy` removes only legacy preview receipts
  without complete trust metadata; active trusted previews are not targeted.
- Direct API wrappers: account inventory, DNS, Access, tunnels, email routing, targeted writes.
- `cfctl wrangler ...` via [scripts/cf_wrangler.sh](scripts/cf_wrangler.sh): wrapped wrangler with cfctl logs, artifacts, and preview gating.
- `cfctl cloudflared ...` via [scripts/cf_cloudflared.sh](scripts/cf_cloudflared.sh): wrapped cloudflared with the same envelope.

## Source Config Vs Live State

`cfctl standards audit` performs checked-in Wrangler config alignment, including `compatibility_date` freshness — it finds missing or stale `compatibility_date`, missing observability, plaintext secret-like vars, binding shape drift. **It does not inspect the Cloudflare dashboard.** For live assertions, use `cfctl list`, `cfctl get`, `cfctl snapshot`, `cfctl can`, or `cfctl verify` and cite the emitted artifact.

## Compatibility

Legacy `scripts/cf_*` entrypoints remain executable, but mutation-capable backends are backend-only by default and must be reached through `cfctl`. Direct maintainer/debug use requires `CF_BACKEND_BYPASS_FILE=<authorization-path>` from `cfctl admin authorize-backend`.

Compatibility map: [compat/script-entrypoints.json](compat/script-entrypoints.json) and [docs/compat.md](docs/compat.md).

## Email routing

The original email-routing workflows that seeded this repo still ship — they're useful as templates and as a reference for stitching Workers + Email Routing rules + verified destinations into one operation:

- [scripts/deploy_accounts_fanout.sh](scripts/deploy_accounts_fanout.sh)
- [scripts/provision_shared_aliases.sh](scripts/provision_shared_aliases.sh)
- [scripts/normalize_secondary_shared_aliases.sh](scripts/normalize_secondary_shared_aliases.sh)
- [scripts/normalize_legacy_shared_routes.sh](scripts/normalize_legacy_shared_routes.sh)
- [scripts/trigger_destination_verification.sh](scripts/trigger_destination_verification.sh)
- [scripts/audit_email_routing.sh](scripts/audit_email_routing.sh)
- [workers/accounts-fanout/index.js](workers/accounts-fanout/index.js)

The defaults in those scripts are placeholders — set `DESTINATION_ADDRESSES_JSON` and `ROUTES_JSON` (or edit the script) before applying.

## Docs

- [QUICKSTART.md](QUICKSTART.md) — install + first commands
- [AGENTS.md](AGENTS.md) — operational landing for autonomous agents
- [CFCTL_PROMPT.md](CFCTL_PROMPT.md) — strict embedding prompt for tool integrators
- [docs/agent-landing.md](docs/agent-landing.md)
- [docs/auth.md](docs/auth.md)
- [docs/capabilities.md](docs/capabilities.md) — generated from catalogs
- [docs/config-standards.md](docs/config-standards.md)
- [docs/cloudflare-doc-bank.md](docs/cloudflare-doc-bank.md)
- [docs/runtime-policy.md](docs/runtime-policy.md)
- [docs/state.md](docs/state.md)
- [docs/compat.md](docs/compat.md)
- [docs/runbooks/cfctl.md](docs/runbooks/cfctl.md)
- [docs/runbooks/tool-choice.md](docs/runbooks/tool-choice.md)
- [docs/runbooks/mutations.md](docs/runbooks/mutations.md)
- [docs/runbooks/live-inventory.md](docs/runbooks/live-inventory.md)
- [docs/runbooks/capability-audit.md](docs/runbooks/capability-audit.md)
- [docs/runbooks/auth-and-env.md](docs/runbooks/auth-and-env.md)
- [docs/runbooks/tunnels.md](docs/runbooks/tunnels.md)
- [docs/official-cloudflare-reference.md](docs/official-cloudflare-reference.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests are welcome — the bar is "the public contract still holds."

## Security

See [SECURITY.md](SECURITY.md). Please do not file public issues for vulnerabilities.

## License

MIT — see [LICENSE](LICENSE).
