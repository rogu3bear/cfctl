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
git clone https://github.com/rogu3bear/cfctl.git
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
| Workspace fallback | `CF_WORKSPACE_ENV_FILE` (default `~/dev/.env`) — strict allowlisted `KEY=VALUE` import, fills gaps only, never shell-sourced; `""` disables |

Lane behavior:

- `dev` derives `CLOUDFLARE_API_TOKEN` for wrangler.
- `global` derives `CLOUDFLARE_API_KEY` and requires `CLOUDFLARE_EMAIL`.

Credential provenance: `cfctl env sources` (and `cfctl doctor` under
`result.env_health`) reports which file supplied each credential and flags
drift when the same variable differs across sources — fingerprints only,
never values. The canonical shared file always wins; the workspace fallback
only fills gaps.

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
cfctl list access.login_method
cfctl classify dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT
cfctl guide dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120
cfctl guide zone.setting set --zone example.com --name ssl --content strict
cfctl guide edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com
cfctl hostname verify --file state/hostname/example.yaml
cfctl maildesk-cf verify --file state/maildesk-cf/example.json
```

Before choosing a write path, scan [docs/capabilities.md](docs/capabilities.md).
It is generated from the catalogs and shows the read/plan/apply/verify contract,
including preview requirements, destructive confirmations, lane policy,
selectors, and desired-state sync support.

Before credentials exist, `cfctl doctor` reports `bootstrap_required` and points
at `cfctl bootstrap permissions`; `cfctl doctor --strict` still fails until a
healthy token lane exists.

Useful reads:

```bash
cfctl snapshot tunnel
cfctl list audit.log
cfctl list pages.project
cfctl list access.login_method
cfctl list access.idp
cfctl list access.group
cfctl get access.organization
cfctl get access.app --domain docs.example.org
cfctl list edge.certificate --zone example.com
cfctl list zone.setting --zone example.com
cfctl list worker.route --zone example.com
cfctl maildesk-cf snapshot --file state/maildesk-cf/example.json
cfctl list api_gateway.operation --zone example.com
cfctl list api_gateway.schema --zone example.com
cfctl list vulnerability_scanner.scan
CF_TOKEN_LANE=global cfctl diff dns.record --zone example.com
```

Useful safe write plans:

```bash
cfctl apply access.policy create --app-id <app-id> --body-file policy.json --plan
CF_TOKEN_LANE=global cfctl apply access.login_method set --provider-type onetimepin --plan
cfctl apply access.idp create --type onetimepin --plan
cfctl apply access.idp delete --type onetimepin --confirm delete --plan
cfctl maildesk-cf provision --file state/maildesk-cf/example.json --plan
CF_TOKEN_LANE=global cfctl apply dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120 --plan
CF_TOKEN_LANE=global cfctl apply zone.setting set --zone example.com --name ssl --content strict --plan
CF_TOKEN_LANE=global cfctl apply zone.setting set --zone example.com --name always_use_https --content on --plan
CF_TOKEN_LANE=global cfctl apply dns.record sync --zone example.com --plan
CF_TOKEN_LANE=global cfctl apply zone.setting sync --zone example.com --plan
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

## maildesk-cf lifecycle

Use `cfctl maildesk-cf verify|snapshot|diff|plan|provision --plan` with JSON specs under [state/maildesk-cf](state/maildesk-cf) when a maildesk deployment needs Email Routing aliases, Workers, D1, R2, Queues, and mode-driven sender readiness checked together. The public template defaults to receive-only outbound mode; Cloudflare Email Service or Resend sender evidence is required only when the spec enables that provider.

```bash
cfctl maildesk-cf init --domain example.com
cfctl maildesk-cf verify --file state/maildesk-cf/example.json
cfctl maildesk-cf snapshot --file state/maildesk-cf/example.json
cfctl maildesk-cf diff --file state/maildesk-cf/example.json
cfctl maildesk-cf provision --file state/maildesk-cf/example.json --plan
```

`maildesk-cf provision --plan` emits a local operation id and proposed component operations. `maildesk-cf provision --ack-plan <operation-id>` is blocked until those component writes are each available through preview-gated public `cfctl` surfaces. The verifier does not perform broad live sends; enabled sender providers use DNS/authentication and provider readback evidence unless a human explicitly asks for targeted delivery proof.

Token minting:

```bash
cfctl token get --id <token-id>
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
env       ownership wrangler  cloudflared hostname  maildesk-cf standards token list
get       can       classify  guide      apply     verify    explain snapshot diff
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

`cfctl env run --lane dev -- <command> [args...]` is the bridge for external
deploy scripts that need lane-derived auth without learning cfctl token internals.
It loads the normal env files, selects the requested lane, exports the mapped
Cloudflare tool env to the child, strips parent lane secrets from the child
environment, redacts child output, and writes a runtime artifact naming the
lane/env mapping without cfctl token values. The artifact records command argv
for evidence, so do not pass secrets as command-line arguments:

```bash
CF_SHARED_ENV_FILE=/Users/star/dev/.env cfctl env run --lane dev -- \
  /Users/star/dev/jkca-web/scripts/deploy-all.sh --only edge-router
```

`./scripts/verify_static_contract.sh` validates the permission catalog schema
and deterministic profile command fixtures, including the public ownership
envelopes. `./scripts/verify_public_contract.sh`
adds a live drift check by comparing the catalog against Cloudflare's current
permission-group inventory. For a credentialless runtime-output check, run
`python3 scripts/verify_permission_catalog.py --cfctl ./cfctl`.

Remote CI is intentionally absent from this checkout. Use
[LOCAL_CI.md](LOCAL_CI.md) for the local contract gate. Live permission-group
drift and public-contract smoke tests require local operator credentials:
`CF_DEV_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and `CFCTL_PUBLIC_CONTRACT_ZONE`. The
selected token lane must be able to operate on `CFCTL_PUBLIC_CONTRACT_ZONE`; run
local smoke tests with an explicit lane when the default lane cannot see that
zone, such as `CF_TOKEN_LANE=global CFCTL_PUBLIC_CONTRACT_ZONE=example.com
./scripts/verify_public_contract.sh`. The operator policy for these credentials is in
[docs/permission-doctrine.md](docs/permission-doctrine.md).

See [docs/runbooks/cfctl.md](docs/runbooks/cfctl.md) and [docs/capabilities.md](docs/capabilities.md) for the full reference. `docs/capabilities.md` is generated from the catalogs and is the fastest way to see which surfaces are read-only, which operations are preview-gated, which destructive operations require confirmation, and which surfaces support desired-state sync.

## Layout

```
cfctl              - thin entrypoint
commands/          - verb handlers
lib/runtime/       - auth, result envelopes, lanes, desired-state helpers
lib/backends/      - backend wrappers
lib/surfaces/      - runtime catalog access and surface metadata
catalog/           - surface registry, runtime policy, standards, doc bank
state/             - selective desired-state specs plus ownership, hostname, and maildesk-cf lifecycle registries
compat/            - legacy script -> cfctl mapping
legacy/            - older workflows kept for reference
scripts/           - inventory, mutation, wrangler/cloudflared wrappers, email-routing helpers
workers/           - bundled Workers (template form)
var/inventory/     - runtime, auth, and operation evidence (gitignored)
var/logs/          - command logs (gitignored)
```

## Desired state

Desired state is selective, not universal — it exists where repeated drift justifies `diff` and `sync`, not as a blanket declarative layer.

Currently supported: `access.app`, `access.policy`, `dns.record`, `zone.setting`, `security.txt`, `hostname` verify/diff/plan, `maildesk-cf` verify/snapshot/diff/plan/provision-plan, `tunnel`.

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
CF_TOKEN_LANE=global CFCTL_PUBLIC_CONTRACT_ZONE=example.com ./scripts/verify_public_contract.sh
cfctl previews
cfctl previews purge-expired
cfctl previews purge-inactive-legacy
cfctl previews purge-duplicate-active
cfctl locks
cfctl locks clear-stale
cfctl admin authorizations
cfctl admin revoke-backend --path <authorization-path>
```

- `cfctl doctor` is bootstrap-aware: zero configured token lanes is
  `bootstrap_required`, while configured-but-unhealthy lanes remain unsafe.
- `cfctl previews purge-inactive-legacy` removes only legacy preview receipts
  without complete trust metadata; active trusted previews are not targeted.
- `cfctl previews purge-duplicate-active` removes older active preview receipts
  when a newer trusted receipt exists for the same lane, target, request, and policy.
- Direct API wrappers: account inventory, DNS, Access, tunnels, email routing, targeted writes.
- `cfctl wrangler ...` via [scripts/cf_wrangler.sh](scripts/cf_wrangler.sh): wrapped wrangler with cfctl logs, artifacts, and preview gating.
- `cfctl cloudflared ...` via [scripts/cf_cloudflared.sh](scripts/cf_cloudflared.sh): wrapped cloudflared with the same envelope.

## Source Config Vs Live State

`cfctl standards audit` performs checked-in Wrangler config alignment, including `compatibility_date` freshness — it finds missing or stale `compatibility_date`, missing observability, plaintext secret-like vars, binding shape drift. Workspace-wide scans also classify source authority so canonical repo config can be separated from worktree, dry-run deploy, and baseline-copy config without hiding those files. **It does not inspect the Cloudflare dashboard.** For live assertions, use `cfctl list`, `cfctl get`, `cfctl snapshot`, `cfctl can`, or `cfctl verify` and cite the emitted artifact.

`cfctl audit access` is the live-truth complement for authentication posture:
it reads the account's Access applications and identity providers and
evaluates machine pass/fail checks tied to catalog standards — explicit
`allowed_idps`, onetimepin (OTP) allowed only where a `state/access.app`
spec records it, launcher visibility, auto-redirect, and allow-policy
coverage. `--strict` also fails recommended-level warnings; `--id`/`--domain`
scope the audit to one application. Exit code and `ok` reflect the result, so
it works as a gate.

`cfctl audit state` is the one-command convergence sweep: it diffs every
desired-state surface (deriving the zones to check from the specs
themselves), folds in the Access posture result, and returns a single
`converged` verdict plus a `remediation_queue` of ready-to-run
`cfctl apply <surface> sync --plan` commands. It reads live account truth,
is read-only, and its exit code reflects whether live matches recorded
intent — the intended heartbeat for keeping the account from silently
drifting.

## Compatibility

Legacy `scripts/cf_*` entrypoints remain executable, but mutation-capable backends are backend-only by default and must be reached through `cfctl`. Direct maintainer/debug use requires `CF_BACKEND_BYPASS_FILE=<authorization-path>` from `cfctl admin authorize-backend`.

Compatibility map: [compat/script-entrypoints.json](compat/script-entrypoints.json) and [docs/compat.md](docs/compat.md).

## Email routing

Email Routing rule reads and targeted rule upserts are first-class `cfctl`
operations through `email.routing_rule`. Use
[docs/runbooks/email-routing.md](docs/runbooks/email-routing.md) for the
operator model, commands, evidence locations, and troubleshooting rules.

The original email-routing workflows that seeded this repo still ship. They are
useful as templates and as account-wide audit helpers, but they are not the
primary public interface for targeted rule work:

- [scripts/deploy_accounts_fanout.sh](scripts/deploy_accounts_fanout.sh)
- [scripts/provision_shared_aliases.sh](scripts/provision_shared_aliases.sh)
- [scripts/normalize_secondary_shared_aliases.sh](scripts/normalize_secondary_shared_aliases.sh)
- [scripts/normalize_legacy_shared_routes.sh](scripts/normalize_legacy_shared_routes.sh)
- [scripts/trigger_destination_verification.sh](scripts/trigger_destination_verification.sh)
- [scripts/audit_email_routing.sh](scripts/audit_email_routing.sh)
- [workers/accounts-fanout/index.js](workers/accounts-fanout/index.js)

The defaults in those scripts are placeholders. Set
`DESTINATION_ADDRESSES_JSON` and the target aliases/zones before applying.
When retrying `normalize_secondary_shared_aliases.sh` for a subset of zones,
pass `WORKER_DOMAINS_JSON` with the full Worker recipient-domain allowlist so a
targeted retry does not shrink accepted domains to only the retry subset.

## Docs

- [QUICKSTART.md](QUICKSTART.md) — install + first commands
- [docs/agent-landing.md](docs/agent-landing.md) — public operational landing for autonomous agents
- [CFCTL_PROMPT.md](CFCTL_PROMPT.md) — strict embedding prompt for tool integrators
- [docs/agent-landing.md](docs/agent-landing.md)
- [docs/auth.md](docs/auth.md)
- [docs/capabilities.md](docs/capabilities.md) — generated from catalogs; includes the read/plan/apply/verify operation matrix
- [docs/config-standards.md](docs/config-standards.md)
- [docs/cloudflare-doc-bank.md](docs/cloudflare-doc-bank.md)
- [docs/runtime-policy.md](docs/runtime-policy.md)
- [docs/state.md](docs/state.md)
- [docs/compat.md](docs/compat.md)
- [docs/runbooks/cfctl.md](docs/runbooks/cfctl.md)
- [docs/runbooks/email-routing.md](docs/runbooks/email-routing.md)
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
