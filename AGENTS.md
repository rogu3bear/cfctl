# Cloudflare Agent Runtime

This directory is a local-first Cloudflare control plane for agents.

Use it to inspect or change Cloudflare state through one public interface, verify the result, and leave behind evidence. Do not treat this directory as a generic shell-script dump. The public contract is `cfctl` on `PATH`; the local implementation in this directory is `./cfctl`.

If you are wrapping this runtime as a dedicated agent tool, use the strict embedding prompt in [CFCTL_PROMPT.md](CFCTL_PROMPT.md).

## Purpose

- Use `cfctl` as the primary interface for live reads, capability checks, mutations, verification, snapshots, and desired-state diffs. When standing in this directory, `./cfctl` is equivalent.
- Use backend scripts in `scripts/` only when extending the runtime, debugging a backend, or operating a legacy workflow that is intentionally outside the public contract.
- Keep the runtime `cfctl`-first. New capabilities should land in `cfctl`, the catalogs, and runtime modules before they are treated as public.

## Task Triage

Classify the request before choosing tools:

- Live Cloudflare account state:
  use `cfctl list`, `cfctl get`, `cfctl snapshot`, `cfctl can`, and `cfctl verify` so conclusions cite live read artifacts.
- Checked-in application configuration:
  use `cfctl standards audit <repo>` plus the target repo's native Cloudflare contract checks. A clean standards audit proves source-config alignment, not live edge state.
- Cloudflare mutation:
  read current state, load standards, classify the operation, generate a guide, run a preview, then apply only with the preview `operation_id`.
- Runtime extension:
  update `cfctl`, `catalog/`, `lib/`, `commands/`, docs, and contract checks together. Do not expose a capability in docs before it is present in the catalog and public command surface.
- Incident or degraded trust:
  run `cfctl doctor --repair-hints`, `cfctl previews`, and `cfctl locks` before attempting new writes.

Every final claim should say which evidence class supports it: source config, live Cloudflare read, preview artifact, apply artifact, or post-change verification.

## First Moves

When you land here, do this first:

```bash
cfctl doctor
cfctl bootstrap permissions
cfctl bootstrap permissions --profile hostname --zone example.com
cfctl surfaces
cfctl docs
cfctl docs watch
cfctl standards audit
cfctl standards <surface>
cfctl wrangler --version
cfctl cloudflared version
cfctl explain <surface>
cfctl classify <surface> <operation>
cfctl guide <surface> <operation>
```

Common examples:

```bash
cfctl doctor
cfctl bootstrap permissions
cfctl bootstrap permissions --profile hostname --zone example.com
cfctl surfaces
cfctl docs
cfctl docs watch
cfctl docs ai-search
cfctl list audit.log
cfctl standards audit
cfctl standards dns.record
cfctl standards worker.errors
cfctl standards worker.runtime
cfctl token permission-groups --name "DNS"
cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --plan
cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --ack-plan <operation-id> --value-out /tmp/dns-editor.token
cfctl token revoke --id <token-id> --plan
cfctl token revoke --id <token-id> --ack-plan <operation-id> --confirm delete
cfctl guide dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120
cfctl explain access.app
cfctl list pages.project
cfctl get access.app --domain docs.example.org
cfctl hostname verify --file state/hostname/example.yaml
CF_TOKEN_LANE=global cfctl diff dns.record --zone example.com
```

Advanced Certificate Manager / edge certificate example:

```bash
cfctl standards edge.certificate
cfctl explain edge.certificate
cfctl guide edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com
cfctl list edge.certificate --zone example.com
CF_TOKEN_LANE=global cfctl can edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --all-lanes
CF_TOKEN_LANE=global cfctl apply edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --validation-method txt --certificate-authority lets_encrypt --validity-days 90 --plan
CF_TOKEN_LANE=global cfctl apply edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --ack-plan <operation-id>
CF_TOKEN_LANE=global cfctl verify edge.certificate --zone example.com --host app.example.com --host deep.app.example.com
```

Use the default `dev` lane first. If `cfctl can ... --all-lanes` shows the dev lane cannot order SSL certificate packs, explicitly switch to `CF_TOKEN_LANE=global` and keep the same preview, acknowledgement, and verification evidence trail.

The bare `cfctl` command is expected to be installed in the user shell path. If `PATH` is degraded while standing in this directory, `./cfctl` is the equivalent local implementation:

```bash
cfctl doctor
cfctl surfaces
```

For a broad read-only bank refresh:

```bash
./scripts/cf_agent_bootstrap.sh
```

Hostname lifecycle specs live under `state/hostname/`. Use `cfctl hostname verify|diff|plan --file <spec>` when one hostname set needs DNS, Worker route, Access, certificate, Worker script, app response, and storage proven together. Composite `hostname apply` is blocked until the component write surfaces are individually preview-gated.

## Auth Lanes

- Default lane: `CF_DEV_TOKEN`
- Emergency lane: `CF_GLOBAL_TOKEN`
- Lane selector: `CF_TOKEN_LANE=dev|global`
- Canonical env source: `~/.config/cfctl/.env` unless `CF_SHARED_ENV_FILE` overrides it

Rules:

- Use `dev` first.
- Switch to `global` explicitly when `dev` is blocked or the task intentionally needs the wider emergency surface.
- Prefer `cfctl doctor`, `cfctl classify ...`, and `cfctl can ... --all-lanes` over guessing what the current lane can do.
- Do not hand-roll auth. Use `cfctl` or the shared loader in `scripts/lib/cloudflare.sh`.

## Tool Hierarchy

Use tools in this order:

1. `cfctl`
2. `cfctl wrangler ...` for Wrangler-native operations
3. `cfctl cloudflared ...` for tunnel runtime/connectivity
4. direct backend scripts in `scripts/` only when extending/debugging with a scoped authorization from `cfctl admin authorize-backend`

Do not teach other agents the flat `scripts/` surface as the primary interface. Mutation backends are backend-only and should be treated as blocked unless `cfctl` invoked them.

## Mutation Rules

- Read current state before writing.
- Use `cfctl explain <surface>` before working on an unfamiliar surface.
- Use `cfctl standards <surface>` to load the canonical configuration standards before designing a change.
- Use `cfctl standards audit` when the task depends on the actual Wrangler shape across a workspace root, not just one Cloudflare control-plane surface.
- Use `cfctl classify <surface> <operation>` before assuming a write is supported or safe on the current lane.
- Use `cfctl guide <surface> <operation>` when a write is non-trivial or unfamiliar.
- Use `cfctl previews` and `cfctl locks` when a preview/apply flow looks blocked or stale.
- Real writes require a reviewed preview first:
  run `cfctl apply ... --plan`, capture `operation_id`, then rerun with `--ack-plan <operation-id>`.
- Wrapped `wrangler` and `cloudflared` commands follow the same trust posture:
  clearly read-only subcommands can run directly, and everything else must go through `--plan` then `--ack-plan <operation-id>`.
- Token minting follows the same review gate:
  run `cfctl token mint ... --plan`, then rerun with `--ack-plan <operation-id>` and `--value-out <path>`. Stdout reveal is disabled unless runtime policy explicitly re-enables it.
- Token revocation follows the same review gate:
  run `cfctl token revoke --id <token-id> --plan`, then rerun with `--ack-plan <operation-id> --confirm delete`.
- Destructive operations require explicit confirmation such as `--confirm delete`.
- For desired-state-backed surfaces, use `diff` and `apply <surface> sync` instead of ad hoc repeated edits.
- Desired-state support means the engine exists for that surface. Managed specs are still opt-in and may be absent until they are checked into `state/`.
- If selectors resolve to zero or multiple resources, stop and fix targeting before planning a write.
- If `dev` is blocked and `global` is needed, state the lane switch explicitly and keep the same preview/apply evidence trail.

## Desired State

Desired state is selective, not universal.

Currently supported:

- `access.app`
- `access.policy`
- `dns.record`
- `hostname` (verify/diff/plan only)
- `tunnel`

Use:

```bash
cfctl diff <surface>
cfctl apply <surface> sync --plan
cfctl apply <surface> sync --ack-plan <operation-id>
```

State specs live under `state/`.

## Evidence Contract

Leave behind evidence for meaningful reads and writes:

- runtime envelopes: `var/inventory/runtime/`
- auth and token envelopes: `var/inventory/auth/`
- backend operation artifacts: `var/inventory/operations/`
- inventory snapshots and audits: `var/inventory/`
- logs: `var/logs/`

Repair helpers:

```bash
cfctl doctor --repair-hints
./scripts/verify_static_contract.sh
cfctl previews purge-expired
cfctl locks clear-stale
cfctl admin authorizations
```

Do not claim a change is done without verification evidence when a verification path exists.
Do not infer live Cloudflare truth from a passing source-config audit; use live `cfctl` reads for edge/account assertions.

## If You Are Extending This Runtime

- Treat `cfctl` as the only public interface.
- Add or update surface metadata in `catalog/surfaces.json`.
- Add or update runtime-level metadata in `catalog/runtime.json`.
- Put verb behavior in `commands/`.
- Put shared auth/result/lane/state logic in `lib/runtime/`.
- Put backend adaptation logic in `lib/backends/`.
- Keep legacy script entrypoints as compatibility shims or backends, not the primary UX.
- Guard any new mutation backend with `cf_require_backend_dispatch`.
- Update `README.md`, `docs/agent-landing.md`, and relevant docs when the public contract changes.

## Repo Reality

- This directory may be a normal git checkout. Verify live git state before committing or publishing, and do not assume branch state from this document.
- The original email-routing workflows still exist, but they are part of the broader runtime now.
- If you need the detailed human-facing overview, start with `README.md`. If you need the operational contract, start with this file and `cfctl`.
