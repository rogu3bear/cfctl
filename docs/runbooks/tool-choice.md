# Tool Choice

## Use cfctl First

Use `cfctl` from `PATH` as the public interface whenever possible. When standing in `.`, `./cfctl` is the equivalent local implementation.

It gives agents and operators:

- lane health and lane comparison
- capability discovery
- exact targeting rules
- live permission probes
- snapshot and diff verbs
- structured runtime results
- consistent verification semantics

## Use Direct API Wrappers For

- account-wide inventory
- zone inventory and DNS reads
- Access applications and policies
- tunnel inventory and configuration reads
- DNS and zone-level config work
- email routing
- backend implementation for targeted writes through `cf_api_apply.sh` and `cf_mutate_*.sh`
- any workflow that needs a durable JSON snapshot under `var/inventory/`

These are backend implementation paths. Prefer reaching them through `cfctl` unless you are extending the runtime itself.

Do not call mutation backends directly during normal operations. `cfctl` invokes them for you. Direct invocation is maintainer/debug-only and requires `cfctl admin authorize-backend` plus `CF_BACKEND_BYPASS_FILE=<authorization-path>`.

Mutation backends currently wrapped by `cfctl`:

- `./scripts/cf_mutate_dns_record.sh`
- `./scripts/cf_mutate_access_app.sh`
- `./scripts/cf_mutate_access_policy.sh`
- `./scripts/cf_mutate_turnstile_widget.sh`
- `./scripts/cf_mutate_waiting_room.sh`
- `./scripts/cf_mutate_logpush_job.sh`
- `./scripts/cf_mutate_tunnel.sh`

Use `./scripts/cf_api_apply.sh` when:

- you need a Cloudflare API write that does not yet have a dedicated wrapper
- the mutation is simple and JSON-backed
- you still want dry-run planning, redacted evidence, and optional readback verification

Use the backend scripts directly when:

- you are implementing a new `cfctl` surface
- you need a backend-specific debug pass
- the public `cfctl` contract has not been wired for that surface yet
- you are repairing or auditing a legacy workflow that intentionally bypasses the public runtime
- you have explicitly issued a scoped backend authorization with `cfctl admin authorize-backend`

## Use Wrangler For

- Worker-native deploy and management flows
- Worker versions and tailing
- D1, KV, R2, Queues, Hyperdrive, and related developer-product operations

Invoke Wrangler through `cfctl` for operator work:

```bash
cfctl wrangler <wrangler args>
```

Use `./scripts/cf_wrangler.sh` only when extending or debugging the wrapper itself.

## Use cloudflared For

- running a remotely-managed tunnel
- validating tunnel connectivity
- local ingress testing

`cloudflared` is runtime tooling. It is not the source of truth for account inventory or broader configuration.
