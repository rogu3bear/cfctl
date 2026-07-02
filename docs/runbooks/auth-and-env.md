# Auth And Env

## Primary Contract

- Primary credential: `CF_DEV_TOKEN`
- Emergency credential: `CF_GLOBAL_TOKEN`
- Canonical source: `~/.config/cfctl/.env` unless `CF_SHARED_ENV_FILE` overrides it
- Account pin: `CLOUDFLARE_ACCOUNT_ID`
- Lane selector: `CF_TOKEN_LANE=dev|global`

All repo scripts use the shared loader in `scripts/lib/cloudflare.sh`.

Load order:

1. `~/.config/cfctl/.env` or `CF_SHARED_ENV_FILE` (shell-sourced, canonical)
2. optional repo-local `.env.local` (shell-sourced, overrides shared)
3. workspace fallback `CF_WORKSPACE_ENV_FILE` (default `~/dev/.env`) — strict
   `KEY=VALUE` import only, never executed as shell, allowlisted to the lane
   credentials plus lane requirements and `CLOUDFLARE_ACCOUNT_ID`, and it
   fills gaps only: a value already set by the process env, shared file, or
   repo file always wins. Unrelated workspace secrets are never imported.
   Set `CF_WORKSPACE_ENV_FILE=""` to disable the fallback entirely.

The allowlist is derived from `catalog/runtime.json` (`lanes[*].credential_env`,
`lanes[*].requires`, and `env_import.allowlist`), so adding a lane extends it
without code changes.

## Provenance And Drift

Because the same credential can legitimately exist in more than one file,
cfctl tracks where each allowlisted variable came from and flags drift:

- `cfctl env sources` reports, read-only, each tracked variable's winning
  source and per-file fingerprints (truncated SHA-256, never values).
- `cfctl doctor` includes the same data under `result.env_health`, reports
  `summary.credential_drift_count`, and degrades overall status when the same
  variable differs across sources — the signal that a rotation landed in one
  file but not the canonical one.
- Repair stays manual by design: update the canonical shared env file, then
  re-run `cfctl doctor`. cfctl never syncs secret values between files.

## Stray Files

The repo override file is `.env.local`. A repo-root `.env` is **not** read by
cfctl; secrets placed there have no consumer, and `cfctl doctor` surfaces a
hint when one exists.

After loading, the library selects an active lane and exports:

- `CF_ACTIVE_AUTH_SCHEME`
- `CF_ACTIVE_TOKEN_LANE`
- `CF_ACTIVE_TOKEN_ENV`
- `CLOUDFLARE_API_TOKEN` when the active lane is `dev`
- `CLOUDFLARE_API_KEY` when the active lane is `global`

That keeps direct API calls and Wrangler on the same credential.

External repo deploy scripts should not source cfctl env files themselves.
Use `cfctl env run` when an app repo owns deploy semantics but cfctl owns
credential hydration:

```bash
CF_SHARED_ENV_FILE=/Users/star/dev/.env cfctl env run --lane dev -- \
  /Users/star/dev/jkca-web/scripts/deploy-all.sh --only edge-router
```

The child process receives the lane-derived Cloudflare tool env, such as
`CLOUDFLARE_API_TOKEN` on the `dev` lane. Parent lane secrets such as
`CF_DEV_TOKEN`, `CF_GLOBAL_TOKEN`, and `CF_ACTIVE_AUTH_SECRET` are stripped from
the child environment. Child output is redacted before it reaches the terminal,
and the runtime artifact records the lane/env mapping and command argv without
cfctl token values. Because argv is evidence, do not pass secrets as command
arguments.

In this workspace, `CF_DEV_TOKEN` may be an account-scoped API token rather than a user-scoped token. The auth probe handles that by verifying the currently active lane against:

- `/accounts/$CLOUDFLARE_ACCOUNT_ID/tokens/verify` first when account context is available
- `/user/tokens/verify` as the fallback

## Credential Separation

- `CF_DEV_TOKEN`:
  day-to-day Cloudflare API mutation and inventory across this workspace.
- `CF_GLOBAL_TOKEN`:
  emergency wider-scope Global API key lane for surfaces the primary token cannot reach cleanly.
- `CLOUDFLARE_EMAIL`:
  required alongside `CF_GLOBAL_TOKEN` for Global API key auth and Wrangler legacy auth.
- `CLOUDFLARE_ACCESS_CLIENT_ID` and `CLOUDFLARE_ACCESS_CLIENT_SECRET`:
  only for calling Access-protected applications.
- `CF_TUNNEL_TOKEN`:
  only for running a remotely-managed tunnel with `cloudflared`.

Do not treat Access service tokens or tunnel tokens as substitutes for the account API credential.

## Verification

Run:

```bash
cfctl doctor
cfctl lanes
CF_SHARED_ENV_FILE=/Users/star/dev/.env cfctl env run --lane dev -- env
cfctl can dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --all-lanes
CF_TOKEN_LANE=global cfctl can dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --all-lanes
./scripts/cf_auth_check.sh
CF_TOKEN_LANE=global ./scripts/cf_auth_check.sh
./scripts/cf_wrangler.sh whoami
CF_TOKEN_LANE=global ./scripts/cf_wrangler.sh whoami
./scripts/cf_compare_token_coverage.sh
```

`cfctl doctor` is the fastest trust check for the runtime as a whole.
`cfctl lanes` is the fastest lane-only health check for the configured lanes.
`cfctl can ... --all-lanes` is the fastest way to see whether a surface is reachable on `dev`, `global`, or both.
`cfctl token mint ...` uses the currently active lane. In practice, token creation should run on the lane that has `Account API Tokens Write`.
By default, real token mints keep the secret out of stdout. Use `cfctl token mint ... --plan`, then rerun with `--ack-plan <operation-id>` and `--value-out <path>`. `--reveal-token-once` exists, but runtime policy disables it unless an operator explicitly re-enables one-time stdout reveal.
`cf_auth_check.sh` verifies the currently active Cloudflare credential directly.
`cf_wrangler.sh` proves Wrangler compatibility using the lane-derived `CLOUDFLARE_API_TOKEN` or `CLOUDFLARE_API_KEY` and a repo-local Wrangler home under `var/wrangler-home/`.
`cf_compare_token_coverage.sh` compares what `CF_DEV_TOKEN` and `CF_GLOBAL_TOKEN` can actually reach and banks the difference under `var/inventory/auth/`.
