# Auth And Env

## Primary Contract

- Primary credential: `CF_DEV_TOKEN`
- Emergency credential: `CF_GLOBAL_TOKEN`
- Canonical source: `~/dev/.env`
- Account pin: `CLOUDFLARE_ACCOUNT_ID`
- Lane selector: `CF_TOKEN_LANE=dev|global`

All repo scripts use the shared loader in `scripts/lib/cloudflare.sh`.

Load order:

1. `~/dev/.env`
2. optional repo-local `.env.local`

After loading, the library selects an active lane and exports:

- `CF_ACTIVE_AUTH_SCHEME`
- `CF_ACTIVE_TOKEN_LANE`
- `CF_ACTIVE_TOKEN_ENV`
- `CLOUDFLARE_API_TOKEN` when the active lane is `dev`
- `CLOUDFLARE_API_KEY` when the active lane is `global`

That keeps direct API calls and Wrangler on the same credential.

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
