# Auth

This runtime has two Cloudflare auth lanes:

- `dev`
  default lane backed by `CF_DEV_TOKEN`
- `global`
  emergency wider-scope lane backed by `CF_GLOBAL_TOKEN` and `CLOUDFLARE_EMAIL`

Core commands:

```bash
cfctl doctor
cfctl lanes
cfctl can dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --all-lanes
CF_TOKEN_LANE=global cfctl can dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --all-lanes
```

Operational rules:
- load credentials from `~/.config/cfctl/.env` or the `CF_SHARED_ENV_FILE` override
- use `dev` first
- switch to `global` explicitly when the surface is blocked or the operation is intentionally emergency-scope
- classify or guide a write before applying it
- keep Access service tokens and tunnel tokens separate from Cloudflare account auth

Detailed runbook:
- [docs/runbooks/auth-and-env.md](docs/runbooks/auth-and-env.md)
