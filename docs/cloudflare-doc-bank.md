# Cloudflare Docs Bank

This repo keeps a compact bank of official Cloudflare documentation and current capability movement.

Use it through the runtime:

```bash
cfctl docs
cfctl docs watch
cfctl docs api-gateway
cfctl docs browser-run
cfctl docs ai-search
```

The machine-readable source of truth is:

- [catalog/cloudflare-doc-bank.json](catalog/cloudflare-doc-bank.json)

## What This Bank Is

- A curated bank of stable Cloudflare references this runtime depends on
- A watchlist of incoming, beta, renamed, or fast-moving Cloudflare capabilities
- A compact orientation surface for agents landing here

## What This Bank Is Not

- Not a mirror of the whole Cloudflare changelog
- Not a dump of every Workers AI model addition
- Not a second Cloudflare docs site

The rule is: track platform-shape changes that matter for operating Cloudflare from this repo.

Tracked here does not automatically mean operable through `cfctl` today. Use:

- `cfctl surfaces` for the current operable runtime surface
- `cfctl standards` for configuration guidance
- `cfctl docs` for tracked official Cloudflare movement

## Refresh Rules

Refresh the bank when:

- Cloudflare launches or renames a capability that changes how agents can operate
- a beta becomes operationally relevant here
- `cfctl` grows a surface that depends on a new Cloudflare doc family
- a broad Cloudflare research or architecture pass needs current truth

The bank is curated and checked in. `checked_on` plus `refresh_interval_days`
in the bank tell you how fresh that curation is supposed to be.

## Current Watch Areas

As of `2026-04-22`, the bank intentionally tracks:

- managed Cloudflare MCP servers
- AI Search
- Browser Run
- Workflows
- Dynamic Workers
- Workers VPC
- Containers
- Secrets Store
- Pipelines
- API Shield vulnerability scanning
- Workers Builds

## Official Source Policy

The bank uses official Cloudflare docs only:

- `developers.cloudflare.com`

Preferred source order:

1. Product docs
2. Product changelog
3. API reference

When reading Cloudflare docs programmatically, prefer:

- `https://developers.cloudflare.com/llms.txt`
- `https://developers.cloudflare.com/llms-full.txt`
- per-page Markdown via `/index.md`

See also:

- [docs/official-cloudflare-reference.md](docs/official-cloudflare-reference.md)
