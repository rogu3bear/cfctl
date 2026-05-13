# cfctl Claude Contract

This repo is the local Cloudflare control plane. Claude and Codex are peer
operator agents here; neither tool is favored for git, dependencies,
Cloudflare, verification, or release proof.

## First Moves

- Report the repo root, live branch, dirty tree, and active write slice before
  non-trivial edits.
- Read `NORTH_STAR.md`, `ANCHOR.md`, `AGENTS.md`, and this file.
- Run or request `cfctl doctor` before non-trivial Cloudflare operations.
- Distinguish source-config audits from live Cloudflare account truth.

## Canonical Commands

```sh
cfctl doctor
cfctl surfaces
cfctl ownership check
cfctl standards audit
./scripts/verify_static_contract.sh
./scripts/verify_public_contract.sh
```

Use `./cfctl` when `cfctl` is missing from `PATH` while standing in this repo.

## Repo Shape

- `cfctl`: public executable and local entrypoint.
- `commands/`: public verb handlers.
- `catalog/`: runtime, surface, permission, standards, and docs-bank metadata.
- `lib/runtime/`: shared auth, lane, result, policy, and desired-state logic.
- `lib/backends/` and `scripts/`: backend implementation details.
- `state/`: selective desired-state specs, ownership registry, and hostname
  lifecycle specs.
- `var/`: ignored runtime evidence and logs.

## Working Rules

- Expose durable capability through `cfctl`, not by documenting direct backend
  script use.
- Add or update catalog metadata with command behavior and docs in the same
  change when public behavior changes.
- Use `CF_DEV_TOKEN` first. Switch to `CF_GLOBAL_TOKEN` only when proven
  necessary.
- Preview writes with `--plan`, apply with `--ack-plan <operation_id>`, and
  verify when possible.
- Do not reveal token values in stdout, logs, docs, or examples.
- Keep app-repo Cloudflare work scoped: app repos own source config, this repo
  owns live account control.

## Verification

Use the smallest relevant proof:

- Shell/static contract edits: `./scripts/verify_static_contract.sh`
- Public Cloudflare contract edits: `./scripts/verify_public_contract.sh`
- Standards behavior: `cfctl standards audit <repo>`
- Live surface behavior: `cfctl list|get|snapshot|verify <surface>`

If live verification is unavailable because credentials or lanes are missing,
say that explicitly and report the static evidence that did run.
