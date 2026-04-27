# Contributing to cfctl

Thanks for considering a contribution. `cfctl` is a strict, catalog-driven Cloudflare control plane — that strictness is the product, so the bar for changes is "the public contract still holds." This document explains what that means in practice.

## Ground rules

- **`cfctl` is the public surface.** New capabilities should land in the catalog (`catalog/runtime.json`, `catalog/surfaces.json`, `catalog/standards.json`), the public verb handlers under `commands/`, and the docs together. Don't expose a feature in docs that isn't catalog-backed.
- **Backend scripts stay backend.** Anything in `scripts/` that mutates state must call `cf_require_backend_dispatch` so it cannot be invoked outside `cfctl` or an explicit `cfctl admin authorize-backend` lease.
- **Writes go through preview + ack.** If you add a write path, route it through `--plan` -> `operation_id` -> `--ack-plan <operation_id>` and leave evidence under `var/inventory/`.
- **Secrets are sink-only by default.** Token output should default to `--value-out <absolute path>`, never stdout.
- **Read before you change.** Run `cfctl doctor`, `cfctl surfaces`, and `cfctl explain <surface>` before editing the surface in question.

## Development setup

```bash
git clone https://github.com/rogu3bear/cfctl.git
cd cfctl
cp .env.example .env  # fill in CF_DEV_TOKEN and CLOUDFLARE_ACCOUNT_ID
./scripts/verify_static_contract.sh  # offline structural checks
./cfctl doctor                       # live auth + tooling check
```

Required tools: `bash`, `jq`, `curl`, `python3` (for the standards audit), and optionally `wrangler` and `cloudflared` if you want to use the wrapped commands.

## Making a change

1. Open an issue first for anything beyond a typo or trivial bug. The smallest useful unit of work is "a single surface, a single verb, with docs and a passing static contract check."
2. Branch off `main`.
3. Keep changes scoped. A change that touches `catalog/`, `commands/`, `lib/`, and `docs/` for the same surface is fine. A change that touches three unrelated surfaces is not.
4. Run `./scripts/verify_static_contract.sh` until it's clean. If you add a new check, document it.
5. If you have credentials available, run `./scripts/verify_public_contract.sh` against a non-production account.
6. Open a pull request. Describe the surface, the operation, the lane(s) touched, and which artifacts you produced.

## Style

- Bash: `set -euo pipefail`, quote everything, prefer `jq` for JSON over hand-rolled parsing, log via the shared `cf_setup_log_pipe` helper.
- JSON catalog files: keep them sorted within sections; one surface per top-level key.
- Markdown docs: link with relative paths only — never absolute paths. Examples must use `example.com` / `example.org` zones, not real domains.
- No commits with hardcoded zone names, account IDs, IP addresses, or email addresses you actually own. The `var/` and `.gitignore` rules exist to keep those out of history; please don't undo them.

## Adding a new surface

The minimum is:

1. Add the surface entry to `catalog/surfaces.json` with `selectors`, `actions`, `examples`.
2. Add a standards entry to `catalog/standards.json`.
3. If desired-state is in scope, add the surface to `catalog/runtime.json` `desired_state`, drop a module under `lib/surfaces/`, and add `state/<surface>/README.md` explaining the spec shape.
4. Add backend(s) under `scripts/` with `cf_require_backend_dispatch` if writes are involved.
5. Update `docs/capabilities.md` (regenerated from catalogs) and any relevant runbook.
6. Add or extend assertions in `scripts/verify_static_contract.sh`.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not file public issues for vulnerabilities.

## Credit

`cfctl` was created by James KC Auchterlonie. Contributions are welcome under the MIT license; you retain copyright on your contributions.
