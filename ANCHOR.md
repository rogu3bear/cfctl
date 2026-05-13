# cfctl Anchor

This file captures the truths that should stay stable while the Cloudflare
control plane evolves. If proposed work conflicts with this file, update this
file intentionally or do not ship the work.

## Identity

`cfctl` is the local public control plane for Cloudflare account work. It is not
a miscellaneous script folder and not a license for agents to call raw
Cloudflare APIs from application repos.

## Stable Truths

- `cfctl` is the public interface; `./cfctl` is the local equivalent inside this
  repo.
- Backend scripts are implementation details unless extending/debugging the
  runtime or explicitly authorized by `cfctl admin authorize-backend`.
- Account-level mutations require current-state reads, classification, guidance
  when useful, `--plan`, reviewed `operation_id`, `--ack-plan`, and
  verification when available.
- `CF_DEV_TOKEN` is the default lane. `CF_GLOBAL_TOKEN` is an explicit wider
  lane used only when the task or `cfctl can ... --all-lanes` proves it is
  needed.
- Source-config audits prove checked-in app config posture; live account truth
  requires live `cfctl` reads.
- Meaningful operations should leave evidence under `var/inventory/` or
  `var/logs/`.

## Ownership Boundaries

- `catalog/` owns public surface, permission, standards, and runtime metadata.
- `commands/` owns public verb behavior.
- `lib/runtime/` owns auth, lanes, results, desired-state helpers, and common
  policy.
- `lib/backends/` and `scripts/` own backend adaptation.
- `state/` owns selective desired state, ownership authority, and hostname
  lifecycle specs.
- App repos own their checked-in Wrangler/source config and app-specific deploy
  scripts; this repo owns live Cloudflare control-plane truth.

## Operational Anchors

- Runtime health: `cfctl doctor`
- Surface list: `cfctl surfaces`
- Ownership integrity: `cfctl ownership check`
- Standards audit: `cfctl standards audit`
- Static contract verification: `./scripts/verify_static_contract.sh`
- Public contract verification: `./scripts/verify_public_contract.sh`

Do not claim a Cloudflare change is complete without preview/apply/verify
evidence when those lanes exist.

## Agent Anchors

- Codex and Claude are peer operator agents in this repo.
- Neither agent has default supremacy over git, dependencies, Cloudflare,
  verification, or release proof.
- The active operator instruction, repo-local quartet, live git state, and
  declared slice boundaries decide ownership.
- One agent at a time may mutate shared files, the git index, branch topology,
  catalog policy, auth policy, or live Cloudflare state.

## Anti-Goals

- Teaching app repos to bypass `cfctl` for account-level work.
- Adding undocumented mutation surfaces.
- Treating desired state as universal when only selected surfaces support it.
- Revealing token values to stdout or logs.
- Hiding destructive behavior behind friendly wrapper names.

## Decision Questions

1. Does this preserve `cfctl` as the single public interface?
2. Does this keep backend scripts backend-only?
3. Does this fail closed on missing selectors, unsupported surfaces, and unclear
   permissions?
4. Does this leave evidence a future operator can inspect?
5. Does this improve Cloudflare safety for the whole workspace?
