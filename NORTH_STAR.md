# cfctl North Star

`cfctl` exists to make Cloudflare account work safe, repeatable, and
evidence-backed through one local public control plane.

## Canonical Sentence

`cfctl` is a local-first Cloudflare control plane that wraps Wrangler,
cloudflared, and the Cloudflare API behind a strict, catalog-driven CLI with
preview-before-apply and evidence artifacts.

## Core Promise

- Agents and operators use one public interface for Cloudflare reads, standards,
  capability checks, mutation plans, applies, and verification.
- Every meaningful read or write leaves evidence under `var/inventory/` or
  `var/logs/`.
- Writes are previewed first, acknowledged by `operation_id`, and verified after
  apply when a verification path exists.
- Backend scripts remain implementation details unless the runtime explicitly
  authorizes a backend path.

## System Shape Today

- `cfctl` is the public executable. From this repo, `./cfctl` is equivalent.
- `commands/` contains verb handlers for the public command surface.
- `catalog/` defines runtime verbs, Cloudflare surfaces, permissions,
  standards, and docs-bank metadata.
- `state/` contains selective desired-state specs and ownership/hostname
  authority.
- `scripts/` contains backend inventory, mutation, wrapper, and compatibility
  logic.
- `docs/`, `README.md`, `QUICKSTART.md`, and `CFCTL_PROMPT.md` explain the
  operator and embedding contracts.

## What Good Looks Like

Good `cfctl` work:

- keeps new capabilities exposed through `cfctl`, catalogs, command handlers,
  docs, and verification together
- fails closed when selectors, permissions, lanes, or supported operations are
  unclear
- distinguishes source-config standards from live Cloudflare truth
- uses the `dev` lane first and switches to `global` only when proven necessary
- records preview, apply, inventory, auth, and verification evidence
- improves the public control plane instead of teaching agents direct scripts

## Strategic Direction

Prefer changes that:

- expand catalog-backed surface coverage with preview-gated write paths
- make desired-state support deliberate and inspectable
- improve permission/lane diagnostics before widening mutation authority
- strengthen ownership and standards audits across app repos
- make Cloudflare docs and capability drift visible before agents act on stale
  assumptions

Avoid changes that:

- expose backend scripts as the primary UX
- let agents freestyle Cloudflare API writes
- skip preview or acknowledgement gates
- hide token or lane assumptions in shell fragments
- encode Codex or Claude as favored over the other agent

## Decision Filter

Before accepting significant work, ask:

1. Is this reachable through the public `cfctl` surface?
2. Are selectors, permissions, and lane behavior explicit?
3. Does the write path plan before apply and verify after apply?
4. Does it leave a reusable evidence artifact?
5. Does it make app repos safer without turning them into Cloudflare control
   planes?
