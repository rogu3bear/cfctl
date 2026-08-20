# cfctl Authority Layers

This file owns precedence and classification. It creates no product doctrine.
Higher layers constrain lower layers; lower layers realize higher ones. Repair
drift at the lowest layer that owns the disputed claim.

## Authority Stack

| Layer | Owns | Canonical source |
|---|---|---|
| L0 — Purpose | destination, outcomes, strategic test | `NORTH_STAR.md` |
| L1 — Invariants | product, safety, simplicity, operating, and ownership boundaries | `ANCHOR.md` |
| L2 — Public contract | supported commands, types, and operator semantics | `README.md`, `CFCTL_PROMPT.md`, `docs/runtime-policy.md`, `docs/v2-architecture.md` |
| L3 — Capability | exact supported operations, schemas, adapters, and guidance | catalog metadata consumed by `cfctl catalog`, `resolve`, `guide`, and `call` |
| L4 — Implementation | behavior that realizes the contract | `crates/*`, `site/*`, the public `cfctl` binary |
| Gate — Proof | checks required before integration or release | `LOCAL_CI.md`, `cargo xtask verify`, `cargo xtask release` |

The catalog is authoritative for whether a capability exists and how it is
called. It does not outrank the product and safety boundaries above it. A new
capability therefore lands with its implementation, catalog declaration,
public documentation, and proof in one coherent change.

## Projections and Evidence

`AGENTS.md` and `CLAUDE.md` are local operator adapters. They project the
tracked doctrine and public contract for a particular harness; they carry no
independent product truth and cannot widen authority.

`CONTRIBUTING.md`, runbooks, and website planning documents are consumers. They
may explain a bounded workflow but cannot redefine a higher layer.

`NUANCE.md` is a private evidentiary sidecar. A reproduced observation may
falsify an assumption at any layer, but cannot create doctrine, grant
permission, or prove runtime state by narration.

## Residence

The repository-specific constitutional core is tracked:

- `NORTH_STAR.md` owns why and toward what
- `ANCHOR.md` owns what must remain true
- `LAYERS.md` owns where each kind of truth lives

Local adapters and live-estate evidence remain ignored. A clone or worktree
must receive the same constitution without inheriting a private operator or
account context.

## Conflict Rule

When sources disagree:

1. state the exact conflicting claims
2. identify the owner of that truth domain
3. test the claim against executable or live evidence where applicable
4. update consumers before retiring an old definition
5. prove the projection and the owning implementation agree

Do not average incompatible claims into false coherence. Tool identity,
recency, and confident prose do not decide authority.
