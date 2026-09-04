# cfctl Anchor

These invariants constrain implementation. A conflicting change must update
this file deliberately or must not ship.

## Product Boundary

- `cfctl` is the only public interface for Cloudflare account work; `./cfctl`
  is its checkout-local equivalent.
- Backend scripts, provider adapters, and the archived v1 runtime are private
  implementation or migration evidence, never a parallel public surface.
- Application repositories own their source configuration. This repository
  owns the cataloged path to live Cloudflare control-plane truth.
- A capability exists publicly only when the catalog and command surface carry
  it. Prose cannot create support or authority.

## Safety Boundary

- Reads identify their evidence class. Source configuration is not live state,
  a plan is not an apply, and an apply is not verification.
- Writes bind current state, target, input, build, credentials, policy, impact,
  cost, verification, and compensation in a canonical `PlanV2` before apply.
- Protected work runs only under its exact approved operation or a narrowly
  activated standing authority. Drifted, consumed, ambiguous, or legacy-only
  plans fail closed.
- Scoped credentials are the normal lane. Emergency credentials are explicit
  and are never selected silently.
- Secret values never enter arguments, stdout, plans, logs, evidence, or the
  repository.
- Meaningful claims leave redacted, content-addressed evidence. Artifact
  presence alone never proves the claim.

## Simplicity Boundary

- Use the least powerful mechanism that fully expresses the requirement.
- Generalize only after multiple consumers demonstrate the same stable
  invariant. Similar names, markup, or appearance are not enough.
- One abstraction owns one concept. A shared layer must reduce total policy or
  duplication, not merely relocate it.
- Keep orchestration thin. Contracts belong with the crate or catalog domain
  that can validate them.
- Every new durable surface names its consumer, failure mode, proof, and a
  condition for removal or consolidation.

For the public website, climb this ladder only as evidence requires it:

1. semantic HTML and CSS
2. small static Leptos components
3. local client state for genuine interaction
4. a server boundary for protected or dynamic data
5. shared framework machinery after a repeated invariant is proven

The website explains the control plane; it is not a second control plane.

## Operating Boundary

- Resolve intent and inspect the generated guide before improvising a path.
- One active owner mutates a checkout, index, plan, or live target at a time.
- Preserve unrelated dirty work and bind proof to the exact tree or full SHA.
- Keep source, local proof, review, merge, apply, and authenticated live
  readback visibly separate.
- Do not call work complete while an available verification path has not
  passed.
- Local proof is `cargo xtask verify`. Unsigned release assembly is
  `cargo xtask assemble`, which runs that proof first. `cargo xtask release` is
  the signed superset and additionally requires the release trust roots.

## Ownership Boundaries

- `crates/cfctl-core`: public contracts and redaction
- `crates/cfctl-auth`: credentials and profiles
- `crates/cfctl-catalog`: capability schema, documentation, and adapter metadata
- `crates/cfctl-cloudflare`: provider request and response execution
- `crates/cfctl-planner`: policy, impact, and plan construction
- `crates/cfctl-registry`: rebuildable resource, ownership, desired-state, and
  event projections
- `crates/cfctl-workspace`: registered-root discovery and impact graph
- `crates/cfctl-agent`: agent installation and handoff
- `crates/cfctl-storage`: durable plans, locks, imports, and evidence
- `crates/cfctl-cli`: orchestration and the public parser
- `xtask`: repository verification, release assembly, signing, and publication

Ownership moves only with consumer migration and proof that the previous owner
no longer serves a live contract.
