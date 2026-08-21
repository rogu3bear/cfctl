# cfctl North Star

`cfctl` makes Cloudflare account work safe, repeatable, and inspectable through
one local public control plane.

## Promise

An operator or agent should be able to discover what Cloudflare can do, read
live state, prepare a fully pinned change, obtain the required authority, apply
it once, and verify the result without inventing an unsafe side channel.

That promise requires:

- one public interface: `cfctl`
- a catalog that declares supported capabilities and their contracts
- fail-closed targeting, credentials, policy, cost, and execution
- explicit approval for protected work
- redacted, content-addressed evidence for meaningful claims
- an honest distinction between source configuration, plans, applies, and live
  verification

## Strategic Posture

Build the smallest coherent control plane that can keep the promise.
Complexity is a liability until a demonstrated invariant requires it.

Prefer work that:

- completes a real operator journey through the catalog and public CLI
- removes ambiguity before it widens authority
- makes drift, impact, and recovery visible
- strengthens proof at the boundary where a claim becomes consequential
- simplifies the system while preserving its safety guarantees

Decline work that:

- creates another public path around `cfctl`
- generalizes from visual or verbal similarity instead of shared behavior
- turns a documentation or website need into a second application platform
- hides uncertainty behind orchestration, generated prose, or green checks
- expands surface area without a named consumer and retirement path

## Outcome

Good `cfctl` work leaves the operator with less uncertainty and no unnecessary
machinery. It makes the safe path the obvious path, records enough evidence for
the next operator to trust or challenge the result, and keeps application
repositories from becoming accidental Cloudflare control planes.

## Decision Filter

Before accepting significant work, ask:

1. Which operator outcome does this complete?
2. What existing authority or capability already owns the requirement?
3. What is the least powerful mechanism that fully satisfies it?
4. Where can this fail, and does it fail closed?
5. What evidence will distinguish implementation, apply, and verified outcome?
6. What can be removed or left unbuilt if this succeeds?
