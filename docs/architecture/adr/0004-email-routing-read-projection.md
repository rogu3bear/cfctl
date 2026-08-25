# ADR 0004: Normalize Email Routing rule inventory in cfctl

- Status: accepted
- Date: 2026-08-17

## Context

The generated Email Routing rules capability returned Cloudflare's raw rule
objects. Application repositories consequently had to interpret matcher
variants, decide whether numbered pagination was complete, and determine which
action values were safe to retain. A governed read demonstrated two provider
behaviors that were not represented by the downstream assumptions:

- a valid rule may contain a type-only matcher with no `field` or `value`;
- page metadata may omit `total_pages` even when `page`, `per_page`, and
  `total_count` are present.

Raw rule actions may also contain forwarding destinations. Returning those
values through ordinary stdout and evidence is unnecessary for topology
consumers and expands the identity-disclosure boundary.

Cloudflare's account-scoped rule inventory additionally identifies the domain
and parent zone associated with each rule. That is the authoritative surface
for distinguishing a subdomain catch-all from its parent-zone catch-all, but
the provider returns both identities in plaintext.

## Decision

`cfctl-core` owns the versioned `EmailRoutingRuleSetV1` contract. The exact
`email-routing-routing-rules-list-routing-rules` capability is recognized only
when its ID, GET method, zone-scoped path, non-mutating classification, and
Cloudflare JSON response envelope all match the pinned contract.

cfctl derives a separate
`email-routing-account-rules-list-routing-rules` capability from that pinned
read contract. It targets only
`GET /accounts/{account_id}/email/routing/rules`; its normalized rules add
`zone_name_sha256` and `zone_tag_sha256`, never the plaintext provider values.

`cfctl-cloudflare` requests at most 50 items per page, accepts a stable
provider-capped page size, and follows coherent provider page metadata through
its authoritative `total_pages`. When metadata is absent, it uses a bounded
empty-terminal-page probe instead. Mixed, cursor-based, count-incoherent, or
unstable metadata fails closed, and all paths allow at most 100 performed page
reads. Every rule, matcher, action, action value, and copied string is bounded
before projection. Field-bound matchers
retain their field and a `sha256:` identity of the matcher value; matcher
plaintext never enters the projection. Type-only matchers remain type-only.
Worker actions retain validated Worker targets. Non-Worker action values are
reduced to a count and never enter the returned result or durable evidence.

Successful calls return only `EmailRoutingRuleSetV1`, not the raw provider
rule array. Provider-shape, size, or termination failures return a bounded
`EmailRoutingRuleDiagnosticV1`; the CLI keeps `performed: true`, marks
verification failed, emits `CFCTL_RESPONSE_CONTRACT_MISMATCH`, and records no
raw rule values. Catalog description and aliases expose the typed projection,
and exact capability drift blocks the adapter.

Account-scoped consumers may prove one subdomain catch-all only from complete
pagination and exact cardinality across the hashed domain, hashed parent zone,
one enabled `all` matcher, and one exact Worker action. The zone-only catch-all
endpoint is not subdomain evidence.

## Consequences

- Provider normalization and pagination completeness have one authority.
- Application repositories consume a stable versioned result rather than
  reproducing Cloudflare response semantics.
- Forwarding destinations are not needed to prove Worker routing and no longer
  cross the cfctl stdout/evidence boundary.
- Existing raw-result consumers must cut over to `EmailRoutingRuleSetV1`
  before adopting a release containing this change. The generic capability is
  intentionally not dual-emitted because retaining raw results would preserve
  the disclosure and authority split this decision removes.
- This contract proves bounded provider inventory only. It does not establish
  application route policy, mail delivery, inbox receipt, or reply identity.
