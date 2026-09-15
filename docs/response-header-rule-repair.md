# Targeted response-header rule repair

`updateZoneRulesetRule` supports a bounded PATCH to an existing zone rule in
`http_response_headers_transform`. Only `enabled` and `expression` may change.
Submit all six authored fields: `action`, `action_parameters`, `description`,
`enabled`, `expression`, and `ref`. The action must remain `rewrite`; this first
contract supports existing static `set` header definitions. Header definitions,
description and reference must equal the captured target. Position, preview,
other phases, unknown target definition fields, and broad replacement are rejected.

Cloudflare's PATCH requires all fields to retain in the definition and returns
the updated parent ruleset. An omitted position is not a request to reorder.
The native verifier still explicitly checks order rather than assuming it.
[Update a rule](https://developers.cloudflare.com/ruleset-engine/rulesets-api/update-rule/).

The existing call → pinned plan → exact approval → one run lifecycle applies.
This is `cross_config` risk and a reversible write, so approval is required even
though editing an existing rule adds no direct plan/configuration charge. Token
permissions are Zone Transform Rules Read and Write. Source-policy acceptance
is independent of provider authority. The operation creates no rules or plan
upgrade; normal plan entitlements and traffic usage remain in effect.
[Response Header Transform Rules](https://developers.cloudflare.com/rules/transform/response-header-modification/).

Preparation reads the complete exact parent ruleset and pins its identity,
version, target rule and ordered rule array to the plan. Before PATCH, the
runtime reads it again and rejects any snapshot drift. This check is not an
atomic provider CAS; an intervening external writer remains possible. Post-write
verification separately reads the parent, requires the exact intended target
fields and advanced parent/target versions, and compares all unrelated fields,
rules and order. Only provider version/time fields on the parent and edited
child may differ. Any unexpected difference requires rectification; an apply
response alone is insufficient proof.

The captured full parent and rule remain in the governed plan/evidence. Recovery
constructs a separate targeted PATCH containing the prior six-field definition,
with fresh snapshot checks and approval; it does not restore the whole ruleset
or automatically replay a consumed operation. Missing prior state, mismatched
hashes, or unknown rule shape rejects recovery preparation.

The admitted Founder use is two separately pinned changes: disable its duplicate
portal security-header override, then exclude the four portal hosts from the
existing generic HTML cache override. Refresh and plan each against current
state because the first update advances the parent version. Header ownership,
authenticated application behavior, cache behavior, marketing and deck checks
remain CF's later live acceptance work. Source tests do not establish those
provider or application outcomes.
