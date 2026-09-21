# Existing custom challenge expression repair

`zone-custom-challenge-expression-update` changes only the expression of one
existing `managed_challenge` or `js_challenge` rule in a zone
`http_request_firewall_custom` ruleset. Its consumer is an operator repairing a
challenge that prevents a legitimate application request from reaching its
application checks. It does not create exceptions automatically or prove that
other requests in the application journey will pass.

Discover the operation with `cfctl resolve "repair existing custom WAF challenge
expression" --json`, then read
`cfctl guide zone-custom-challenge-expression-update --json`. Read the current
parent with `getZoneRuleset`. Supply exact `zone_id`, `ruleset_id`, and `rule_id`
path selectors and a body containing:

```json
{
  "expression": "<reviewed replacement expression>",
  "expected_expression": "<current expression>",
  "expected_rule_version": "11",
  "expected_ruleset_version": "14",
  "expected_definition": {
    "action": "managed_challenge",
    "enabled": true,
    "expression": "<current expression>",
    "description": "<current description>",
    "ref": "<current ref>"
  }
}
```

The expected definition must match the live rule exactly. Rules with additional
authored fields are rejected; this contract must be extended and tested before
such rules can use it. Action, enablement, description and ref cannot change.
The provider request carries the existing definition with only its expression
replaced, because [Cloudflare's update contract](https://developers.cloudflare.com/ruleset-engine/rulesets-api/update-rule/)
requires including the fields that must remain in the new definition. Expected
versions and other local guard fields are never sent to Cloudflare. No position,
query, conditional header, whole-parent replacement or generic security-rule
fallback is admitted.

The operation requires Zone WAF Read and Zone WAF Write. It creates a plan;
security approval remains bound to that exact operation via
`cfctl plans approve <operation-id> --yes`, then execution uses
`cfctl plans run <operation-id>`. Editing an existing rule has no direct
configuration charge; changed traffic matching can affect application load and
usage. This operation does not authorize additional spend.

Planning captures the complete parent and hashes it into the plan. Execution
reads it again and rejects any drift, including unrelated rules and order.
This read-before-write check is **not provider-atomic compare-and-swap**: a race
between the read and PATCH is still possible. The authenticated PATCH response
and subsequent parent GET must agree, show the intended expression and advancing
rule/ruleset versions, and preserve every other field and rule order. Collateral
drift leaves the operation requiring rectification, rather than verified.

The PATCH is attempted once, without transport retries or an assumed provider
idempotency guarantee. HTTP 429 or 5xx leaves its outcome ambiguous and records
an authenticated parent GET when available. Matching current state alone cannot
prove which writer caused it, so it does not verify the operation or authorize
automatic rollback. Transport or readback failure also preserves rectification
custody; inspect the exact parent with `getZoneRuleset` without replaying PATCH.

`cfctl plans rectify <operation-id>` can draft a separate recovery plan when
authenticated apply and post-change readback receipts prove the target still
has the expression and exact target state returned by this operation. Recovery
restores only the prior expression, retains observed unrelated rules, and binds
the observed versions and complete parent anew. Later drift rejects planning
or execution. Recovery requires its own reviewed approval; it never replays the
consumed operation. Missing receipts, failed transport, unsupported target
shape, or a later target edit require reconciliation, not inferred recovery.

After provider verification, exercise the affected application request and its
downstream workflow separately. A successful token bootstrap does not establish
room admission, signaling, media or screen sharing.
