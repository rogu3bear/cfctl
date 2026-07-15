# Adapter choice in cfctl v2

There is no separate agent-selected tool-choice command. Search the catalog;
the selected `CapabilityV1` contains the governed adapter status and blocker.

```bash
cfctl catalog search "<intent>" --json
cfctl catalog show <capability-id> --json
```

Use statuses in this order only when the catalog declares them:

1. `native` for operation-specific cfctl behavior.
2. `dynamic_api` for schema-validated Cloudflare API execution.
3. `delegated_cli` for governed Wrangler or cloudflared execution.
4. `governed_ui` for a target-bound browser/Computer Use handoff after API and
   CLI insufficiency has been established.
5. `blocked` when entitlement, permission, cost, verification, or adapter
   requirements are unmet.

Adapter selection does not grant authority. Every write still follows the
hash-bound plan, risk policy, approval, lock, execution, verification, and
evidence lifecycle. Do not invoke archived backend scripts, direct API calls,
or Cloudflare API MCP to bypass catalog status.

For unknown Cloudflare capabilities, run `cfctl catalog sync`; the synchronizer
ingests the official OpenAPI schema, docs/changelog feeds, and installed CLI
help. If an official operation remains unsupported, it stays discoverable with
an exact blocker until cfctl gains a safe adapter.
