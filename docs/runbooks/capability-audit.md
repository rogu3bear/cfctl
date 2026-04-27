# Capability Audit

Run:

```bash
./scripts/cf_inventory_capability_audit.sh
```

This synthesizes the live inventory into four buckets:

- in use and inventoried
- present but unused or empty
- partially covered or permission-limited
- high-level Cloudflare areas not yet inventoried in this repo

Use it when you want to know both what the account is already using and what Cloudflare product areas are still untouched or unbanked here.

Recent expansions now feed the audit directly:

- Workers AI bindings and the AI model catalog
- Images, Stream, and Calls
- Zero Trust locations, lists, proxy endpoints, logging, and device posture
- Zero Trust fleet posture, DLP profiles, and CASB integrations
- Browser Isolation posture derived from Access applications and Gateway rules
- API Shield discovery, managed operations, user schemas, and schema validation
- GraphQL analytics schema visibility and permission diagnostics
- Registrar registrations and zone nameserver posture
- WAF and bot-management coverage across all active zones
- SSL posture, waiting rooms, and Logpush permission diagnostics
- mTLS certificates, Secrets Store, VPC services, and Pipelines

The repo now also has an initial mutation layer for common write paths:

- generic JSON-backed Cloudflare API writes via `cf_api_apply.sh`
- DNS record create/update/delete/upsert
- Access app create/update/delete
- Access policy create/update/delete and reusable-policy promotion
- Turnstile widget create/update/delete and secret rotation
- Waiting room create/update/patch/delete
- Logpush create/update/delete and ownership validation helpers
- Tunnel create/update/configure/delete and connection cleanup

Treat the audit as the default answer to two different questions:

- "What Cloudflare is this account already using?"
- "Which Cloudflare surfaces are still empty, blocked by token scope, or not yet banked here?"
