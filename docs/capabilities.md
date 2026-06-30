# Capabilities

_Generated from `catalog/surfaces.json` and `catalog/runtime.json`. Edit the catalogs, not this file._

`cfctl` currently exposes these Cloudflare surfaces as first-class runtime resources:

This table is the operable runtime surface. The standards layer and docs bank intentionally cover more Cloudflare territory than `cfctl` can currently mutate or verify directly.

| Surface | Read | Can | Apply | Verify | Desired State | Standards | Docs Topics | Module |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `access.app` | yes | yes | yes | yes | yes | `access.app` | `zero-trust-api, api-auth` | `access_app` |
| `access.login_method` | yes | yes | yes | yes | no | `access.login_method` | `zero-trust-api, api-auth` | `access_login_method` |
| `access.policy` | yes | yes | yes | yes | yes | `access.policy` | `zero-trust-api, api-auth` | `access_policy` |
| `access.service_token` | yes | yes | yes | yes | no | `-` | `-` | `-` |
| `api_gateway.discovery` | yes | yes | no | yes | no | `-` | `api-gateway, api-auth` | `-` |
| `api_gateway.operation` | yes | yes | no | yes | no | `-` | `api-gateway, api-auth` | `-` |
| `api_gateway.schema` | yes | yes | no | yes | no | `-` | `api-gateway, api-auth` | `-` |
| `audit.log` | yes | yes | no | yes | no | `-` | `audit-logs, api-auth` | `-` |
| `d1.database` | yes | yes | no | yes | no | `-` | `-` | `-` |
| `dns.record` | yes | yes | yes | yes | yes | `dns.record` | `api-auth` | `dns_record` |
| `edge.certificate` | yes | yes | yes | yes | no | `edge.certificate` | `advanced-certificates, api-auth` | `edge_certificate` |
| `email.routing_rule` | yes | yes | yes | yes | no | `-` | `email-routing, api-auth` | `-` |
| `logpush.job` | yes | yes | yes | yes | no | `-` | `-` | `-` |
| `maildesk-cf` | no | no | no | no | yes | `maildesk-cf` | `email-routing, email-workers, d1, r2, queues, api-auth` | `-` |
| `pages.project` | yes | yes | no | yes | no | `-` | `-` | `-` |
| `pages.secret` | yes | yes | yes | yes | no | `-` | `-` | `-` |
| `queue` | yes | yes | no | yes | no | `-` | `-` | `-` |
| `r2.bucket` | yes | yes | no | yes | no | `-` | `-` | `-` |
| `security.txt` | yes | yes | yes | yes | yes | `security.txt` | `security-center-securitytxt, api-auth` | `security_txt` |
| `tunnel` | yes | yes | yes | yes | yes | `tunnel` | `api-auth` | `tunnel` |
| `turnstile.widget` | yes | yes | yes | yes | no | `-` | `-` | `-` |
| `vulnerability_scanner.credential_set` | yes | yes | no | yes | no | `-` | `api-shield-vulnerability-scanner, api-auth` | `-` |
| `vulnerability_scanner.scan` | yes | yes | no | yes | no | `-` | `api-shield-vulnerability-scanner, api-auth` | `-` |
| `vulnerability_scanner.target_environment` | yes | yes | no | yes | no | `-` | `api-shield-vulnerability-scanner, api-auth` | `-` |
| `waiting_room` | yes | yes | yes | yes | no | `-` | `-` | `-` |
| `worker.route` | yes | yes | yes | yes | no | `worker.route` | `workers-routes, api-auth` | `worker_route` |
| `worker.script` | yes | yes | yes | yes | no | `-` | `-` | `worker_script` |
| `worker.secret` | yes | yes | yes | yes | no | `-` | `-` | `worker_secret` |
| `workflow` | yes | yes | no | yes | no | `-` | `-` | `-` |
| `zone` | yes | yes | no | yes | no | `-` | `-` | `-` |
| `zone.ruleset` | yes | yes | yes | yes | no | `-` | `ruleset-engine, api-auth` | `-` |
| `zone.setting` | yes | yes | yes | yes | yes | `zone.setting` | `ssl-tls, api-auth` | `zone_setting` |

## Operation Contract Matrix

This matrix is derived from the same catalogs used by `cfctl explain`, `cfctl classify`, `cfctl guide`, and the static verifier. It is the preflight view for deciding whether a surface is read-only, preview-gated, destructive, lane-sensitive, or desired-state-backed.

| Surface | Operation | Risk | Preview | Lock | Verify After Apply | Confirmation | Allowed Lanes | Selectors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `access.app` | `create` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | - |
| `access.app` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: id |
| `access.app` | `update` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: id |
| `access.app` | `sync` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | state match: id, name, domain |
| `access.login_method` | `set` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | one of: provider_id / provider_type / provider_name |
| `access.policy` | `create` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: app_id |
| `access.policy` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: app_id, policy_id |
| `access.policy` | `make-reusable` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: app_id, policy_id |
| `access.policy` | `update` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: app_id, policy_id |
| `access.policy` | `sync` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | state match: app_id, policy_id, name |
| `access.service_token` | `create` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: name |
| `access.service_token` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: id |
| `dns.record` | `create` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: zone, name, type |
| `dns.record` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: zone; one of: id / name, type |
| `dns.record` | `update` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: zone; one of: id / name, type |
| `dns.record` | `upsert` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: zone, name, type |
| `dns.record` | `sync` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | state match: zone, id, name, type |
| `edge.certificate` | `order` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: zone |
| `email.routing_rule` | `upsert` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: zone, name, service |
| `logpush.job` | `create` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | - |
| `logpush.job` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: id |
| `logpush.job` | `ownership` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | - |
| `logpush.job` | `update` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: id |
| `logpush.job` | `validate-destination` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | - |
| `logpush.job` | `validate-origin` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | - |
| `logpush.job` | `validate-ownership` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | - |
| `pages.secret` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: project, name |
| `pages.secret` | `upsert` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: project, name |
| `security.txt` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: zone |
| `security.txt` | `upsert` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: zone |
| `security.txt` | `sync` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | state match: zone |
| `tunnel` | `cleanup-connections` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: id |
| `tunnel` | `configure` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: id |
| `tunnel` | `create` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | - |
| `tunnel` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: id |
| `tunnel` | `update` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: id |
| `tunnel` | `sync` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | state match: id, name |
| `turnstile.widget` | `create` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | - |
| `turnstile.widget` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: sitekey |
| `turnstile.widget` | `rotate-secret` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: sitekey |
| `turnstile.widget` | `update` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: sitekey |
| `waiting_room` | `create` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: zone |
| `waiting_room` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: zone, id |
| `waiting_room` | `patch` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: zone, id |
| `waiting_room` | `update` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: zone, id |
| `worker.route` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: zone; one of: id / pattern |
| `worker.script` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: name |
| `worker.script` | `upsert` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: name, metadata, module |
| `worker.secret` | `delete` | `destructive` | yes | `lease` | yes | `delete` | `dev`, `global` | required: script, name |
| `worker.secret` | `upsert` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: script, name |
| `zone.ruleset` | `update` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: zone, id |
| `zone.setting` | `set` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | required: zone, name |
| `zone.setting` | `sync` | `write` | yes | `apply` | yes | `-` | `dev`, `global` | state match: zone, id, name |

## Read-Only Surfaces

These surfaces are first-class read surfaces but do not expose `apply` or desired-state `sync` today. Mutation should not be inferred from an inventory script alone.

| Surface | Public Actions | List Selectors | Inventory Backend |
| --- | --- | --- | --- |
| `api_gateway.discovery` | `list`, `get`, `verify`, `can` | required: zone | `scripts/cf_inventory_api_gateway.sh` |
| `api_gateway.operation` | `list`, `get`, `verify`, `can` | required: zone | `scripts/cf_inventory_api_gateway.sh` |
| `api_gateway.schema` | `list`, `get`, `verify`, `can` | required: zone | `scripts/cf_inventory_api_gateway.sh` |
| `audit.log` | `list`, `get`, `verify`, `can` | - | `scripts/cf_inventory_audit_logs.sh` |
| `d1.database` | `list`, `get`, `verify`, `can` | - | `scripts/cf_inventory_d1.sh` |
| `pages.project` | `list`, `get`, `verify`, `can` | - | `scripts/cf_inventory_pages.sh` |
| `queue` | `list`, `get`, `verify`, `can` | - | `scripts/cf_inventory_queues.sh` |
| `r2.bucket` | `list`, `get`, `verify`, `can` | - | `scripts/cf_inventory_r2.sh` |
| `vulnerability_scanner.credential_set` | `list`, `get`, `verify`, `can` | - | `scripts/cf_inventory_vulnerability_scanner.sh` |
| `vulnerability_scanner.scan` | `list`, `get`, `verify`, `can` | - | `scripts/cf_inventory_vulnerability_scanner.sh` |
| `vulnerability_scanner.target_environment` | `list`, `get`, `verify`, `can` | - | `scripts/cf_inventory_vulnerability_scanner.sh` |
| `workflow` | `list`, `get`, `verify`, `can` | - | `scripts/cf_inventory_workflows.sh` |
| `zone` | `list`, `get`, `verify`, `can` | - | `scripts/cf_inventory_zones.sh` |

Composite lifecycle commands:
- `cfctl hostname verify --file state/hostname/<name>.yaml`
- `cfctl hostname diff --file state/hostname/<name>.yaml`
- `cfctl hostname plan --file state/hostname/<name>.yaml`
- `cfctl hostname apply --file state/hostname/<name>.yaml` is intentionally blocked until component mutations are preview-gated.
- `cfctl maildesk-cf init --domain example.com` emits a starter desired-state template without mutating Cloudflare.
- `cfctl maildesk-cf verify --file state/maildesk-cf/<name>.json`
- `cfctl maildesk-cf snapshot --file state/maildesk-cf/<name>.json`
- `cfctl maildesk-cf diff --file state/maildesk-cf/<name>.json`
- `cfctl maildesk-cf provision --file state/maildesk-cf/<name>.json --plan` emits a preview operation id and proposed component operations.
- `cfctl maildesk-cf provision --file state/maildesk-cf/<name>.json --ack-plan <operation-id>` is intentionally blocked until component mutations are preview-gated.

Ownership authority commands:
- `cfctl ownership list`
- `cfctl ownership get --resource-key cloudflare:dns.record:*`
- `cfctl ownership check`

Lane-aware commands:
- `cfctl doctor`
- `cfctl bootstrap permissions`
- `cfctl lanes`
- `cfctl can <surface> <operation> --all-lanes`
- `cfctl classify <surface> <operation>`
- `cfctl guide <surface> <operation>`

State-aware commands:
- `cfctl diff <surface>`
- `cfctl apply <surface> sync --plan`
- `cfctl apply <surface> sync --ack-plan <operation-id>`

Use `cfctl explain <surface>` for the live contract of a specific surface, including selectors, supported apply operations, module bindings, standards refs, docs topics, and current permission truth.
Use `cfctl classify <surface> <operation>` to see whether the operation requires preview, confirmation, or a different auth lane.
