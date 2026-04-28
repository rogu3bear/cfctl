# Capabilities

_Generated from `catalog/surfaces.json` and `catalog/runtime.json`. Edit the catalogs, not this file._

`cfctl` currently exposes these Cloudflare surfaces as first-class runtime resources:

This table is the operable runtime surface. The standards layer and docs bank intentionally cover more Cloudflare territory than `cfctl` can currently mutate or verify directly.

| Surface | Read | Apply | Desired State | Standards | Docs Topics | Module |
| --- | --- | --- | --- | --- | --- | --- |
| `access.app` | yes | yes | yes | `access.app` | `zero-trust-api, api-auth` | `access_app` |
| `access.policy` | yes | yes | yes | `access.policy` | `zero-trust-api, api-auth` | `access_policy` |
| `d1.database` | yes | no | no | `-` | `-` | `-` |
| `dns.record` | yes | yes | yes | `dns.record` | `api-auth` | `dns_record` |
| `edge.certificate` | yes | yes | no | `edge.certificate` | `advanced-certificates, api-auth` | `edge_certificate` |
| `logpush.job` | yes | yes | no | `-` | `-` | `-` |
| `pages.project` | yes | no | no | `-` | `-` | `-` |
| `queue` | yes | no | no | `-` | `-` | `-` |
| `r2.bucket` | yes | no | no | `-` | `-` | `-` |
| `tunnel` | yes | yes | yes | `tunnel` | `api-auth` | `tunnel` |
| `turnstile.widget` | yes | yes | no | `-` | `-` | `-` |
| `waiting_room` | yes | yes | no | `-` | `-` | `-` |
| `worker.route` | yes | no | no | `worker.route` | `workers-routes, api-auth` | `worker_route` |
| `worker.script` | yes | no | no | `-` | `-` | `-` |
| `workflow` | yes | no | no | `-` | `-` | `-` |
| `zone` | yes | no | no | `-` | `-` | `-` |

Composite lifecycle commands:
- `cfctl hostname verify --file state/hostname/<name>.yaml`
- `cfctl hostname diff --file state/hostname/<name>.yaml`
- `cfctl hostname plan --file state/hostname/<name>.yaml`
- `cfctl hostname apply --file state/hostname/<name>.yaml` is intentionally blocked until component mutations are preview-gated.

Lane-aware commands:
- `cfctl doctor`
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
