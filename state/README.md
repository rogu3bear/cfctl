# Desired State

Desired state in this repo is intentionally limited.

Primary purpose:
- capture repeatable intent for a few high-value Cloudflare surfaces
- diff desired vs actual with `./cfctl diff <surface>`
- reconcile with `./cfctl apply <surface> sync`

Current supported surfaces:
- `access.app`
- `access.policy`
- `dns.record`
- `tunnel`

Managed specs are opt-in. A surface being listed here means the engine can diff
and sync that surface, not that this repo already has checked-in specs for it.

General spec shape:

```json
{
  "match": {
    "name": "example"
  },
  "body": {
    "name": "example"
  },
  "delete": false
}
```

Rules:
- `match` is required.
- `body` is required unless `delete` is `true`.
- `delete: true` requests deletion of the matched resource and requires `--confirm delete` during sync.
- Only the keys present in `body` are compared for drift.

Surface-specific examples live under the per-surface directories.
