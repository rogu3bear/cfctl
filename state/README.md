# Desired State

Desired state in this repo is intentionally limited.

Primary purpose:
- capture repeatable intent for a few high-value Cloudflare surfaces
- diff desired vs actual with `./cfctl diff <surface>`
- reconcile with `./cfctl apply <surface> sync`
- verify composite hostname lifecycle specs with `./cfctl hostname verify`

Current supported surfaces:
- `access.app`
- `access.policy`
- `dns.record`
- `hostname` (verify/diff/plan only; composite apply is blocked)
- `tunnel`
- `ownership` (cross-surface owner/proof registry; verified by the static contract)

Managed specs are opt-in. A generic surface being listed here means the engine
can diff and sync that surface, not that this repo already has checked-in specs
for it. `hostname` is the exception: it is a composite lifecycle command backed
by YAML specs, and composite apply is blocked.

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
Hostname lifecycle specs live under `state/hostname/` and verify the full
DNS/TLS/route/Access/Worker/storage path from one YAML document.

Ownership registry:
- `state/ownership/resources.json` maps cfctl-managed resource classes to one
  owner, deploy lane, secret source, allowed change command, verifier, proof
  class, and incident runbook.
- Duplicate `resource_key` entries are invalid. If two systems claim authority
  over the same Cloudflare resource class, `./scripts/verify_static_contract.sh`
  fails before that drift becomes operating doctrine.
- The registry records control-plane authority. It does not replace live reads;
  live Cloudflare claims still require `cfctl list|get|snapshot|verify`.
