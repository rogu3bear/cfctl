# Desired State

Desired state in this repo is intentionally limited.

Primary purpose:
- capture repeatable intent for a few high-value Cloudflare surfaces
- diff desired vs actual with `./cfctl diff <surface>`
- reconcile with `./cfctl apply <surface> sync`
- verify composite hostname lifecycle specs with `./cfctl hostname verify`
- verify composite maildesk-cf lifecycle specs with `./cfctl maildesk-cf verify`
- verify composite public intake lifecycle specs with `./cfctl form-intake verify`

Current supported surfaces:
- `access.app`
- `access.policy`
- `dns.record`
- `zone.setting`
- `security.txt`
- `hostname` (verify/diff/plan only; composite apply is blocked)
- `maildesk-cf` (init/verify/snapshot/diff/plan/provision-plan only; composite provision apply is blocked)
- `form.intake` (init/verify/snapshot/diff/plan only; composite apply is absent)
- `tunnel`
- `ownership` (cross-surface owner/proof registry; exposed through `cfctl ownership list|get|check`)

Managed specs are opt-in. A generic surface being listed here means the engine
can diff and sync that surface, not that this repo already has checked-in specs
for it. `hostname`, `maildesk-cf`, and `form.intake` are exceptions: they are
composite lifecycle commands backed by state specs, and composite apply or
provision remains blocked or absent.

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
Cloudflare-managed `security.txt` specs live under `state/security.txt/` and
should cite the evidence for each public vulnerability contact.
Hostname lifecycle specs live under `state/hostname/` and verify the full
DNS/TLS/route/Access/Worker/storage path from one YAML document.
maildesk-cf lifecycle specs live under `state/maildesk-cf/` and verify Email
Routing aliases, Workers, D1, R2, Queues, sender authentication, and outbound
identity readiness from one JSON document.
form.intake lifecycle specs live under `state/form-intake/` and verify public
user-submission paths across source fields, Turnstile, Access posture, secret
bindings, Resend evidence, page render, and storage/log sinks from one JSON
document.

Ownership registry:
- `state/ownership/resources.json` maps cfctl-managed resource classes to one
  owner, deploy lane, secret source, allowed change command, verifier, proof
  class, and incident runbook.
- Use `cfctl ownership list`, `cfctl ownership get --resource-key <key>`, and
  `cfctl ownership check` as the public operator path. Do not scrape this file
  directly from app repos.
- Duplicate `resource_key` entries are invalid. If two systems claim authority
  over the same Cloudflare resource class, `./scripts/verify_static_contract.sh`
  fails before that drift becomes operating doctrine.
- The registry records control-plane authority. It does not replace live reads;
  live Cloudflare claims still require `cfctl list|get|snapshot|verify`.
