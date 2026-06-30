# State

Desired state is intentionally selective.

Use it when:
- a Cloudflare surface drifts repeatedly
- the desired shape is stable enough to encode
- you want `diff` and `sync` semantics instead of one-off edits

Commands:

```bash
cfctl diff dns.record --zone example.com
cfctl apply dns.record sync --zone example.com --plan
cfctl apply dns.record sync --zone example.com --ack-plan <operation-id>
cfctl diff zone.setting --zone example.com
cfctl apply zone.setting sync --zone example.com --plan
cfctl apply zone.setting sync --zone example.com --ack-plan <operation-id>
cfctl diff security.txt --zone example.com
cfctl apply security.txt sync --zone example.com --plan
cfctl apply security.txt sync --zone example.com --ack-plan <operation-id>
```

Important:

- Support means the desired-state engine exists for that surface.
- Managed specs are still opt-in; a supported surface may currently have zero checked-in specs.
- `sync` follows the same preview/ack flow as other writes.
- `hostname` is a composite lifecycle command, not a generic resource surface.
- `maildesk-cf` is a composite lifecycle command, not a generic resource surface.

Supported surfaces:
- `access.app`
- `access.policy`
- `dns.record`
- `zone.setting`
- `security.txt`
- `hostname` (verify/diff/plan only)
- `maildesk-cf` (init/verify/snapshot/diff/plan/provision-plan only)
- `tunnel`

State specs live under [state](state/README.md).

Rules:
- desired state is opt-in and surface-scoped
- `diff` shows managed specs and unmanaged actual resources
- `sync` only acts on registered desired-state surfaces
- delete syncs require explicit destructive confirmation
- hostname lifecycle specs are YAML under `state/hostname/` and composite apply is blocked until component mutations are preview-gated
- maildesk-cf lifecycle specs are JSON under `state/maildesk-cf/` and composite provision apply is blocked until component mutations are preview-gated
