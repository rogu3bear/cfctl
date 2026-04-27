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
```

Important:

- Support means the desired-state engine exists for that surface.
- Managed specs are still opt-in; a supported surface may currently have zero checked-in specs.
- `sync` follows the same preview/ack flow as other writes.

Supported surfaces:
- `access.app`
- `access.policy`
- `dns.record`
- `tunnel`

State specs live under [state](state/README.md).

Rules:
- desired state is opt-in and surface-scoped
- `diff` shows managed specs and unmanaged actual resources
- `sync` only acts on registered desired-state surfaces
- delete syncs require explicit destructive confirmation
