# maildesk-cf State

`maildesk-cf` specs describe the Cloudflare account resources needed for one
maildesk deployment: Email Routing aliases, Workers, D1, R2, Queues, sender
authentication, and outbound identity readiness.

Use the composite command when the question is deployment readiness rather than
one isolated Cloudflare resource:

```bash
cfctl maildesk-cf verify --file state/maildesk-cf/example.json
cfctl maildesk-cf snapshot --file state/maildesk-cf/example.json
cfctl maildesk-cf diff --file state/maildesk-cf/example.json
cfctl maildesk-cf provision --file state/maildesk-cf/example.json --plan
```

`maildesk-cf provision --plan` emits proposed component operations and an
operation id. `maildesk-cf provision --ack-plan <operation-id>` is intentionally
blocked until the component write paths are each preview-gated through public
`cfctl` surfaces.

The verifier does not perform broad live sends. Sender readiness is based on
DNS/authentication and provider readback evidence; targeted send proof remains
an explicit human-requested check.
