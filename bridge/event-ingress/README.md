# cfctl event ingress bridge

This source is the minimal inbound RealtimeKit verification bridge used by
`cfctl events bridge inspect|prepare`. It verifies the `rtk-signature` against
the exact request bytes, carries `rtk-uuid` as the durable dedupe key, and
awaits the Queue write before returning success.

The placeholder Queue name is deliberate. Deploying the Worker, creating its
Queue, or registering a webhook remains a separately planned and approved
Cloudflare mutation through `cfctl`; this directory is not a direct Wrangler
deployment lane.

Use Bun for the local bridge proof:

```bash
bun install --frozen-lockfile
bun run check
```
