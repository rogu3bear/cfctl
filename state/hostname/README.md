# hostname State

Hostname lifecycle specs are YAML because they describe one composite surface
rather than one Cloudflare API resource.

Example:

```yaml
zone: example.com
hosts:
  - app.example.com
dns:
  proxied_placeholder: true
worker:
  route: "*.example.com/*"
  service: example-edge-router
access:
  required: true
  audience: example-approved
certificate:
  advanced: true
storage:
  d1: example-db
  r2: example-objects
```

Use:

```bash
cfctl hostname verify --file state/hostname/example.yaml
cfctl hostname diff --file state/hostname/example.yaml
cfctl hostname plan --file state/hostname/example.yaml
```

`hostname apply` is intentionally blocked until every component mutation is
available as an individual preview-gated surface.
