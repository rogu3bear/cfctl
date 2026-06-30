# security.txt State

Cloudflare can serve a zone-managed `/.well-known/security.txt` from the
Security Center API. Use desired state when the zone has a proven public
security contact and you want the dashboard finding to be repeatably diffed
and previewed instead of hand-edited.

Example:

```json
{
  "match": {
    "zone": "example.com"
  },
  "body": {
    "enabled": true,
    "contact": ["mailto:security@example.com"],
    "canonical": ["https://example.com/.well-known/security.txt"],
    "preferred_languages": "en"
  }
}
```

Recommended match keys:
- `zone`

Use:

```bash
cfctl diff security.txt --zone example.com
cfctl apply security.txt sync --zone example.com --plan
cfctl apply security.txt sync --zone example.com --ack-plan <operation-id>
```

Managed specs:
- `adapteros-com.json`: AdapterOS public vulnerability contact.
- `mlnavigator-com.json`: MLNavigator public vulnerability contact.
