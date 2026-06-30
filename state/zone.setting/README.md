# zone.setting State

Zone settings are high-blast-radius edge posture. Use desired state for owned
TLS, HTTPS, HSTS, and transport baselines that should be diffed and previewed
repeatably instead of hand-edited in the dashboard.

Example:

```json
{
  "match": {
    "zone": "example.com",
    "name": "ssl"
  },
  "body": {
    "value": "strict"
  }
}
```

Recommended match keys:
- `zone`
- `name`

Use:

```bash
cfctl diff zone.setting --zone example.com
cfctl apply zone.setting sync --zone example.com --plan
cfctl apply zone.setting sync --zone example.com --ack-plan <operation-id>
```
