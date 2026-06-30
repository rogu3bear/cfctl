# access.app State

Example:

```json
{
  "match": {
    "domain": "docs.example.org"
  },
  "body": {
    "name": "Docs",
    "domain": "docs.example.org",
    "type": "self_hosted",
    "session_duration": "24h"
  }
}
```

Recommended match keys:
- `domain`
- `id`
- `name`

Managed specs:
- `beta-adapteros.json`: adapterOS beta Access app.
- `ops-adapteros.json`: adapterOS ops Access app.
- `founder-public-surveys.json`: intentional public survey-read carve-out under the Access-protected founder host.
- `mlnavigator-survey-retire.json`: retirement plan for the deprecated legacy survey Pages custom domain.
