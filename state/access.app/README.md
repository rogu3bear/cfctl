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
