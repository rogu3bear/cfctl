# dns.record State

Example:

```json
{
  "match": {
    "zone": "example.com",
    "name": "_ops-smoke.example.com",
    "type": "TXT"
  },
  "body": {
    "name": "_ops-smoke.example.com",
    "type": "TXT",
    "content": "hello-world",
    "ttl": 120
  }
}
```

Recommended match keys:
- `zone`
- `id`
- `name` with `type`
