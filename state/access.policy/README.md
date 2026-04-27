# access.policy State

Example:

```json
{
  "match": {
    "app_id": "81f1c301-81ef-4bb2-a562-b4eab9e92b29",
    "name": "Allow Example"
  },
  "body": {
    "name": "Allow Example",
    "decision": "allow",
    "include": [
      {
        "email_domain": {
          "domain": "example.com"
        }
      }
    ],
    "exclude": [],
    "require": []
  }
}
```

Recommended match keys:
- `app_id` with `name`
- `policy_id`
