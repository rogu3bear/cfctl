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
- `mlnavigator-advisor-portal.json`: OTP is intentional for external advisor access.
- `mlnavigator-founder-portal.json`: OTP is intentional for external founder access.
- `mlnavigator-investor-portal.json`: OTP is intentional for external investor access.
- `mlnavigator-survey-retire.json`: retirement plan for the deprecated legacy survey Pages custom domain.

Do not add `state/access.app` OTP specs merely to quiet `cfctl audit access`.
Operator, staff, service-token-only, deny-only, launcher, and WARP surfaces
should stay offenders until a preview-gated `access.login_method` or Access app
fix moves them to the correct IdP/posture.
