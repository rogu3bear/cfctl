# Permission Doctrine

This document is the operator-facing policy for `catalog/permissions.json`.
The catalog remains the executable source of truth; this doctrine defines the
review and operating rules that make the catalog safe to use in a shared
Cloudflare account.

## Sources

- Cloudflare API token permissions are resource-scoped into user, account, and
  zone categories, and Cloudflare recommends the permission-groups endpoint for
  the current permission IDs:
  <https://developers.cloudflare.com/fundamentals/api/reference/permissions/>.
- Cloudflare Audit Logs v2 is an account API endpoint that accepts
  `Account Settings Read` or `Account Settings Write` and supports bounded
  `since`, `before`, and `limit` queries:
  <https://developers.cloudflare.com/api/resources/accounts/subresources/logs/subresources/audit/methods/list/>.

## Local Live Contract

Remote CI is intentionally absent from this checkout. Live Cloudflare contract
checks are local operator smoke tests, run only from a prepared checkout with
explicit local credentials.

Required local environment inputs:

- `CFCTL_PUBLIC_CONTRACT_ACCOUNT_ID`: the account pinned on the selected
  profile.
- `CFCTL_PUBLIC_CONTRACT_PROFILE`: an already selected, credentialed profile
  with account-token administration permission.
- `CFCTL_PUBLIC_CONTRACT_PERMISSION_GROUP_ID`: a low-risk read permission from
  the live account permission-group inventory.
- `CFCTL_PUBLIC_CONTRACT_CONFIRM=mint-rotate-revoke-disposable-token`: explicit
  acknowledgement of the reviewed lifecycle smoke.

The smoke creates a one-hour, account-scoped token, writes its value only to a
mode-0600 temporary sink, rolls the value, revokes the token, and requires a
live not-found verification before success:

```bash
CFCTL_PUBLIC_CONTRACT_ACCOUNT_ID=<account-id> \
CFCTL_PUBLIC_CONTRACT_PROFILE=<selected-profile> \
CFCTL_PUBLIC_CONTRACT_PERMISSION_GROUP_ID=<read-permission-group-id> \
CFCTL_PUBLIC_CONTRACT_CONFIRM=mint-rotate-revoke-disposable-token \
./scripts/verify_public_contract.sh
```

Do not add hosted scheduled jobs or protected-environment live checks without
an explicit operator decision. Local smoke checks use normal cfctl profiles,
hash-bound plans, exact operation approval, secret sinks, and content-addressed
evidence.

## Bootstrap Creator

The bootstrap creator is temporary. It exists only to mint narrower operator
tokens and then must be revoked.

Allowed bootstrap creator permissions:

- `Account API Tokens Read`
- `Account API Tokens Write`
- `Account Settings Read`

The bootstrap creator must not be installed as `CF_DEV_TOKEN`, stored in hosted
CI, or reused for day-to-day operations.

Token-admin authority stays separate from the day-to-day lane. `CF_DEV_TOKEN`
should be able to run normal inventory, policy, Access, deploy, and intake
verification work without `Account API Tokens Write`. Token minting and
rotation use the bootstrap creator or an explicit token-admin procedure, then
return to the narrower operator token.

## Operator Profiles

Profile names are fixed by `catalog/permissions.json`:

- `read`: default inventory and audit profile, including `audit.log`.
- `dns`: DNS record read/write profile for preview-gated DNS work.
- `hostname`: composite hostname lifecycle profile for DNS, Access, routes,
  Worker, certificates, and zone-level TLS/HTTPS settings.
- `deploy`: Worker, Pages, D1, R2, Queues, route, and wrangler deploy profile.
- `form.intake` is covered by the read/deploy/security-audit allowlists as a
  composite verifier; its real changes still use component surfaces.
- `security-audit`: read-only API-security, Access, logging, and edge posture
  inventory profile.
- `full-operator`: broad local operator profile; use only when narrower
  profiles cannot complete the task.

Maximum TTLs are catalog-enforced:

- read profiles: 720 hours.
- write and broad-write profiles: 168 hours.

## Non-Negotiable Rules

- Operator profiles must not include `Account API Tokens *` permissions.
- Read-risk profiles must not include `* Write`, `* Revoke`, or `* Run`
  permissions.
- Any new permission added to a profile must fit that profile's
  `allowed_surfaces`.
- `Account Settings Read` is the coarse Cloudflare permission behind
  `doctor`, `lanes`, and `audit.log`; any profile carrying it must be reviewed
  as capable of account audit-log reads.
- A new profile requires docs, catalog entries, verifier coverage, and a clear
  owner/use case.
- `full-operator` is a break-glass profile. Prefer a narrower profile first,
  and document why the broad profile was required.
- Tokens must be delivered through `--value-out <absolute-path>` and never
  copied from stdout.
- Token minting, rotation, and revocation must create a plan, then use
  `cfctl plans approve <operation-id> --yes` and
  `cfctl plans run <operation-id>`.
- Live mutation evidence must include preview, apply, and verification
  artifacts when those paths exist.

## Review Checklist

Before merging permission or live-contract changes:

- `cargo xtask verify`
- `cfctl keys permissions --account <account-id> --json`
- Optional local live-contract smoke with the four explicit
  `CFCTL_PUBLIC_CONTRACT_*` inputs documented above.
