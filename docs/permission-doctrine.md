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
- GitHub Actions environment secrets and protection rules gate a job before it
  can access environment secrets:
  <https://docs.github.com/en/actions/concepts/workflows-and-actions/deployment-environments>.
- GitHub Actions required reviewers can block protected-environment jobs until
  an allowed reviewer approves them:
  <https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#required-reviewers>.

## Live Contract Environment

The live Cloudflare contract job must run in the `cfctl-live` GitHub Actions
environment. Configure that environment with required reviewers and store the
live contract credentials there, not as broadly accessible repository secrets.

Required environment secrets and variables:

- `CF_DEV_TOKEN`: a scoped day-to-day operator token, not the bootstrap creator.
- `CLOUDFLARE_ACCOUNT_ID`: the account pinned for live contract verification.
- `CFCTL_PUBLIC_CONTRACT_ZONE`: a disposable zone or zone name used only for
  contract smoke tests.

The live job is intentionally not run on pull requests. It runs on
`workflow_dispatch` and the scheduled contract lane after the protected
environment releases the job.

## Bootstrap Creator

The bootstrap creator is temporary. It exists only to mint narrower operator
tokens and then must be revoked.

Allowed bootstrap creator permissions:

- `Account API Tokens Read`
- `Account API Tokens Write`
- `Account Settings Read`

The bootstrap creator must not be installed as `CF_DEV_TOKEN`, stored in GitHub
Actions, or reused for day-to-day operations.

## Operator Profiles

Profile names are fixed by `catalog/permissions.json`:

- `read`: default inventory and audit profile, including `audit.log`.
- `dns`: DNS record read/write profile for preview-gated DNS work.
- `hostname`: composite hostname lifecycle profile for DNS, Access, routes,
  Worker, and certificate work.
- `deploy`: Worker, Pages, D1, R2, Queues, route, and wrangler deploy profile.
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
- Token minting must use `--plan`, then `--ack-plan <operation-id>`.
- Live mutation evidence must include preview, apply, and verification
  artifacts when those paths exist.

## Review Checklist

Before merging permission or live-contract changes:

- `./scripts/verify_static_contract.sh`
- `python3 scripts/verify_permission_catalog.py`
- `python3 scripts/verify_permission_catalog.py --cfctl ./cfctl`
- `python3 scripts/verify_permission_catalog.py --permission-groups <live-artifact>`
- Manual `cfctl contract` workflow dispatch against the `cfctl-live`
  environment after secrets are configured.
