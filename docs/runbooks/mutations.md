# Mutations

Mutation workflows in this repo are `cfctl`-first.

Runtime defaults:
- mutation backends are backend-only; use `cfctl`
- `--plan` produces the reviewed preview
- the real mutation requires `--ack-plan <operation-id>` from that preview
- successful writes do follow-up verification when a stable readback path exists
- every run writes a structured runtime artifact under `var/inventory/runtime/`
- backend mutation scripts also write redacted operation artifacts under `var/inventory/operations/`
- destructive actions require explicit confirmation such as `--confirm delete`

## Public Interface

For most live operations, use `cfctl`:

```bash
cfctl can access.app update
cfctl classify access.app update
cfctl apply access.app update --id <app-id> --body-file app.json --plan
cfctl apply access.policy create --app-id <app-id> --body-file policy.json --plan
CF_TOKEN_LANE=global cfctl apply access.login_method set --provider-type onetimepin --plan
cfctl apply tunnel create --body '{"name":"example","config_src":"cloudflare"}' --plan
CF_TOKEN_LANE=global cfctl apply dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120 --plan
CF_TOKEN_LANE=global cfctl apply dns.record sync --zone example.com --plan
CF_TOKEN_LANE=global cfctl apply dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120 --ack-plan <operation-id>
CF_TOKEN_LANE=global cfctl apply edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --validation-method txt --certificate-authority lets_encrypt --validity-days 90 --plan
```

Advanced Certificate Manager public flow:

```bash
cfctl standards edge.certificate
cfctl explain edge.certificate
cfctl guide edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com
cfctl list edge.certificate --zone example.com
CF_TOKEN_LANE=global cfctl can edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --all-lanes
CF_TOKEN_LANE=global cfctl apply edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --validation-method txt --certificate-authority lets_encrypt --validity-days 90 --plan
CF_TOKEN_LANE=global cfctl apply edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --ack-plan <operation-id>
CF_TOKEN_LANE=global cfctl verify edge.certificate --zone example.com --host app.example.com --host deep.app.example.com
```

Use repeated `--host` flags for each certificate hostname. The runtime adds the zone apex automatically, then submits an Advanced Certificate Manager `type=advanced` certificate-pack order.

The script-level wrappers below remain the backend contract, but mutation backends are backend-only and require `cfctl admin authorize-backend` plus `CF_BACKEND_BYPASS_FILE=<authorization-path>` for direct maintainer/debug use.

Access login-method reconciliation pins targeted apps to exactly one existing identity provider. It never creates, deletes, or mutates identity providers.

```bash
cfctl list access.login_method
cfctl guide access.login_method set --provider-type onetimepin
CF_TOKEN_LANE=global cfctl apply access.login_method set --provider-type onetimepin --plan
CF_TOKEN_LANE=global cfctl apply access.login_method set --provider-id <provider-id> --ack-plan <operation-id>
```

Add `--id`, `--name`, or `--domain` to narrow the app target. Without an app selector, the target is all Access applications.

Beyond single-provider pinning, login methods support explicit multi-IdP sets
and per-app union/subtraction:

```bash
cfctl apply access.login_method set-list --provider-id <id-a> --provider-id <id-b> --domain docs.example.org --plan
cfctl apply access.login_method add --provider-type onetimepin --domain docs.example.org --plan
cfctl apply access.login_method remove --provider-type onetimepin --domain docs.example.org --plan
```

`add` and `remove` compute each app's desired set from its current
`allowed_idps` (idempotent noops included). Any change that would leave an
app's `allowed_idps` empty is refused — empty means every login method is
allowed — so removing the last provider requires an explicit `set`/`set-list`
decision instead.

When `cfctl audit access` flags `otp_only_where_intended`, first separate true
external-counterparty OTP portals from operator, staff, service-token-only,
deny-only, launcher, and WARP surfaces. Only record a `state/access.app` OTP
intent for a real external counterparty portal whose users cannot join the
private IdP. An OTP intent is a spec whose `match.domain` targets the app and
whose `body.allowed_idps` lists the onetimepin provider id; the `intent` block
records the justifying classification and rationale, and
`state/access.app/README.md` owns the spec-side policy for which surfaces may
carry one. For the remaining operator surfaces, prepare a targeted GitHub IdP
preview instead of adding an OTP exception:

```bash
cfctl list access.idp
CF_TOKEN_LANE=global cfctl apply access.login_method set --provider-id <github-provider-id> --domain <app-domain> --plan
```

Use one app selector per preview. The preview preserves the app body and policy
shape while changing `allowed_idps`; after review, apply with the emitted
`operation_id` and verify with `cfctl audit access` plus a targeted
`cfctl list access.login_method --domain <app-domain>` readback.

If the target app is managed by a `state/access.app` spec, an
`access.login_method` change to `allowed_idps` is silently reverted by the next
`cfctl apply access.app sync` — sync rebuilds the live app from the spec's
`body` alone. For a spec-managed app, update the spec's `body.allowed_idps`
(and sync) instead of, or alongside, `login_method set`.

`cfctl audit access` also runs `otp_intent_specs_justified`: any
`state/access.app` spec that grants the onetimepin provider id without a
justified `intent.classification` (`authenticated_counterparty_portal` or
`intentional_public_carveout`) is reported as a spec-level offender
`{domain, classification}` — for example `operator_pending_idp_migration`
stays flagged until the surface migrates off OTP. The
`otp_only_where_intended` offender rows also carry `app_launcher_visible`,
`auto_redirect_to_identity`, and `has_allow_policy`, so triage reads
operator-vs-portal posture straight off the row.

Identity-provider lifecycle itself lives on `access.idp`. Creating or deleting
the `onetimepin` provider is the account-wide OTP login-method toggle;
creating it when it already exists is a noop, and delete is destructive:

```bash
cfctl list access.idp
cfctl get access.idp --type onetimepin
cfctl apply access.idp create --type onetimepin --plan
cfctl apply access.idp create --type onetimepin --ack-plan <operation-id>
cfctl apply access.idp delete --type onetimepin --confirm delete --plan
cfctl apply access.idp delete --type onetimepin --confirm delete --ack-plan <operation-id>
```

Only `onetimepin` gets a synthesized create body. Every other provider type
requires an explicit `--body`/`--body-file` (including `update`): the live GET
omits provider config secrets, so cfctl refuses to build read-modify-write
bodies that would blank them. Secret-like config values are redacted before
any body reaches a plan artifact.

Access groups are body-driven CRUD, and the Zero Trust organization singleton
takes field-scoped writes that merge onto live state (never a blind PUT):

```bash
cfctl list access.group
cfctl apply access.group create --body-file group.json --plan
cfctl apply access.group update --id <group-id> --body-file group.json --plan
cfctl apply access.group delete --id <group-id> --confirm delete --plan
cfctl get access.organization
cfctl apply access.organization set-session-duration --content 24h --plan
cfctl apply access.organization set-ui-read-only --content true --plan
cfctl apply access.organization update --body '{"login_design":{"header_text":"Ops"}}' --plan
```

Organization writes read the live org object first, merge the requested
change, strip read-only timestamps, plan a noop when nothing differs, and
verify changed fields by readback after apply.

Example authorization flow:

```bash
AUTH_PATH="$(cfctl admin authorize-backend --backend scripts/cf_api_apply.sh --reason 'maintainer debug' | jq -r '.result.authorization_path')"
```

## Generic JSON Apply

Use [cf_api_apply.sh](scripts/cf_api_apply.sh) only for maintainer/debug work when the repo does not yet have a dedicated wrapper for the target surface.

```bash
CF_BACKEND_BYPASS_FILE=/absolute/path/to/backend-bypass.json \
REQUEST_METHOD=PATCH \
REQUEST_PATH=/accounts/<account-id>/access/apps/<app-id> \
VERIFY_PATH=/accounts/<account-id>/access/apps/<app-id> \
BODY_JSON='{"session_duration":"24h"}' \
./scripts/cf_api_apply.sh
```

## Dedicated Wrappers

DNS upsert:

```bash
CF_BACKEND_BYPASS_FILE=/absolute/path/to/backend-bypass.json \
ZONE_NAME=example.com \
RECORD_TYPE=TXT \
RECORD_NAME=_ops.example.com \
RECORD_CONTENT='hello-world' \
TTL=120 \
./scripts/cf_mutate_dns_record.sh
```

Access app update:

```bash
CF_BACKEND_BYPASS_FILE=/absolute/path/to/backend-bypass.json \
APP_ID=<access-app-id> \
OPERATION=update \
BODY_JSON='{"session_duration":"24h"}' \
./scripts/cf_mutate_access_app.sh
```

Access policy create:

```bash
CF_BACKEND_BYPASS_FILE=/absolute/path/to/backend-bypass.json \
APP_ID=<access-app-id> \
OPERATION=create \
BODY_JSON='{"name":"Allow Example","decision":"allow","include":[{"email_domain":{"domain":"example.com"}}],"exclude":[],"require":[]}' \
./scripts/cf_mutate_access_policy.sh
```

Access login-method set:

```bash
CF_BACKEND_BYPASS_FILE=/absolute/path/to/backend-bypass.json \
OPERATION=set \
PROVIDER_TYPE=onetimepin \
./scripts/cf_mutate_access_login_method.sh
```

Turnstile widget update:

```bash
CF_BACKEND_BYPASS_FILE=/absolute/path/to/backend-bypass.json \
SITEKEY=<sitekey> \
OPERATION=update \
BODY_JSON='{"name":"Example Widget","mode":"managed","domains":["example.com"]}' \
./scripts/cf_mutate_turnstile_widget.sh
```

Waiting room patch:

```bash
CF_BACKEND_BYPASS_FILE=/absolute/path/to/backend-bypass.json \
ZONE_NAME=example.com \
WAITING_ROOM_ID=<waiting-room-id> \
OPERATION=patch \
BODY_JSON='{"suspended":true}' \
./scripts/cf_mutate_waiting_room.sh
```

Advanced Certificate Manager edge certificate order:

```bash
CF_BACKEND_BYPASS_FILE=/absolute/path/to/backend-bypass.json \
ZONE_NAME=example.com \
OPERATION=order \
HOSTS_JSON='["app.example.com","deep.app.example.com"]' \
VALIDATION_METHOD=txt \
CERTIFICATE_AUTHORITY=lets_encrypt \
VALIDITY_DAYS=90 \
./scripts/cf_mutate_edge_certificate.sh
```

Logpush job update:

```bash
CF_BACKEND_BYPASS_FILE=/absolute/path/to/backend-bypass.json \
SCOPE_KIND=account \
JOB_ID=<job-id> \
OPERATION=update \
BODY_JSON='{"enabled":true,"name":"account-logpush"}' \
./scripts/cf_mutate_logpush_job.sh
```

Tunnel create:

```bash
CF_BACKEND_BYPASS_FILE=/absolute/path/to/backend-bypass.json \
OPERATION=create \
BODY_JSON='{"name":"example-tunnel","config_src":"cloudflare"}' \
./scripts/cf_mutate_tunnel.sh
```

## Notes

- With the default `CF_DEV_TOKEN`, DNS dry runs may still be unable to pre-resolve an existing record id.
- If a write is blocked on the primary lane, retry the same command with `CF_TOKEN_LANE=global`.
- `apply <surface> sync` is only supported for `access.app`, `access.policy`, `dns.record`, `zone.setting`, `security.txt`, and `tunnel`.
- `cf_api_apply.sh` expects a fully expanded Cloudflare API path in `REQUEST_PATH` and `VERIFY_PATH`.
- `cf_api_apply.sh` is the backend escape hatch for API Shield, rate limits, Access policies, and other surfaces that do not yet have a dedicated wrapper.
