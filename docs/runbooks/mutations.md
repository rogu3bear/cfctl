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
- `apply <surface> sync` is only supported for `access.app`, `access.policy`, `dns.record`, and `tunnel`.
- `cf_api_apply.sh` expects a fully expanded Cloudflare API path in `REQUEST_PATH` and `VERIFY_PATH`.
- `cf_api_apply.sh` is the backend escape hatch for API Shield, rate limits, Access policies, and other surfaces that do not yet have a dedicated wrapper.
