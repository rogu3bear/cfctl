#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "probe-token-permissions" "build"

ZONE_NAME="${ZONE_NAME:-example.com}"
ZONE_ID="$(cf_resolve_zone_id "${ZONE_NAME}")"

if [[ -z "${ZONE_ID}" || "${ZONE_ID}" == "null" ]]; then
  echo "Unable to resolve zone id for ${ZONE_NAME}" >&2
  exit 1
fi

ENDPOINTS_JSON="$(jq -n \
  --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" \
  --arg zone_id "${ZONE_ID}" \
  --arg zone_name "${ZONE_NAME}" \
  '
    [
      {label:"auth.account_verify", method:"GET", path:("/accounts/" + $account_id + "/tokens/verify")},
      {label:"access.apps", method:"GET", path:("/accounts/" + $account_id + "/access/apps")},
      {label:"access.identity_providers", method:"GET", path:("/accounts/" + $account_id + "/access/identity_providers")},
      {label:"access.service_tokens", method:"GET", path:("/accounts/" + $account_id + "/access/service_tokens")},
      {label:"gateway.rules", method:"GET", path:("/accounts/" + $account_id + "/gateway/rules")},
      {label:"turnstile.widgets", method:"GET", path:("/accounts/" + $account_id + "/challenges/widgets")},
      {label:"load_balancers", method:"GET", path:("/accounts/" + $account_id + "/load_balancers")},
      {label:"load_balancer.pools", method:"GET", path:("/accounts/" + $account_id + "/load_balancers/pools")},
      {label:"pages.projects", method:"GET", path:("/accounts/" + $account_id + "/pages/projects")},
      {label:"queues", method:"GET", path:("/accounts/" + $account_id + "/queues")},
      {label:"workflows", method:"GET", path:("/accounts/" + $account_id + "/workflows?per_page=100")},
      {label:"hyperdrive", method:"GET", path:("/accounts/" + $account_id + "/hyperdrive/configs")},
      {label:"vectorize", method:"GET", path:("/accounts/" + $account_id + "/vectorize/v2/indexes")},
      {label:"ai_gateway", method:"GET", path:("/accounts/" + $account_id + "/ai-gateway/gateways")},
      {label:"zone.dns_records." + $zone_name, method:"GET", path:("/zones/" + $zone_id + "/dns_records?per_page=100")},
      {label:"zone.email_routing." + $zone_name, method:"GET", path:("/zones/" + $zone_id + "/email/routing")},
      {label:"zone.email_routing_rules." + $zone_name, method:"GET", path:("/zones/" + $zone_id + "/email/routing/rules")},
      {label:"zone.rulesets." + $zone_name, method:"GET", path:("/zones/" + $zone_id + "/rulesets")},
      {label:"zone.firewall_access_rules." + $zone_name, method:"GET", path:("/zones/" + $zone_id + "/firewall/access_rules/rules")},
      {label:"zone.rate_limits." + $zone_name, method:"GET", path:("/zones/" + $zone_id + "/rate_limits")},
      {label:"zone.waiting_rooms." + $zone_name, method:"GET", path:("/zones/" + $zone_id + "/waiting_rooms")},
      {label:"account.logpush_jobs", method:"GET", path:("/accounts/" + $account_id + "/logpush/jobs")},
      {label:"zone.logpush_jobs." + $zone_name, method:"GET", path:("/zones/" + $zone_id + "/logpush/jobs")},
      {label:"zone.ssl." + $zone_name, method:"GET", path:("/zones/" + $zone_id + "/settings/ssl")},
      {label:"zone.min_tls." + $zone_name, method:"GET", path:("/zones/" + $zone_id + "/settings/min_tls_version")},
      {label:"zone.tls_1_3." + $zone_name, method:"GET", path:("/zones/" + $zone_id + "/settings/tls_1_3")},
      {label:"zone.custom_hostnames." + $zone_name, method:"GET", path:("/zones/" + $zone_id + "/custom_hostnames")}
    ]
  ')"

RESULTS='[]'
while IFS= read -r row; do
  label="$(jq -r '.label' <<< "${row}")"
  method="$(jq -r '.method' <<< "${row}")"
  path="$(jq -r '.path' <<< "${row}")"
  capture="$(cf_api_capture "${method}" "${path}")"
  RESULTS="$(
    jq \
      --arg label "${label}" \
      --argjson capture "${capture}" \
      '
        . + [
          {
            label: $label,
            status_code: $capture.status_code,
            success: ($capture.success // false),
            error_codes: (($capture.errors // []) | map(.code)),
            error_messages: (($capture.errors // []) | map(.message))
          }
        ]
      ' \
      <<< "${RESULTS}"
  )"
done < <(jq -c '.[]' <<< "${ENDPOINTS_JSON}")

OUTPUT_FILE="$(cf_inventory_file "auth" "token-permissions")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg zone_name "${ZONE_NAME}" \
    --arg zone_id "${ZONE_ID}" \
    --arg active_token_lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg active_token_env "${CF_ACTIVE_TOKEN_ENV:-unknown}" \
    --argjson results "${RESULTS}" \
    '
      {
        generated_at: $generated_at,
        auth: {
          active_token_lane: $active_token_lane,
          active_token_env: $active_token_env
        },
        zone: {
          name: $zone_name,
          id: $zone_id
        },
        probes: $results,
        summary: {
          success_count: ($results | map(select(.success == true)) | length),
          failure_count: ($results | map(select(.success != true)) | length),
          failures: ($results | map(select(.success != true)))
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Probed token permissions across Cloudflare surfaces."
echo "${REPORT_JSON}" | jq '{
  success_count: .summary.success_count,
  failure_count: .summary.failure_count,
  failures: .summary.failures
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
