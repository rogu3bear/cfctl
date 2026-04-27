#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_setup_log_pipe "inventory-zone-security" "build"

ZONE_NAME="${ZONE_NAME:-example.com}"
ZONE_ID="$(cf_resolve_zone_id "${ZONE_NAME}")"

if [[ -z "${ZONE_ID}" || "${ZONE_ID}" == "null" ]]; then
  echo "Unable to resolve zone id for ${ZONE_NAME}" >&2
  exit 1
fi

RULESETS_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/rulesets")"
FIREWALL_CUSTOM_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/rulesets/phases/http_request_firewall_custom/entrypoint")"
TRANSFORM_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/rulesets/phases/http_request_transform/entrypoint")"
FIREWALL_ACCESS_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/firewall/access_rules/rules")"
RATE_LIMITS_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/rate_limits")"

OUTPUT_FILE="$(cf_inventory_file "account" "zone-security")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg zone_name "${ZONE_NAME}" \
    --arg zone_id "${ZONE_ID}" \
    --argjson rulesets "${RULESETS_JSON}" \
    --argjson firewall_custom "${FIREWALL_CUSTOM_JSON}" \
    --argjson transform "${TRANSFORM_JSON}" \
    --argjson firewall_access "${FIREWALL_ACCESS_JSON}" \
    --argjson rate_limits "${RATE_LIMITS_JSON}" \
    '
      {
        generated_at: $generated_at,
        zone: {
          name: $zone_name,
          id: $zone_id
        },
        rulesets: $rulesets,
        firewall_custom_entrypoint: $firewall_custom,
        request_transform_entrypoint: $transform,
        firewall_access_rules: $firewall_access,
        rate_limits: $rate_limits,
        summary: {
          ruleset_count: (($rulesets.result // []) | length),
          firewall_access_rule_count: (($firewall_access.result // []) | length),
          rate_limit_count: (($rate_limits.result // []) | length),
          ruleset_phases: (($rulesets.result // []) | map(.phase) | unique | sort),
          permission_limited_surfaces: [
            {
              surface: "firewall_access_rules",
              status_code: $firewall_access.status_code,
              success: $firewall_access.success
            },
            {
              surface: "rate_limits",
              status_code: $rate_limits.status_code,
              success: $rate_limits.success
            },
            {
              surface: "request_transform_entrypoint",
              status_code: $transform.status_code,
              success: $transform.success
            }
          ] | map(select(.success != true))
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured zone security inventory for ${ZONE_NAME}."
echo "${REPORT_JSON}" | jq '{
  zone: .zone,
  ruleset_count: .summary.ruleset_count,
  firewall_access_rule_count: .summary.firewall_access_rule_count,
  rate_limit_count: .summary.rate_limit_count,
  ruleset_phases: .summary.ruleset_phases,
  permission_limited_surfaces: .summary.permission_limited_surfaces
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
