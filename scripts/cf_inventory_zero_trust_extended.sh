#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-zero-trust-extended" "build"

RULES_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/gateway/rules")"
LISTS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/gateway/lists")"
LOCATIONS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/gateway/locations")"
APP_TYPES_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/gateway/app_types")"
CATEGORIES_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/gateway/categories")"
PROXY_ENDPOINTS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/gateway/proxy_endpoints")"
LOGGING_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/gateway/logging")"
DEVICE_POSTURE_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/devices/posture")"

OUTPUT_FILE="$(cf_inventory_file "account" "zero-trust-extended")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson rules "${RULES_JSON}" \
    --argjson lists "${LISTS_JSON}" \
    --argjson locations "${LOCATIONS_JSON}" \
    --argjson app_types "${APP_TYPES_JSON}" \
    --argjson categories "${CATEGORIES_JSON}" \
    --argjson proxy_endpoints "${PROXY_ENDPOINTS_JSON}" \
    --argjson logging "${LOGGING_JSON}" \
    --argjson device_posture "${DEVICE_POSTURE_JSON}" \
    '
      {
        generated_at: $generated_at,
        gateway_rules: $rules,
        gateway_lists: $lists,
        gateway_locations: $locations,
        gateway_app_types: $app_types,
        gateway_categories: $categories,
        gateway_proxy_endpoints: $proxy_endpoints,
        gateway_logging: $logging,
        device_posture: $device_posture,
        summary: {
          gateway_rule_count: (($rules.result // []) | length),
          isolate_rule_count: (($rules.result // []) | map(select(.action == "isolate")) | length),
          gateway_list_count: (($lists.result // []) | length),
          gateway_list_type_counts: (
            ($lists.result // [])
            | map(.type)
            | group_by(.)
            | map({type: .[0], count: length})
          ),
          gateway_location_count: (($locations.result // []) | length),
          gateway_location_names: (($locations.result // []) | map(.name) | map(select(. != null)) | sort),
          gateway_category_count: (($categories.result // []) | length),
          gateway_app_type_count: (($app_types.result // []) | length),
          proxy_endpoint_count: (($proxy_endpoints.result // []) | length),
          device_posture_rule_count: (($device_posture.result // []) | length),
          device_posture_types: (($device_posture.result // []) | map(.type) | unique | sort),
          logging_redact_pii: ($logging.result.redact_pii // null)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured extended Zero Trust inventory."
echo "${REPORT_JSON}" | jq '{
  gateway_rule_count: .summary.gateway_rule_count,
  isolate_rule_count: .summary.isolate_rule_count,
  gateway_list_count: .summary.gateway_list_count,
  gateway_location_count: .summary.gateway_location_count,
  gateway_category_count: .summary.gateway_category_count,
  gateway_app_type_count: .summary.gateway_app_type_count,
  proxy_endpoint_count: .summary.proxy_endpoint_count,
  device_posture_rule_count: .summary.device_posture_rule_count,
  device_posture_types: .summary.device_posture_types,
  logging_redact_pii: .summary.logging_redact_pii
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
