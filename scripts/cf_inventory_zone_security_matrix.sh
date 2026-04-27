#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-zone-security-matrix" "build"

ZONES_JSON="$(cf_api GET "/zones?per_page=100&page=1&account.id=${CLOUDFLARE_ACCOUNT_ID}")"
ACTIVE_ZONES="$(jq '[.result[] | select(.status == "active") | {id, name}]' <<< "${ZONES_JSON}")"
MATRIX='[]'

while IFS= read -r zone_row; do
  zone_id="$(jq -r '.id' <<< "${zone_row}")"
  zone_name="$(jq -r '.name' <<< "${zone_row}")"

  echo "Scanning zone security posture for ${zone_name}"
  rulesets="$(cf_api_capture GET "/zones/${zone_id}/rulesets")"
  firewall_custom="$(cf_api_capture GET "/zones/${zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint")"
  firewall_managed="$(cf_api_capture GET "/zones/${zone_id}/rulesets/phases/http_request_firewall_managed/entrypoint")"
  firewall_access="$(cf_api_capture GET "/zones/${zone_id}/firewall/access_rules/rules")"
  rate_limits="$(cf_api_capture GET "/zones/${zone_id}/rate_limits")"

  MATRIX="$(
    jq \
      --arg zone_name "${zone_name}" \
      --arg zone_id "${zone_id}" \
      --argjson rulesets "${rulesets}" \
      --argjson firewall_custom "${firewall_custom}" \
      --argjson firewall_managed "${firewall_managed}" \
      --argjson firewall_access "${firewall_access}" \
      --argjson rate_limits "${rate_limits}" \
      '
        . + [
          {
            zone: {
              id: $zone_id,
              name: $zone_name
            },
            ruleset_count: (($rulesets.result // []) | length),
            ruleset_phases: (($rulesets.result // []) | map(.phase) | unique | sort),
            firewall_custom_success: ($firewall_custom.success // false),
            firewall_managed_success: ($firewall_managed.success // false),
            firewall_access_success: ($firewall_access.success // false),
            firewall_access_rule_count: (($firewall_access.result // []) | length),
            rate_limits_success: ($rate_limits.success // false),
            rate_limit_count: (($rate_limits.result // []) | length),
            permission_failures: [
              {surface:"firewall_access_rules", status_code:$firewall_access.status_code, success:($firewall_access.success // false)},
              {surface:"rate_limits", status_code:$rate_limits.status_code, success:($rate_limits.success // false)}
            ] | map(select(.success != true))
          }
        ]
      ' \
      <<< "${MATRIX}"
  )"
done < <(jq -c '.[]' <<< "${ACTIVE_ZONES}")

OUTPUT_FILE="$(cf_inventory_file "account" "zone-security-matrix")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson zones "${MATRIX}" \
    '
      {
        generated_at: $generated_at,
        zones: $zones,
        summary: {
          zone_count: ($zones | length),
          ruleset_enabled_zone_count: ($zones | map(select(.ruleset_count > 0)) | length),
          firewall_access_permission_failure_count: ($zones | map(select(.firewall_access_success != true)) | length),
          rate_limit_permission_failure_count: ($zones | map(select(.rate_limits_success != true)) | length)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured zone security matrix."
echo "${REPORT_JSON}" | jq '{
  zone_count: .summary.zone_count,
  ruleset_enabled_zone_count: .summary.ruleset_enabled_zone_count,
  firewall_access_permission_failure_count: .summary.firewall_access_permission_failure_count,
  rate_limit_permission_failure_count: .summary.rate_limit_permission_failure_count
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
