#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-waf-bot" "build"

ZONES_JSON="$(cf_api GET "/zones?per_page=100&page=1&account.id=${CLOUDFLARE_ACCOUNT_ID}")"
ACTIVE_ZONES="$(jq '[.result[] | select(.status == "active") | {id, name}]' <<< "${ZONES_JSON}")"
ZONE_REPORTS='[]'

while IFS= read -r zone_row; do
  zone_id="$(jq -r '.id' <<< "${zone_row}")"
  zone_name="$(jq -r '.name' <<< "${zone_row}")"

  echo "Scanning WAF and bot posture for ${zone_name}"
  rulesets="$(cf_api_capture GET "/zones/${zone_id}/rulesets")"
  firewall_managed="$(cf_api_capture GET "/zones/${zone_id}/rulesets/phases/http_request_firewall_managed/entrypoint")"
  firewall_custom="$(cf_api_capture GET "/zones/${zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint")"
  bot_management="$(cf_api_capture GET "/zones/${zone_id}/bot_management")"

  ZONE_REPORTS="$(
    jq \
      --arg zone_id "${zone_id}" \
      --arg zone_name "${zone_name}" \
      --argjson rulesets "${rulesets}" \
      --argjson firewall_managed "${firewall_managed}" \
      --argjson firewall_custom "${firewall_custom}" \
      --argjson bot_management "${bot_management}" \
      '
        . + [
          {
            zone: {
              id: $zone_id,
              name: $zone_name
            },
            rulesets: $rulesets,
            firewall_managed: $firewall_managed,
            firewall_custom: $firewall_custom,
            bot_management: $bot_management,
            summary: {
              ruleset_count: (($rulesets.result // []) | length),
              managed_ruleset_count: (($rulesets.result // []) | map(select(.phase == "http_request_firewall_managed")) | length),
              ddos_ruleset_count: (($rulesets.result // []) | map(select(.phase == "ddos_l7")) | length),
              rate_limit_phase_present: (($rulesets.result // []) | any(.phase == "http_ratelimit")),
              firewall_managed_readable: ($firewall_managed.success // false),
              firewall_custom_readable: ($firewall_custom.success // false),
              bot_management_readable: ($bot_management.success // false)
            }
          }
        ]
      ' \
      <<< "${ZONE_REPORTS}"
  )"
done < <(jq -c '.[]' <<< "${ACTIVE_ZONES}")

OUTPUT_FILE="$(cf_inventory_file "account" "waf-bot-management")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson zones "${ZONE_REPORTS}" \
    '
      {
        generated_at: $generated_at,
        zones: $zones,
        summary: {
          zone_count: ($zones | length),
          zones_with_managed_waf_phase: ($zones | map(select(.summary.managed_ruleset_count > 0)) | length),
          zones_with_ddos_phase: ($zones | map(select(.summary.ddos_ruleset_count > 0)) | length),
          firewall_managed_readable_zone_count: ($zones | map(select(.summary.firewall_managed_readable == true)) | length),
          firewall_custom_readable_zone_count: ($zones | map(select(.summary.firewall_custom_readable == true)) | length),
          bot_management_readable_zone_count: ($zones | map(select(.summary.bot_management_readable == true)) | length),
          bot_management_permission_failure_count: ($zones | map(select(.summary.bot_management_readable != true)) | length)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured WAF and bot-management inventory."
echo "${REPORT_JSON}" | jq '{
  zone_count: .summary.zone_count,
  zones_with_managed_waf_phase: .summary.zones_with_managed_waf_phase,
  zones_with_ddos_phase: .summary.zones_with_ddos_phase,
  firewall_managed_readable_zone_count: .summary.firewall_managed_readable_zone_count,
  firewall_custom_readable_zone_count: .summary.firewall_custom_readable_zone_count,
  bot_management_readable_zone_count: .summary.bot_management_readable_zone_count,
  bot_management_permission_failure_count: .summary.bot_management_permission_failure_count
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
