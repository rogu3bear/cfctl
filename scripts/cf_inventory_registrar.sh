#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-registrar" "build"

REGISTRATIONS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/registrar/registrations")"
DOMAIN_SEARCH_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/registrar/domain-search?q=cloudflare&limit=3")"
ACCOUNT_CUSTOM_NS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/custom_ns")"
ZONES_JSON="$(cf_api GET "/zones?per_page=100&page=1&account.id=${CLOUDFLARE_ACCOUNT_ID}")"
ACTIVE_ZONES="$(jq '[.result[] | select(.status == "active") | {id, name}]' <<< "${ZONES_JSON}")"
ZONE_POSTURE='[]'

while IFS= read -r zone_row; do
  zone_id="$(jq -r '.id' <<< "${zone_row}")"
  zone_name="$(jq -r '.name' <<< "${zone_row}")"
  zone_json="$(cf_api_capture GET "/zones/${zone_id}")"
  zone_custom_ns="$(cf_api_capture GET "/zones/${zone_id}/custom_ns")"

  ZONE_POSTURE="$(
    jq \
      --arg zone_id "${zone_id}" \
      --arg zone_name "${zone_name}" \
      --argjson zone_json "${zone_json}" \
      --argjson zone_custom_ns "${zone_custom_ns}" \
      '
        . + [
          {
            zone: {
              id: $zone_id,
              name: $zone_name
            },
            details: $zone_json,
            custom_nameservers: $zone_custom_ns,
            summary: {
              plan_name: ($zone_json.result.plan.name // null),
              name_servers: ($zone_json.result.name_servers // []),
              zone_type: ($zone_json.result.type // null),
              custom_ns_enabled: ($zone_custom_ns.result.enabled // false)
            }
          }
        ]
      ' \
      <<< "${ZONE_POSTURE}"
  )"
done < <(jq -c '.[]' <<< "${ACTIVE_ZONES}")

OUTPUT_FILE="$(cf_inventory_file "account" "registrar")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson registrations "${REGISTRATIONS_JSON}" \
    --argjson domain_search "${DOMAIN_SEARCH_JSON}" \
    --argjson account_custom_ns "${ACCOUNT_CUSTOM_NS_JSON}" \
    --argjson zones "${ZONE_POSTURE}" \
    '
      {
        generated_at: $generated_at,
        registrations: $registrations,
        domain_search_probe: $domain_search,
        account_custom_nameservers: $account_custom_ns,
        zones: $zones,
        summary: {
          registration_count: (($registrations.result // []) | length),
          locked_registration_count: (($registrations.result // []) | map(select(.locked == true)) | length),
          auto_renew_disabled_count: (($registrations.result // []) | map(select(.auto_renew != true)) | length),
          soonest_expiration: (($registrations.result // []) | map(.expires_at) | sort | .[0]),
          registered_domains: (($registrations.result // []) | map(.domain_name) | sort),
          domain_search_probe_count: (($domain_search.result.domains // []) | length),
          account_custom_ns_enabled: ($account_custom_ns.success // false),
          zone_count: ($zones | length),
          custom_ns_enabled_zone_count: ($zones | map(select(.summary.custom_ns_enabled == true)) | length),
          zone_plan_counts: (
            $zones
            | map(.summary.plan_name)
            | group_by(.)
            | map({plan: .[0], count: length})
          ),
          cloudflare_nameserver_zone_count: (
            $zones
            | map(select((.summary.name_servers | map(test("ns\\.cloudflare\\.com$")) | any)))
            | length
          )
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured registrar and nameserver posture."
echo "${REPORT_JSON}" | jq '{
  registration_count: .summary.registration_count,
  locked_registration_count: .summary.locked_registration_count,
  auto_renew_disabled_count: .summary.auto_renew_disabled_count,
  soonest_expiration: .summary.soonest_expiration,
  domain_search_probe_count: .summary.domain_search_probe_count,
  zone_count: .summary.zone_count,
  custom_ns_enabled_zone_count: .summary.custom_ns_enabled_zone_count,
  zone_plan_counts: .summary.zone_plan_counts
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
