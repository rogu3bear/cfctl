#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-ssl-posture" "build"

ZONES_JSON="$(cf_api GET "/zones?per_page=100&page=1&account.id=${CLOUDFLARE_ACCOUNT_ID}")"
ACTIVE_ZONES="$(jq '[.result[] | select(.status == "active") | {id, name}]' <<< "${ZONES_JSON}")"
ZONE_REPORTS='[]'

while IFS= read -r zone_row; do
  zone_id="$(jq -r '.id' <<< "${zone_row}")"
  zone_name="$(jq -r '.name' <<< "${zone_row}")"

  echo "Scanning SSL posture for ${zone_name}"
  ssl_setting="$(cf_api_capture GET "/zones/${zone_id}/settings/ssl")"
  min_tls="$(cf_api_capture GET "/zones/${zone_id}/settings/min_tls_version")"
  tls13="$(cf_api_capture GET "/zones/${zone_id}/settings/tls_1_3")"
  certificate_packs="$(cf_api_capture GET "/zones/${zone_id}/ssl/certificate_packs?status=all")"
  custom_hostnames="$(cf_api_capture GET "/zones/${zone_id}/custom_hostnames")"

  ZONE_REPORTS="$(
    jq \
      --arg zone_id "${zone_id}" \
      --arg zone_name "${zone_name}" \
      --argjson ssl_setting "${ssl_setting}" \
      --argjson min_tls "${min_tls}" \
      --argjson tls13 "${tls13}" \
      --argjson certificate_packs "${certificate_packs}" \
      --argjson custom_hostnames "${custom_hostnames}" \
      '
        . + [
          {
            zone: {
              id: $zone_id,
              name: $zone_name
            },
            ssl_setting: $ssl_setting,
            min_tls_version: $min_tls,
            tls_1_3: $tls13,
            certificate_packs: $certificate_packs,
            custom_hostnames: $custom_hostnames,
            summary: {
              ssl_readable: ($ssl_setting.success // false),
              min_tls_readable: ($min_tls.success // false),
              tls13_readable: ($tls13.success // false),
              certificate_packs_readable: ($certificate_packs.success // false),
              custom_hostnames_readable: ($custom_hostnames.success // false),
              certificate_pack_count: (($certificate_packs.result // []) | length),
              custom_hostname_count: (($custom_hostnames.result // []) | length)
            }
          }
        ]
      ' \
      <<< "${ZONE_REPORTS}"
  )"
done < <(jq -c '.[]' <<< "${ACTIVE_ZONES}")

OUTPUT_FILE="$(cf_inventory_file "account" "ssl-posture")"
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
          ssl_readable_zone_count: ($zones | map(select(.summary.ssl_readable == true)) | length),
          min_tls_readable_zone_count: ($zones | map(select(.summary.min_tls_readable == true)) | length),
          tls13_readable_zone_count: ($zones | map(select(.summary.tls13_readable == true)) | length),
          certificate_packs_readable_zone_count: ($zones | map(select(.summary.certificate_packs_readable == true)) | length),
          custom_hostnames_readable_zone_count: ($zones | map(select(.summary.custom_hostnames_readable == true)) | length),
          certificate_pack_count: ($zones | map(.summary.certificate_pack_count) | add),
          custom_hostname_count: ($zones | map(.summary.custom_hostname_count) | add)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured SSL posture inventory."
echo "${REPORT_JSON}" | jq '{
  zone_count: .summary.zone_count,
  ssl_readable_zone_count: .summary.ssl_readable_zone_count,
  min_tls_readable_zone_count: .summary.min_tls_readable_zone_count,
  tls13_readable_zone_count: .summary.tls13_readable_zone_count,
  certificate_packs_readable_zone_count: .summary.certificate_packs_readable_zone_count,
  custom_hostnames_readable_zone_count: .summary.custom_hostnames_readable_zone_count,
  certificate_pack_count: .summary.certificate_pack_count,
  custom_hostname_count: .summary.custom_hostname_count
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
