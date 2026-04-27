#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-waiting-rooms" "build"

ZONES_JSON="$(cf_api GET "/zones?per_page=100&page=1&account.id=${CLOUDFLARE_ACCOUNT_ID}")"
ACTIVE_ZONES="$(jq '[.result[] | select(.status == "active") | {id, name}]' <<< "${ZONES_JSON}")"
ZONE_REPORTS='[]'

while IFS= read -r zone_row; do
  zone_id="$(jq -r '.id' <<< "${zone_row}")"
  zone_name="$(jq -r '.name' <<< "${zone_row}")"

  echo "Scanning waiting rooms for ${zone_name}"
  waiting_rooms="$(cf_api_capture GET "/zones/${zone_id}/waiting_rooms")"
  statuses='[]'

  if [[ "$(jq -r '.success // false' <<< "${waiting_rooms}")" == "true" ]]; then
    while IFS= read -r room_row; do
      room_id="$(jq -r '.id' <<< "${room_row}")"
      room_name="$(jq -r '.name' <<< "${room_row}")"
      room_status="$(cf_api_capture GET "/zones/${zone_id}/waiting_rooms/${room_id}/status")"
      statuses="$(
        jq \
          --arg room_id "${room_id}" \
          --arg room_name "${room_name}" \
          --argjson room_status "${room_status}" \
          '
            . + [
              {
                id: $room_id,
                name: $room_name,
                status: $room_status
              }
            ]
          ' \
          <<< "${statuses}"
      )"
    done < <(jq -c '.result[]? // empty' <<< "${waiting_rooms}")
  fi

  ZONE_REPORTS="$(
    jq \
      --arg zone_id "${zone_id}" \
      --arg zone_name "${zone_name}" \
      --argjson waiting_rooms "${waiting_rooms}" \
      --argjson statuses "${statuses}" \
      '
        . + [
          {
            zone: {
              id: $zone_id,
              name: $zone_name
            },
            waiting_rooms: $waiting_rooms,
            statuses: $statuses,
            summary: {
              waiting_room_count: (($waiting_rooms.result // []) | length),
              readable: ($waiting_rooms.success // false)
            }
          }
        ]
      ' \
      <<< "${ZONE_REPORTS}"
  )"
done < <(jq -c '.[]' <<< "${ACTIVE_ZONES}")

OUTPUT_FILE="$(cf_inventory_file "account" "waiting-rooms")"
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
          readable_zone_count: ($zones | map(select(.summary.readable == true)) | length),
          permission_error_count: ($zones | map(select(.summary.readable != true)) | length),
          waiting_room_count: ($zones | map(.summary.waiting_room_count) | add)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured waiting-room inventory."
echo "${REPORT_JSON}" | jq '{
  zone_count: .summary.zone_count,
  readable_zone_count: .summary.readable_zone_count,
  permission_error_count: .summary.permission_error_count,
  waiting_room_count: .summary.waiting_room_count
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
