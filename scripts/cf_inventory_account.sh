#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-account" "build"

ACCOUNT_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}")"
ZONES_JSON="$(cf_api GET "/zones?per_page=100&page=1&account.id=${CLOUDFLARE_ACCOUNT_ID}")"
OUTPUT_FILE="$(cf_inventory_file "account" "account")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson account "${ACCOUNT_JSON}" \
    --argjson zones "${ZONES_JSON}" \
    '
      {
        generated_at: $generated_at,
        account: ($account.result // null),
        zones: ($zones.result // []),
        summary: {
          zone_count: (($zones.result // []) | length),
          active_zone_count: (($zones.result // []) | map(select(.status == "active")) | length),
          paused_zone_count: (($zones.result // []) | map(select(.paused == true)) | length)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured account and zone inventory."
echo "${REPORT_JSON}" | jq '{
  account_id: .account.id,
  account_name: .account.name,
  zone_count: .summary.zone_count,
  first_five_zones: (.zones | map(.name) | sort | .[:5])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
