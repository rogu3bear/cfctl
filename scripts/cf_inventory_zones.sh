#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-zones" "build"

ZONES_JSON="$(cf_api GET "/zones?per_page=100&page=1&account.id=${CLOUDFLARE_ACCOUNT_ID}")"
OUTPUT_FILE="$(cf_inventory_file "account" "zones")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson zones "${ZONES_JSON}" \
    '
      {
        generated_at: $generated_at,
        zones: ($zones.result // []),
        summary: {
          zone_count: (($zones.result // []) | length),
          active_zone_count: (($zones.result // []) | map(select(.status == "active")) | length),
          by_plan: (
            ($zones.result // [])
            | map(.plan.name // "unknown")
            | group_by(.)
            | map({plan: .[0], count: length})
          )
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured zone inventory."
echo "${REPORT_JSON}" | jq '{
  zone_count: .summary.zone_count,
  active_zone_count: .summary.active_zone_count,
  by_plan: .summary.by_plan,
  first_ten_zones: (.zones | map({name, status, paused, plan: (.plan.name // null)})[:10])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
