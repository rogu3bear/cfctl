#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_setup_log_pipe "inventory-d1" "build"

RAW_JSON="$("${ROOT_DIR}/scripts/cf_wrangler.sh" d1 list --json)"
OUTPUT_FILE="$(cf_inventory_file "account" "d1")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson databases "${RAW_JSON}" \
    '
      {
        generated_at: $generated_at,
        databases: $databases,
        summary: {
          database_count: ($databases | length),
          names: ($databases | map(.name) | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured D1 inventory."
echo "${REPORT_JSON}" | jq '{
  database_count: .summary.database_count,
  names: (.summary.names[:20])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
