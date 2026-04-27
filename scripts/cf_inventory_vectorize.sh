#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-vectorize" "build"

RAW_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/vectorize/v2/indexes")"
OUTPUT_FILE="$(cf_inventory_file "account" "vectorize")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson response "${RAW_JSON}" \
    '
      {
        generated_at: $generated_at,
        indexes: ($response.result // []),
        summary: {
          index_count: (($response.result // []) | length),
          names: (($response.result // []) | map(.name) | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Vectorize inventory."
echo "${REPORT_JSON}" | jq '{
  index_count: .summary.index_count,
  names: .summary.names
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
