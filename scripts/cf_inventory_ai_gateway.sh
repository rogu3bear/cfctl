#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-ai-gateway" "build"

RAW_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/ai-gateway/gateways")"
OUTPUT_FILE="$(cf_inventory_file "account" "ai-gateway")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson response "${RAW_JSON}" \
    '
      {
        generated_at: $generated_at,
        gateways: ($response.result // []),
        summary: {
          gateway_count: (($response.result // []) | length),
          ids: (($response.result // []) | map(.id) | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured AI Gateway inventory."
echo "${REPORT_JSON}" | jq '{
  gateway_count: .summary.gateway_count,
  ids: .summary.ids
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
