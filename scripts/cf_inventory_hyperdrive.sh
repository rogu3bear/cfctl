#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-hyperdrive" "build"

RAW_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/hyperdrive/configs")"
OUTPUT_FILE="$(cf_inventory_file "account" "hyperdrive")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson response "${RAW_JSON}" \
    '
      {
        generated_at: $generated_at,
        hyperdrives: ($response.result // []),
        summary: {
          hyperdrive_count: (($response.result // []) | length),
          names: (($response.result // []) | map(.name) | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Hyperdrive inventory."
echo "${REPORT_JSON}" | jq '{
  hyperdrive_count: .summary.hyperdrive_count,
  names: .summary.names
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
