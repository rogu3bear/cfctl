#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-workflows" "build"

RAW_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/workflows?per_page=100")"
OUTPUT_FILE="$(cf_inventory_file "account" "workflows")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson response "${RAW_JSON}" \
    '
      {
        generated_at: $generated_at,
        workflows: ($response.result // []),
        summary: {
          workflow_count: (($response.result // []) | length),
          names: (($response.result // []) | map(.name) | sort),
          scripts: (($response.result // []) | map(.script_name) | unique | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Workflows inventory."
echo "${REPORT_JSON}" | jq '{
  workflow_count: .summary.workflow_count,
  names: .summary.names,
  scripts: .summary.scripts
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
