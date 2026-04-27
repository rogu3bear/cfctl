#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-workers" "build"

WORKERS_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts")"
OUTPUT_FILE="$(cf_inventory_file "workers" "workers")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson workers "${WORKERS_JSON}" \
    '
      {
        generated_at: $generated_at,
        workers: ($workers.result // []),
        summary: {
          script_count: (($workers.result // []) | length),
          script_names: (($workers.result // []) | map(.id) | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Workers inventory."
echo "${REPORT_JSON}" | jq '{
  script_count: .summary.script_count,
  script_names: (.summary.script_names[:10])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
