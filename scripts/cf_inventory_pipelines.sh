#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq sed
cf_require_api_auth
cf_setup_log_pipe "inventory-pipelines" "build"

RAW_OUTPUT="$("${ROOT_DIR}/scripts/cf_wrangler.sh" pipelines list 2>&1 || true)"
CLEAN_OUTPUT="$(printf '%s\n' "${RAW_OUTPUT}" | sed $'s/\033\\[[0-9;]*[A-Za-z]//g')"

OUTPUT_FILE="$(cf_inventory_file "account" "pipelines")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg raw_output "${CLEAN_OUTPUT}" \
    '
      {
        generated_at: $generated_at,
        raw_output: $raw_output,
        summary: {
          pipeline_count: (if ($raw_output | test("No pipelines found")) then 0 else null end),
          empty: ($raw_output | test("No pipelines found"))
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Pipelines inventory."
echo "${REPORT_JSON}" | jq '{
  pipeline_count: .summary.pipeline_count,
  empty: .summary.empty
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
