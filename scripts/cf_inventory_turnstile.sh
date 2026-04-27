#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-turnstile" "build"

WIDGETS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/challenges/widgets")"

OUTPUT_FILE="$(cf_inventory_file "account" "turnstile")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson widgets "${WIDGETS_JSON}" \
    '
      {
        generated_at: $generated_at,
        widgets: $widgets,
        summary: {
          widget_count: (($widgets.result // []) | length),
          widget_names: (($widgets.result // []) | map(.name) | sort),
          modes: (($widgets.result // []) | map(.mode) | unique | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Turnstile inventory."
echo "${REPORT_JSON}" | jq '{
  widget_count: .summary.widget_count,
  widget_names: (.summary.widget_names[:20]),
  modes: .summary.modes
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
