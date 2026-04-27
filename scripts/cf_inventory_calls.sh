#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-calls" "build"

APPS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/calls/apps")"
TURN_KEYS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/calls/turn_keys")"

OUTPUT_FILE="$(cf_inventory_file "account" "calls")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson apps "${APPS_JSON}" \
    --argjson turn_keys "${TURN_KEYS_JSON}" \
    '
      {
        generated_at: $generated_at,
        apps: $apps,
        turn_keys: $turn_keys,
        summary: {
          app_count: (($apps.result // []) | length),
          turn_key_count: (($turn_keys.result // []) | length),
          app_names: (($apps.result // []) | map(.name) | map(select(. != null)) | sort),
          app_ids: (($apps.result // []) | map(.uid) | map(select(. != null)) | sort),
          active_turn_key_count: (($turn_keys.result // []) | map(select(.disabled != true)) | length)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Calls inventory."
echo "${REPORT_JSON}" | jq '{
  app_count: .summary.app_count,
  turn_key_count: .summary.turn_key_count,
  active_turn_key_count: .summary.active_turn_key_count,
  app_names: .summary.app_names
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
