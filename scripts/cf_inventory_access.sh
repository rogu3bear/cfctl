#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-access" "build"

ACCESS_APPS_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps")"
OUTPUT_FILE="$(cf_inventory_file "access" "access-apps")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson apps "${ACCESS_APPS_JSON}" \
    '
      {
        generated_at: $generated_at,
        applications: ($apps.result // []),
        summary: {
          app_count: (($apps.result // []) | length),
          domains: (($apps.result // []) | map(.domain) | map(select(. != null)) | sort),
          apps: (
            ($apps.result // [])
            | map({
                id,
                name,
                domain,
                type,
                aud,
                allowed_idps: (.allowed_idps // []),
                auto_redirect_to_identity,
                app_launcher_visible
              })
          )
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Access application inventory."
echo "${REPORT_JSON}" | jq '{
  app_count: .summary.app_count,
  sample_apps: (.summary.apps[:10])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
