#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-pages" "build"

RAW_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/pages/projects")"
OUTPUT_FILE="$(cf_inventory_file "account" "pages-projects")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson response "${RAW_JSON}" \
    '
      {
        generated_at: $generated_at,
        projects: ($response.result // []),
        summary: {
          project_count: (($response.result // []) | length),
          names: (($response.result // []) | map(.name) | sort),
          custom_domain_projects: (
            ($response.result // [])
            | map(select(((.domains // []) | length) > 0))
            | map({name, domains})
          )
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Pages project inventory."
echo "${REPORT_JSON}" | jq '{
  project_count: .summary.project_count,
  names: (.summary.names[:20]),
  custom_domain_projects: (.summary.custom_domain_projects[:10])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
