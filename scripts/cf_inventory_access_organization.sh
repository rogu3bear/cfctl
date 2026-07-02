#!/usr/bin/env bash

# Reads /accounts/:id/access/organizations (a singleton) and emits a
# normalized {organization: {...}} payload that the cfctl runtime extracts as
# a one-element list via [.organization] in cfctl_collect_surface_items.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-access-organization" "build"

ORG_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/organizations")"
OUTPUT_FILE="$(cf_inventory_file "access" "access-organization")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson raw "${ORG_JSON}" \
    '
      ($raw.result // null) as $org
      | {
          generated_at: $generated_at,
          organization: $org,
          summary: {
            present: ($org != null),
            name: ($org.name // null),
            auth_domain: ($org.auth_domain // null),
            session_duration: ($org.session_duration // null),
            is_ui_read_only: ($org.is_ui_read_only // false),
            auto_redirect_to_identity: ($org.auto_redirect_to_identity // false)
          }
        }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Access organization settings."
echo "${REPORT_JSON}" | jq '.summary'
cf_print_log_footer
echo "${OUTPUT_FILE}"
