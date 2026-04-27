#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "audit-access" "build"

ACCESS_APPS_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps")"
OUTPUT_FILE="$(cf_inventory_file "access" "access-audit")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson apps "${ACCESS_APPS_JSON}" \
    '
      {
        generated_at: $generated_at,
        findings: {
          empty_allowed_idps: (
            ($apps.result // [])
            | map(select(.type == "self_hosted" and ((.allowed_idps // []) | length == 0)))
            | map({
                id,
                name,
                domain,
                aud,
                app_launcher_visible,
                auto_redirect_to_identity
              })
          ),
          launcher_visible_self_hosted: (
            ($apps.result // [])
            | map(select(.type == "self_hosted" and .app_launcher_visible == true))
            | map({id, name, domain, aud})
          ),
          self_hosted_without_auto_redirect: (
            ($apps.result // [])
            | map(select(.type == "self_hosted" and .auto_redirect_to_identity == false))
            | map({id, name, domain, aud, allowed_idps: (.allowed_idps // [])})
          )
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Audited Access applications for common drift markers."
echo "${REPORT_JSON}" | jq '{
  empty_allowed_idps: (.findings.empty_allowed_idps | length),
  self_hosted_without_auto_redirect: (.findings.self_hosted_without_auto_redirect | length),
  launcher_visible_self_hosted: (.findings.launcher_visible_self_hosted | length),
  sample_empty_allowed_idps: (.findings.empty_allowed_idps[:10])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
