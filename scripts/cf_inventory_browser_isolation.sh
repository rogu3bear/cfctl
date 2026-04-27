#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-browser-isolation" "build"

ACCESS_APPS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps")"
GATEWAY_RULES_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/gateway/rules")"

OUTPUT_FILE="$(cf_inventory_file "account" "browser-isolation")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson access_apps "${ACCESS_APPS_JSON}" \
    --argjson gateway_rules "${GATEWAY_RULES_JSON}" \
    '
      {
        generated_at: $generated_at,
        access_apps: $access_apps,
        gateway_rules: $gateway_rules,
        summary: {
          access_app_count: (($access_apps.result // []) | length),
          clientless_app_launcher_count: (
            ($access_apps.result // [])
            | map(select(.use_clientless_isolation_app_launcher_url == true))
            | length
          ),
          non_identity_policy_count: (
            ($access_apps.result // [])
            | map(.policies // [])
            | flatten
            | map(select(.decision == "non_identity"))
            | length
          ),
          access_apps_with_non_identity_policies: (
            ($access_apps.result // [])
            | map(select((.policies // []) | any(.decision == "non_identity")))
            | map({
                name,
                domain,
                type,
                non_identity_policy_names: ((.policies // []) | map(select(.decision == "non_identity") | .name))
              })
          ),
          gateway_isolate_rule_count: (
            ($gateway_rules.result // [])
            | map(select(.action == "isolate"))
            | length
          ),
          gateway_isolate_rules: (
            ($gateway_rules.result // [])
            | map(select(.action == "isolate"))
            | map({name, enabled, filters, traffic})
          ),
          browser_isolation_signal_count: (
            (
              ($access_apps.result // [])
              | map(.policies // [])
              | flatten
              | map(select(.decision == "non_identity"))
              | length
            )
            + (
              ($access_apps.result // [])
              | map(select(.use_clientless_isolation_app_launcher_url == true))
              | length
            )
            + (
              ($gateway_rules.result // [])
              | map(select(.action == "isolate"))
              | length
            )
          )
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Browser Isolation posture."
echo "${REPORT_JSON}" | jq '{
  clientless_app_launcher_count: .summary.clientless_app_launcher_count,
  non_identity_policy_count: .summary.non_identity_policy_count,
  gateway_isolate_rule_count: .summary.gateway_isolate_rule_count,
  browser_isolation_signal_count: .summary.browser_isolation_signal_count,
  access_apps_with_non_identity_policies: .summary.access_apps_with_non_identity_policies,
  gateway_isolate_rules: .summary.gateway_isolate_rules
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
