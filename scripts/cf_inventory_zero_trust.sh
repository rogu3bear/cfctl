#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-zero-trust" "build"

IDPS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/identity_providers")"
SERVICE_TOKENS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/service_tokens")"
GATEWAY_RULES_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/gateway/rules")"
GATEWAY_CONFIG_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/gateway/configuration")"

OUTPUT_FILE="$(cf_inventory_file "account" "zero-trust")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson idps "${IDPS_JSON}" \
    --argjson service_tokens "${SERVICE_TOKENS_JSON}" \
    --argjson gateway_rules "${GATEWAY_RULES_JSON}" \
    --argjson gateway_config "${GATEWAY_CONFIG_JSON}" \
    '
      {
        generated_at: $generated_at,
        identity_providers: $idps,
        service_tokens: $service_tokens,
        gateway_rules: $gateway_rules,
        gateway_configuration: $gateway_config,
        summary: {
          identity_provider_count: (($idps.result // []) | length),
          service_token_count: (($service_tokens.result // []) | length),
          gateway_rule_count: (($gateway_rules.result // []) | length),
          identity_provider_names: (($idps.result // []) | map(.name) | sort),
          service_token_names: (($service_tokens.result // []) | map(.name) | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Zero Trust inventory."
echo "${REPORT_JSON}" | jq '{
  identity_provider_count: .summary.identity_provider_count,
  service_token_count: .summary.service_token_count,
  gateway_rule_count: .summary.gateway_rule_count,
  identity_provider_names: .summary.identity_provider_names,
  service_token_names: (.summary.service_token_names[:10])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
