#!/usr/bin/env bash

# Reads /accounts/:id/access/service_tokens and emits a normalized
# {service_tokens: [{id, name, client_id, ...}]} payload that the cfctl runtime
# extracts via .service_tokens in cfctl_collect_surface_items. The list endpoint
# never returns client_secret — it is write-only at mint time.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-access-service-tokens" "build"

TOKENS_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/service_tokens")"
OUTPUT_FILE="$(cf_inventory_file "access" "access-service-tokens")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson raw "${TOKENS_JSON}" \
    '
      ($raw.result // []) as $entries
      | {
          generated_at: $generated_at,
          service_tokens: ($entries | map({
            id: .id,
            name: .name,
            client_id: .client_id,
            duration: .duration,
            created_at: .created_at,
            updated_at: .updated_at,
            expires_at: .expires_at
          })),
          summary: {
            service_token_count: ($entries | length),
            service_token_names: ($entries | map(.name) | sort)
          }
        }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Access service-token inventory."
echo "${REPORT_JSON}" | jq '{
  service_token_count: .summary.service_token_count,
  service_token_names: (.summary.service_token_names[:20])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
