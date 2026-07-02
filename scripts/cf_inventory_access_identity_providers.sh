#!/usr/bin/env bash

# Reads /accounts/:id/access/identity_providers and emits a normalized
# {identity_providers: [{id, name, type}]} payload that the cfctl runtime
# extracts via .identity_providers in cfctl_collect_surface_items. Provider
# config is intentionally omitted: SAML/OIDC configs can carry secrets and the
# list surface only needs identity-shape facts.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-access-identity-providers" "build"

PROVIDERS_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/identity_providers")"
OUTPUT_FILE="$(cf_inventory_file "access" "access-identity-providers")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson raw "${PROVIDERS_JSON}" \
    '
      ($raw.result // []) as $entries
      | {
          generated_at: $generated_at,
          identity_providers: ($entries | map({
            id: .id,
            name: (.name // null),
            type: (.type // null)
          })),
          summary: {
            provider_count: ($entries | length),
            provider_types: ($entries | map(.type // "unknown") | sort | unique),
            onetimepin_present: (($entries | map(select(.type == "onetimepin")) | length) > 0)
          }
        }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Access identity-provider inventory."
echo "${REPORT_JSON}" | jq '{
  provider_count: .summary.provider_count,
  provider_types: .summary.provider_types,
  onetimepin_present: .summary.onetimepin_present
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
