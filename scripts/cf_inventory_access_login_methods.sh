#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-access-login-methods" "build"

ACCESS_APPS_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps")"
IDENTITY_PROVIDERS_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/identity_providers")"
OUTPUT_FILE="$(cf_inventory_file "access" "access-login-methods")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson apps "${ACCESS_APPS_JSON}" \
    --argjson providers "${IDENTITY_PROVIDERS_JSON}" \
    '
      ($apps.result // []) as $app_rows
      | ($providers.result // []) as $provider_rows
      | (reduce $provider_rows[] as $provider ({}; .[$provider.id] = {
          id: $provider.id,
          name: ($provider.name // null),
          type: ($provider.type // null)
        })) as $provider_by_id
      | (
          $app_rows
          | map(
              (.allowed_idps // []) as $allowed
              | {
                  id,
                  name,
                  domain,
                  type,
                  allowed_idps: $allowed,
                  allowed_providers: (
                    $allowed
                    | map($provider_by_id[.] // {id: ., name: null, type: null, missing: true})
                  ),
                  allowed_provider_types: (
                    $allowed
                    | map(($provider_by_id[.] // {}).type // null)
                    | map(select(. != null))
                    | unique
                  ),
                  auto_redirect_to_identity: (.auto_redirect_to_identity // null),
                  policy_decisions: ((.policies // []) | map(.decision // empty) | unique),
                  policies: ((.policies // []) | map({
                    id: (.id // null),
                    name: (.name // null),
                    decision: (.decision // null),
                    precedence: (.precedence // null)
                  }))
                }
            )
        ) as $applications
      | {
          generated_at: $generated_at,
          identity_providers: (
            $provider_rows
            | map({
                id,
                name: (.name // null),
                type: (.type // null)
              })
          ),
          applications: $applications,
          summary: {
            provider_count: ($provider_rows | length),
            provider_types: ($provider_rows | map(.type // empty) | unique),
            app_count: ($applications | length),
            single_provider_app_count: ($applications | map(select((.allowed_idps // []) | length == 1)) | length),
            multi_provider_app_count: ($applications | map(select((.allowed_idps // []) | length > 1)) | length),
            no_provider_app_count: ($applications | map(select((.allowed_idps // []) | length == 0)) | length),
            apps: ($applications | map({
              id,
              name,
              domain,
              type,
              allowed_idps,
              allowed_providers,
              allowed_provider_types,
              auto_redirect_to_identity,
              policy_decisions
            }))
          }
        }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Access login-method inventory."
echo "${REPORT_JSON}" | jq '{
  app_count: .summary.app_count,
  provider_count: .summary.provider_count,
  provider_types: .summary.provider_types,
  sample_apps: (.summary.apps[:10])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
