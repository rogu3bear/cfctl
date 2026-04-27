#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-api-shield" "build"

ZONES_JSON="$(cf_api GET "/zones?per_page=100&page=1&account.id=${CLOUDFLARE_ACCOUNT_ID}")"
ACTIVE_ZONES="$(jq '[.result[] | select(.status == "active") | {id, name}]' <<< "${ZONES_JSON}")"
ZONE_REPORTS='[]'

while IFS= read -r zone_row; do
  zone_id="$(jq -r '.id' <<< "${zone_row}")"
  zone_name="$(jq -r '.name' <<< "${zone_row}")"

  echo "Scanning API Shield posture for ${zone_name}"
  operations="$(cf_api_capture GET "/zones/${zone_id}/api_gateway/operations")"
  discovery_operations="$(cf_api_capture GET "/zones/${zone_id}/api_gateway/discovery/operations")"
  discovery_schema="$(cf_api_capture GET "/zones/${zone_id}/api_gateway/discovery")"
  user_schemas="$(cf_api_capture GET "/zones/${zone_id}/api_gateway/user_schemas")"
  schema_validation="$(cf_api_capture GET "/zones/${zone_id}/schema_validation/schemas")"

  ZONE_REPORTS="$(
    jq \
      --arg zone_id "${zone_id}" \
      --arg zone_name "${zone_name}" \
      --argjson operations "${operations}" \
      --argjson discovery_operations "${discovery_operations}" \
      --argjson discovery_schema "${discovery_schema}" \
      --argjson user_schemas "${user_schemas}" \
      --argjson schema_validation "${schema_validation}" \
      '
        . + [
          {
            zone: {
              id: $zone_id,
              name: $zone_name
            },
            operations: $operations,
            discovery_operations: $discovery_operations,
            discovery_schema: $discovery_schema,
            user_schemas: $user_schemas,
            schema_validation: $schema_validation,
            summary: {
              operation_count: (($operations.result // []) | length),
              discovery_operation_count: (($discovery_operations.result // []) | length),
              discovered_schema_count: (($discovery_schema.result.schemas // []) | length),
              user_schema_count: (($user_schemas.result // []) | length),
              schema_validation_count: (($schema_validation.result // []) | length)
            }
          }
        ]
      ' \
      <<< "${ZONE_REPORTS}"
  )"
done < <(jq -c '.[]' <<< "${ACTIVE_ZONES}")

OUTPUT_FILE="$(cf_inventory_file "account" "api-shield")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson zones "${ZONE_REPORTS}" \
    '
      {
        generated_at: $generated_at,
        zones: $zones,
        summary: {
          zone_count: ($zones | length),
          readable_zone_count: (
            $zones
            | map(select(
                (.operations.success == true)
                and (.discovery_operations.success == true)
                and (.user_schemas.success == true)
                and (.schema_validation.success == true)
              ))
            | length
          ),
          managed_operation_count: ($zones | map(.summary.operation_count) | add),
          discovered_operation_count: ($zones | map(.summary.discovery_operation_count) | add),
          discovered_schema_count: ($zones | map(.summary.discovered_schema_count) | add),
          user_schema_count: ($zones | map(.summary.user_schema_count) | add),
          schema_validation_count: ($zones | map(.summary.schema_validation_count) | add)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured API Shield inventory."
echo "${REPORT_JSON}" | jq '{
  zone_count: .summary.zone_count,
  readable_zone_count: .summary.readable_zone_count,
  managed_operation_count: .summary.managed_operation_count,
  discovered_operation_count: .summary.discovered_operation_count,
  discovered_schema_count: .summary.discovered_schema_count,
  user_schema_count: .summary.user_schema_count,
  schema_validation_count: .summary.schema_validation_count
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
