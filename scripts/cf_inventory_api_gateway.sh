#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-api-gateway" "build"

ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"
API_GATEWAY_RESOURCE="${API_GATEWAY_RESOURCE:-operations}"

if [[ -z "${ZONE_ID}" ]]; then
  if [[ -z "${ZONE_NAME}" ]]; then
    echo "ZONE_NAME or ZONE_ID must be set for API Gateway inventory." >&2
    exit 1
  fi
  ZONE_ID="$(cf_resolve_zone_id "${ZONE_NAME}")"
fi

if [[ -z "${ZONE_NAME}" ]]; then
  ZONE_NAME="$(cf_api GET "/zones/${ZONE_ID}" | jq -r '.result.name // empty')"
fi

case "${API_GATEWAY_RESOURCE}" in
  operations)
    RAW_JSON="$(cf_api GET "/zones/${ZONE_ID}/api_gateway/operations?per_page=100")"
    OUTPUT_FILE="$(cf_inventory_file "api-gateway" "operations")"
    REPORT_JSON="$(
      jq -n \
        --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg zone_id "${ZONE_ID}" \
        --arg zone_name "${ZONE_NAME}" \
        --argjson response "${RAW_JSON}" \
        '
          def normalize_operation:
            if ((.id // "") == "" and (.operation_id // "") != "") then
              . + {id: .operation_id}
            else
              .
            end;

          {
            generated_at: $generated_at,
            resource: "operations",
            zone: {
              id: $zone_id,
              name: $zone_name
            },
            response: $response,
            operations: [
              ($response.result // [])[]
              | normalize_operation
            ],
            summary: {
              operation_count: (($response.result // []) | length),
              hosts: (($response.result // []) | map(.host // empty) | unique | sort),
              methods: (($response.result // []) | map(.method // empty) | unique | sort)
            }
          }
        '
    )"
    ;;
  schemas)
    RAW_JSON="$(cf_api GET "/zones/${ZONE_ID}/api_gateway/schemas")"
    OUTPUT_FILE="$(cf_inventory_file "api-gateway" "schemas")"
    REPORT_JSON="$(
      jq -n \
        --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg zone_id "${ZONE_ID}" \
        --arg zone_name "${ZONE_NAME}" \
        --argjson response "${RAW_JSON}" \
        '
          def schema_host:
            (((.servers // [])[0].url // "")
            | sub("^https?://"; "")
            | split("/")[0]) // "";

          {
            generated_at: $generated_at,
            resource: "schemas",
            zone: {
              id: $zone_id,
              name: $zone_name
            },
            response: $response,
            schemas: [
              ($response.result.schemas // [] | to_entries[])
              | .key as $idx
              | .value as $schema
              | ($schema | schema_host) as $host
              | {
                  id: (
                    $schema.id
                    // $schema.schema_id
                    // (((if $host != "" then $host elif (($schema.info.title // "") != "") then $schema.info.title else "schema" end) + "#" + ($idx | tostring)))
                  ),
                  host: $host,
                  title: ($schema.info.title // null),
                  version: ($schema.info.version // null),
                  server_urls: (($schema.servers // []) | map(.url // empty)),
                  path_count: (($schema.paths // {}) | keys | length),
                  schema: $schema
                }
            ],
            summary: {
              schema_count: (($response.result.schemas // []) | length),
              hosts: [
                ($response.result.schemas // [])[]
                | schema_host
                | select(. != "")
              ] | unique | sort
            }
          }
        '
    )"
    ;;
  discovery)
    RAW_JSON="$(cf_api GET "/zones/${ZONE_ID}/api_gateway/discovery")"
    OUTPUT_FILE="$(cf_inventory_file "api-gateway" "discovery")"
    REPORT_JSON="$(
      jq -n \
        --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg zone_id "${ZONE_ID}" \
        --arg zone_name "${ZONE_NAME}" \
        --argjson response "${RAW_JSON}" \
        '
          def schema_host:
            (((.servers // [])[0].url // "")
            | sub("^https?://"; "")
            | split("/")[0]) // "";

          {
            generated_at: $generated_at,
            resource: "discovery",
            zone: {
              id: $zone_id,
              name: $zone_name
            },
            response: $response,
            schemas: [
              ($response.result.schemas // [] | to_entries[])
              | .key as $idx
              | .value as $schema
              | ($schema | schema_host) as $host
              | {
                  id: (
                    $schema.id
                    // $schema.schema_id
                    // (((if $host != "" then $host elif (($schema.info.title // "") != "") then $schema.info.title else "discovered-schema" end) + "#" + ($idx | tostring)))
                  ),
                  host: $host,
                  title: ($schema.info.title // null),
                  version: ($schema.info.version // null),
                  path_count: (($schema.paths // {}) | keys | length),
                  schema: $schema
                }
            ],
            summary: {
              schema_count: (($response.result.schemas // []) | length),
              hosts: [
                ($response.result.schemas // [])[]
                | schema_host
                | select(. != "")
              ] | unique | sort
            }
          }
        '
    )"
    ;;
  *)
    echo "Unsupported API_GATEWAY_RESOURCE: ${API_GATEWAY_RESOURCE}" >&2
    exit 1
    ;;
esac

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured API Gateway ${API_GATEWAY_RESOURCE} inventory."
echo "${REPORT_JSON}" | jq '{
  resource,
  zone: .zone.name,
  summary
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
