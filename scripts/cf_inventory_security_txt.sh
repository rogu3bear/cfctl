#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-security-txt" "build"

ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"

if [[ -z "${ZONE_ID}" ]]; then
  if [[ -z "${ZONE_NAME}" ]]; then
    echo "ZONE_NAME or ZONE_ID must be set" >&2
    exit 1
  fi
  ZONE_ID="$(cf_resolve_zone_id "${ZONE_NAME}")"
fi

if [[ -z "${ZONE_ID}" || "${ZONE_ID}" == "null" ]]; then
  echo "Unable to resolve zone" >&2
  exit 1
fi

if [[ -z "${ZONE_NAME}" ]]; then
  ZONE_NAME="$(cf_api GET "/zones/${ZONE_ID}" | jq -r '.result.name // empty')"
fi

SECURITY_TXT_RESPONSE="$(cf_api_capture GET "/zones/${ZONE_ID}/security-center/securitytxt")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg zone_id "${ZONE_ID}" \
    --arg zone_name "${ZONE_NAME}" \
    --argjson response "${SECURITY_TXT_RESPONSE}" \
    '
      {
        generated_at: $generated_at,
        zone: {
          id: $zone_id,
          name: $zone_name
        },
        security_txt: (
          if ($response.success // false) and (($response.result | type) == "object") then
            [
              ($response.result + {
                zone_id: $zone_id,
                zone_name: $zone_name
              })
            ]
          else
            []
          end
        ),
        errors: ($response.errors // []),
        messages: ($response.messages // []),
        summary: {
          configured: (($response.success // false) and (($response.result | type) == "object")),
          enabled: (
            if (($response.result | type) == "object") then
              ($response.result.enabled // false)
            else
              false
            end
          ),
          contact_count: (
            if (($response.result | type) == "object") then
              (($response.result.contact // []) | length)
            else
              0
            end
          ),
          error_count: (($response.errors // []) | length)
        }
      }
    '
)"

OUTPUT_FILE="$(cf_inventory_file "account" "security-txt")"
cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured security.txt inventory."
echo "${REPORT_JSON}" | jq '{
  zone: .zone.name,
  configured: .summary.configured,
  enabled: .summary.enabled,
  contact_count: .summary.contact_count,
  error_count: .summary.error_count
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
