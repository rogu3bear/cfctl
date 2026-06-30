#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_setup_log_pipe "inventory-zone-settings" "build"

ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"
SETTING_NAME="${SETTING_NAME:-}"

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

if [[ -n "${SETTING_NAME}" ]]; then
  SETTINGS_RESPONSE="$(cf_api GET "/zones/${ZONE_ID}/settings/${SETTING_NAME}")"
  SETTINGS_JSON="$(
    jq '
      if (.success // false) then
        [ .result ]
      else
        []
      end
    ' <<< "${SETTINGS_RESPONSE}"
  )"
  ERRORS_JSON="$(jq '.errors // []' <<< "${SETTINGS_RESPONSE}")"
else
  SETTINGS_RESPONSE="$(cf_api GET "/zones/${ZONE_ID}/settings?per_page=200")"
  SETTINGS_JSON="$(jq '.result // []' <<< "${SETTINGS_RESPONSE}")"
  ERRORS_JSON="$(jq '.errors // []' <<< "${SETTINGS_RESPONSE}")"
fi

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg zone_id "${ZONE_ID}" \
    --arg zone_name "${ZONE_NAME}" \
    --arg setting_name "${SETTING_NAME}" \
    --argjson settings "${SETTINGS_JSON}" \
    --argjson errors "${ERRORS_JSON}" \
    '
      {
        generated_at: $generated_at,
        zone: {
          id: $zone_id,
          name: $zone_name
        },
        selector: ({
          setting: (if $setting_name == "" then null else $setting_name end)
        } | with_entries(select(.value != null))),
        settings: (
          $settings
          | map(. + {
              name: (.id // .name // null),
              zone_id: $zone_id,
              zone_name: $zone_name
            })
        ),
        errors: $errors,
        summary: {
          setting_count: ($settings | length),
          error_count: ($errors | length)
        }
      }
    '
)"

OUTPUT_FILE="$(cf_inventory_file "account" "zone-settings")"
cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured zone settings inventory."
echo "${REPORT_JSON}" | jq '{
  zone: .zone.name,
  setting_count: .summary.setting_count,
  error_count: .summary.error_count,
  sample_settings: (.settings | map({id, value, modified_on, editable})[:12])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
