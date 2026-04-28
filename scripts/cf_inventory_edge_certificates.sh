#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_setup_log_pipe "inventory-edge-certificates" "build"

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

certificate_packs="$(cf_api_capture GET "/zones/${ZONE_ID}/ssl/certificate_packs?status=all")"

OUTPUT_FILE="$(cf_inventory_file "account" "edge-certificates")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg zone_id "${ZONE_ID}" \
    --arg zone_name "${ZONE_NAME}" \
    --argjson certificate_packs "${certificate_packs}" \
    '
      {
        generated_at: $generated_at,
        zone: {
          id: $zone_id,
          name: $zone_name
        },
        certificate_packs: $certificate_packs,
        summary: {
          certificate_packs_readable: ($certificate_packs.success // false),
          certificate_pack_count: (($certificate_packs.result // []) | length)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured edge certificate inventory for ${ZONE_NAME}."
echo "${REPORT_JSON}" | jq '.summary'
cf_print_log_footer
echo "${OUTPUT_FILE}"
