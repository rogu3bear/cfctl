#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_setup_log_pipe "inventory-sender-domains" "build"

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

SUBDOMAINS_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/email/sending/subdomains")"
OUTPUT_FILE="$(cf_inventory_file "email-sending" "sender-domains")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg zone_id "${ZONE_ID}" \
    --arg zone_name "${ZONE_NAME}" \
    --argjson subdomains "${SUBDOMAINS_JSON}" \
    '
      ($subdomains.result // []) as $items
      | {
          generated_at: $generated_at,
          zone: {
            id: $zone_id,
            name: $zone_name
          },
          sender_domains: (
            $items
            | map(
                . + {
                  zone_id: $zone_id,
                  zone_name: $zone_name,
                  domain: (.name // null),
                  provider: "cloudflare_email_service",
                  verified: (.enabled // false),
                  status: (if (.enabled // false) then "verified" else "pending" end)
                }
              )
          ),
          response: $subdomains,
          summary: {
            readable: ($subdomains.success // false),
            sender_domain_count: ($items | length),
            verified_count: ($items | map(select(.enabled == true)) | length),
            names: ($items | map(.name // .id // null) | map(select(. != null)) | sort),
            error_count: (($subdomains.errors // []) | length)
          }
        }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Email Sending sender domains for ${ZONE_NAME}."
echo "${REPORT_JSON}" | jq '.summary'
cf_print_log_footer
echo "${OUTPUT_FILE}"
