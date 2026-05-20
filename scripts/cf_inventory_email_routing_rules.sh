#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_setup_log_pipe "inventory-email-routing-rules" "build"

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

ROUTING_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/email/routing")"
RULES_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/email/routing/rules")"
OUTPUT_FILE="$(cf_inventory_file "email-routing" "email-routing-rules")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg zone_id "${ZONE_ID}" \
    --arg zone_name "${ZONE_NAME}" \
    --argjson routing "${ROUTING_JSON}" \
    --argjson rules "${RULES_JSON}" \
    '
      {
        generated_at: $generated_at,
        zone: {
          id: $zone_id,
          name: $zone_name
        },
        email_routing: $routing,
        rules: $rules,
        summary: {
          routing_readable: ($routing.success // false),
          routing_status: ($routing.result.status // "unknown"),
          routing_enabled: ($routing.result.enabled // false),
          rules_readable: ($rules.success // false),
          rule_count: (($rules.result // []) | length),
          recipients: (
            ($rules.result // [])
            | map([.matchers[]? | select(.field == "to") | .value][0] // null)
            | map(select(. != null))
            | sort
          )
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Email Routing rules for ${ZONE_NAME}."
echo "${REPORT_JSON}" | jq '.summary'
cf_print_log_footer
echo "${OUTPUT_FILE}"
