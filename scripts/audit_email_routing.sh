#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "email-routing-audit" "build"

EXCLUDE_REGEX="${EXCLUDE_REGEX:-^$}"
LOG_FILE="$(cf_inventory_file "email-routing" "email-routing-audit")"

fetch_json() {
  local url="$1"
  local scope="$2"
  local tmp_body
  tmp_body="$(mktemp)"

  cf_build_curl_auth_args

  local status_code
  status_code="$(
    curl -sS \
      "${CF_CURL_AUTH_ARGS[@]}" \
      -o "${tmp_body}" \
      -w '%{http_code}' \
      "${url}"
  )"

  if [[ "${status_code}" == "200" ]]; then
    cat "${tmp_body}"
  else
    jq -n \
      --arg scope "${scope}" \
      --arg status_code "${status_code}" \
      --arg body "$(cat "${tmp_body}")" \
      '
        {
          success: false,
          errors: [
            {
              scope: $scope,
              status_code: ($status_code | tonumber),
              body: $body
            }
          ],
          result: []
        }
      '
  fi

  rm -f "${tmp_body}"
}

ZONES_JSON="$(
  cf_api GET "/zones?per_page=100&page=1" \
  | jq --arg exclude_regex "${EXCLUDE_REGEX}" '
      [
        .result[]
        | select(.name | test($exclude_regex; "i") | not)
        | {id, name}
      ]
    '
)"

DESTINATIONS_JSON="$(
  fetch_json "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/email/routing/addresses" "account.destination_addresses" \
  | jq '
      {
        success,
        errors: (.errors // []),
        result: [
          .result[]
          | {email, verified, created}
        ]
      }
    '
)"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg exclude_regex "${EXCLUDE_REGEX}" \
    --argjson destinations "${DESTINATIONS_JSON}" \
    --argjson zones "${ZONES_JSON}" \
    '
      {
        generated_at: $generated_at,
        exclude_regex: $exclude_regex,
        destination_addresses: $destinations,
        zones: $zones
      }
    '
)"

for row in $(echo "${ZONES_JSON}" | jq -r '.[] | @base64'); do
  _jq() {
    echo "${row}" | base64 --decode | jq -r "$1"
  }

  zone_id="$(_jq '.id')"
  zone_name="$(_jq '.name')"

  routing_json="$(
    fetch_json "https://api.cloudflare.com/client/v4/zones/${zone_id}/email/routing" "zone.routing:${zone_name}"
  )"

  rules_json="$(
    fetch_json "https://api.cloudflare.com/client/v4/zones/${zone_id}/email/routing/rules" "zone.rules:${zone_name}"
  )"

  REPORT_JSON="$(
    jq \
      --arg zone_name "${zone_name}" \
      --arg zone_id "${zone_id}" \
      --argjson routing "${routing_json}" \
      --argjson rules "${rules_json}" \
      '
        .zones |= map(
          if .id == $zone_id then
            . + {
              email_routing: {
                success: ($routing.success // false),
                enabled: (if (($routing.result | type) == "object") then ($routing.result.enabled // false) else false end),
                status: (if (($routing.result | type) == "object") then ($routing.result.status // "unknown") else "unknown" end),
                errors: (
                  ($routing.errors // [])
                  + (
                    if (($routing.result | type) == "object") then
                      ($routing.result.errors // [])
                    else
                      []
                    end
                  )
                )
              },
              rules: ($rules.result // []),
              rule_errors: ($rules.errors // [])
            }
          else
            .
          end
        )
      ' \
      <<< "${REPORT_JSON}"
  )"
done

echo "${REPORT_JSON}" | jq '.' > "${LOG_FILE}"
echo "${REPORT_JSON}" | jq '{
  generated_at,
  zone_count: (.zones | length),
  ready_zone_count: (.zones | map(select(.email_routing.status == "ready")) | length),
  destination_count: (.destination_addresses.result | length),
  destination_error_count: (.destination_addresses.errors | length),
  zone_permission_error_count: (.zones | map(select((.rule_errors | length) > 0 or (.email_routing.success == false))) | length)
}'
cf_print_log_footer
echo "${LOG_FILE}"
