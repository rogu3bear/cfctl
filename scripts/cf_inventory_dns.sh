#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-dns" "build"

ZONE_NAME="${ZONE_NAME:-}"
ZONE_NAMES_JSON="${ZONE_NAMES_JSON:-[]}"
INCLUDE_RECORDS="${INCLUDE_RECORDS:-1}"

ZONES_JSON="$(cf_api GET "/zones?per_page=100&page=1&account.id=${CLOUDFLARE_ACCOUNT_ID}")"
SELECTED_ZONES="$(
  jq \
    --arg zone_name "${ZONE_NAME}" \
    --argjson zone_names "${ZONE_NAMES_JSON}" \
    '
      [
        (.result // [])[]
        | select(
            if ($zone_name | length) > 0 then
              .name == $zone_name
            elif ($zone_names | length) > 0 then
              ($zone_names | index(.name)) != null
            else
              true
            end
          )
        | {id, name}
      ]
    ' \
    <<< "${ZONES_JSON}"
)"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg include_records "${INCLUDE_RECORDS}" \
    --argjson zones "${SELECTED_ZONES}" \
    '
      {
        generated_at: $generated_at,
        include_records: ($include_records == "1"),
        zones: ($zones | map(. + {dns: {record_count: 0, counts_by_type: [], records: []}}))
      }
    '
)"

while IFS= read -r zone_row; do
  zone_id="$(jq -r '.id' <<< "${zone_row}")"
  zone_name="$(jq -r '.name' <<< "${zone_row}")"
  echo "Fetching DNS records for ${zone_name}"
  tmp_body="$(mktemp)"
  cf_build_curl_auth_args
  status_code="$(
    curl -sS \
      "${CF_CURL_AUTH_ARGS[@]}" \
      -o "${tmp_body}" \
      -w '%{http_code}' \
      "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?per_page=5000"
  )"

  if [[ "${status_code}" == "200" ]]; then
    records_json="$(cat "${tmp_body}")"
  else
    records_json="$(
      jq -n \
        --arg status_code "${status_code}" \
        --arg zone_id "${zone_id}" \
        --arg zone_name "${zone_name}" \
        --arg body "$(cat "${tmp_body}")" \
        '
          {
            success: false,
            errors: [
              {
                status_code: ($status_code | tonumber),
                zone_id: $zone_id,
                zone_name: $zone_name,
                body: $body
              }
            ],
            result: []
          }
        '
    )"
  fi
  rm -f "${tmp_body}"

  REPORT_JSON="$(
    jq \
      --arg zone_id "${zone_id}" \
      --arg include_records "${INCLUDE_RECORDS}" \
      --argjson records "${records_json}" \
      '
        .zones |= map(
          if .id == $zone_id then
            . + {
              dns: {
                success: ($records.success // false),
                record_count: (($records.result // []) | length),
                counts_by_type: (
                  ($records.result // [])
                  | map(.type)
                  | group_by(.)
                  | map({type: .[0], count: length})
                ),
                errors: ($records.errors // []),
                records: (
                  if $include_records == "1" then
                    ($records.result // [])
                  else
                    []
                  end
                )
              }
            }
          else
            .
          end
        )
      ' \
      <<< "${REPORT_JSON}"
  )"
done < <(jq -c '.[]' <<< "${SELECTED_ZONES}")

OUTPUT_FILE="$(cf_inventory_file "account" "dns")"
cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured DNS inventory."
echo "${REPORT_JSON}" | jq '{
  zone_count: (.zones | length),
  dns_success_count: (.zones | map(select(.dns.success == true)) | length),
  dns_error_count: (.zones | map(select((.dns.errors | length) > 0)) | length),
  zones: (.zones | map({name, success: .dns.success, record_count: .dns.record_count, counts_by_type: .dns.counts_by_type, errors: .dns.errors})[:10])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
