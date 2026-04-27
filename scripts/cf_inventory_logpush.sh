#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-logpush" "build"

ACCOUNT_LOGPUSH_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/logpush/jobs")"
ZONES_JSON="$(cf_api GET "/zones?per_page=100&page=1&account.id=${CLOUDFLARE_ACCOUNT_ID}")"
ACTIVE_ZONES="$(jq '[.result[] | select(.status == "active") | {id, name}]' <<< "${ZONES_JSON}")"
ZONE_REPORTS='[]'

while IFS= read -r zone_row; do
  zone_id="$(jq -r '.id' <<< "${zone_row}")"
  zone_name="$(jq -r '.name' <<< "${zone_row}")"

  echo "Scanning Logpush jobs for ${zone_name}"
  zone_jobs="$(cf_api_capture GET "/zones/${zone_id}/logpush/jobs")"

  ZONE_REPORTS="$(
    jq \
      --arg zone_id "${zone_id}" \
      --arg zone_name "${zone_name}" \
      --argjson zone_jobs "${zone_jobs}" \
      '
        . + [
          {
            zone: {
              id: $zone_id,
              name: $zone_name
            },
            jobs: $zone_jobs,
            summary: {
              readable: ($zone_jobs.success // false),
              job_count: (($zone_jobs.result // []) | length)
            }
          }
        ]
      ' \
      <<< "${ZONE_REPORTS}"
  )"
done < <(jq -c '.[]' <<< "${ACTIVE_ZONES}")

OUTPUT_FILE="$(cf_inventory_file "account" "logpush")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson account_jobs "${ACCOUNT_LOGPUSH_JSON}" \
    --argjson zones "${ZONE_REPORTS}" \
    '
      {
        generated_at: $generated_at,
        account_jobs: $account_jobs,
        zones: $zones,
        summary: {
          account_job_count: (($account_jobs.result // []) | length),
          zone_count: ($zones | length),
          readable_zone_count: ($zones | map(select(.summary.readable == true)) | length),
          permission_error_count: ($zones | map(select(.summary.readable != true)) | length),
          zone_job_count: ($zones | map(.summary.job_count) | add),
          zones_with_jobs: ($zones | map(select(.summary.job_count > 0)) | map(.zone.name) | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Logpush inventory."
echo "${REPORT_JSON}" | jq '{
  account_job_count: .summary.account_job_count,
  zone_count: .summary.zone_count,
  readable_zone_count: .summary.readable_zone_count,
  permission_error_count: .summary.permission_error_count,
  zone_job_count: .summary.zone_job_count,
  zones_with_jobs: .summary.zones_with_jobs
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
