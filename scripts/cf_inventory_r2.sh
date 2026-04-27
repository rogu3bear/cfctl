#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq awk
cf_require_api_auth
cf_setup_log_pipe "inventory-r2" "build"

RAW_TEXT="$("${ROOT_DIR}/scripts/cf_wrangler.sh" r2 bucket list)"
PARSED_JSON="$(
  printf '%s\n' "${RAW_TEXT}" \
    | awk -F': *' '
        /^name:/ { name=$2 }
        /^creation_date:/ { print name "\t" $2 }
      ' \
    | jq -R -s '
        split("\n")
        | map(select(length > 0))
        | map(split("\t"))
        | map({name: .[0], creation_date: .[1]})
      '
)"

OUTPUT_FILE="$(cf_inventory_file "account" "r2-buckets")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg raw_text "${RAW_TEXT}" \
    --argjson buckets "${PARSED_JSON}" \
    '
      {
        generated_at: $generated_at,
        buckets: $buckets,
        raw_text: $raw_text,
        summary: {
          bucket_count: ($buckets | length),
          names: ($buckets | map(.name) | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured R2 bucket inventory."
echo "${REPORT_JSON}" | jq '{
  bucket_count: .summary.bucket_count,
  names: .summary.names
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
