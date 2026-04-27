#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq awk sed
cf_require_api_auth
cf_setup_log_pipe "inventory-secrets-store" "build"

RAW_OUTPUT="$("${ROOT_DIR}/scripts/cf_wrangler.sh" secrets-store store list --remote 2>&1 || true)"
PARSED_JSON="$(
  printf '%s\n' "${RAW_OUTPUT}" \
    | sed $'s/\033\\[[0-9;]*[A-Za-z]//g' \
    | awk -F'│' '
        /^│/ {
          name=$2; id=$3; account_id=$4; created=$5; modified=$6
          gsub(/^ +| +$/, "", name)
          gsub(/^ +| +$/, "", id)
          gsub(/^ +| +$/, "", account_id)
          gsub(/^ +| +$/, "", created)
          gsub(/^ +| +$/, "", modified)
          if (name != "" && name != "Name") {
            printf "%s\t%s\t%s\t%s\t%s\n", name, id, account_id, created, modified
          }
        }
      ' \
    | jq -R -s '
        split("\n")
        | map(select(length > 0))
        | map(split("\t"))
        | map({
            name: .[0],
            id: .[1],
            account_id: .[2],
            created: .[3],
            modified: .[4]
          })
      '
)"

OUTPUT_FILE="$(cf_inventory_file "account" "secrets-store")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg raw_output "${RAW_OUTPUT}" \
    --argjson stores "${PARSED_JSON}" \
    '
      {
        generated_at: $generated_at,
        stores: $stores,
        raw_output: $raw_output,
        summary: {
          store_count: ($stores | length),
          names: ($stores | map(.name) | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Secrets Store inventory."
echo "${REPORT_JSON}" | jq '{
  store_count: .summary.store_count,
  names: .summary.names
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
