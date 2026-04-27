#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq awk
cf_require_api_auth
cf_setup_log_pipe "inventory-containers" "build"

RAW_OUTPUT="$("${ROOT_DIR}/scripts/cf_wrangler.sh" containers list 2>&1)"
PARSED_JSON="$(
  printf '%s\n' "${RAW_OUTPUT}" \
    | awk -F'│' '
        /^│/ {
          id=$2; name=$3; state=$4; live=$5; modified=$6
          gsub(/^ +| +$/, "", id)
          gsub(/^ +| +$/, "", name)
          gsub(/^ +| +$/, "", state)
          gsub(/^ +| +$/, "", live)
          gsub(/^ +| +$/, "", modified)
          if (id != "" && id != "ID") {
            printf "%s\t%s\t%s\t%s\t%s\n", id, name, state, live, modified
          }
        }
      ' \
    | jq -R -s '
        split("\n")
        | map(select(length > 0))
        | map(split("\t"))
        | map({
            id: .[0],
            name: .[1],
            state: .[2],
            live_instances: (.[3] | tonumber),
            last_modified: .[4]
          })
      '
)"

OUTPUT_FILE="$(cf_inventory_file "account" "containers")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg raw_output "${RAW_OUTPUT}" \
    --argjson containers "${PARSED_JSON}" \
    '
      {
        generated_at: $generated_at,
        containers: $containers,
        raw_output: $raw_output,
        summary: {
          container_count: ($containers | length),
          active_or_ready_count: ($containers | map(select(.state == "active" or .state == "ready")) | length),
          degraded_count: ($containers | map(select(.state == "degraded" or .state == "provisioning")) | length),
          names: ($containers | map(.name) | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured containers inventory."
echo "${REPORT_JSON}" | jq '{
  container_count: .summary.container_count,
  active_or_ready_count: .summary.active_or_ready_count,
  degraded_count: .summary.degraded_count,
  names: (.summary.names[:20])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
