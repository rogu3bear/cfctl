#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-load-balancing" "build"

LBS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/load_balancers")"
POOLS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/load_balancers/pools")"
MONITORS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/load_balancers/monitors")"

OUTPUT_FILE="$(cf_inventory_file "account" "load-balancing")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson load_balancers "${LBS_JSON}" \
    --argjson pools "${POOLS_JSON}" \
    --argjson monitors "${MONITORS_JSON}" \
    '
      {
        generated_at: $generated_at,
        load_balancers: $load_balancers,
        pools: $pools,
        monitors: $monitors,
        summary: {
          load_balancer_count: (($load_balancers.result // []) | length),
          pool_count: (($pools.result // []) | length),
          monitor_count: (($monitors.result // []) | length)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured load balancing inventory."
echo "${REPORT_JSON}" | jq '{
  load_balancer_count: .summary.load_balancer_count,
  pool_count: .summary.pool_count,
  monitor_count: .summary.monitor_count
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
