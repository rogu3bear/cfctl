#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_setup_log_pipe "inventory-kv" "build"

RAW_JSON="$("${ROOT_DIR}/scripts/cf_wrangler.sh" kv namespace list)"
OUTPUT_FILE="$(cf_inventory_file "account" "kv-namespaces")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson namespaces "${RAW_JSON}" \
    '
      {
        generated_at: $generated_at,
        namespaces: $namespaces,
        summary: {
          namespace_count: ($namespaces | length),
          titles: ($namespaces | map(.title) | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured KV namespace inventory."
echo "${REPORT_JSON}" | jq '{
  namespace_count: .summary.namespace_count,
  titles: .summary.titles
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
