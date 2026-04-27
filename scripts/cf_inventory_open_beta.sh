#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_setup_log_pipe "inventory-open-beta" "build"

run_capture() {
  local name="$1"
  shift
  local output
  output="$("$@" 2>&1)" || true
  jq -n --arg name "${name}" --arg output "${output}" '{name:$name, output:$output}'
}

PIPELINES="$(run_capture pipelines "${ROOT_DIR}/scripts/cf_wrangler.sh" pipelines list)"
VPC="$(run_capture vpc "${ROOT_DIR}/scripts/cf_wrangler.sh" vpc list)"
SECRETS_STORE="$(run_capture secrets_store "${ROOT_DIR}/scripts/cf_wrangler.sh" secrets-store store list)"
AI_SEARCH="$(run_capture ai_search "${ROOT_DIR}/scripts/cf_wrangler.sh" ai-search list)"
CONTAINERS="$(run_capture containers "${ROOT_DIR}/scripts/cf_wrangler.sh" containers list)"

OUTPUT_FILE="$(cf_inventory_file "account" "open-beta")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson pipelines "${PIPELINES}" \
    --argjson vpc "${VPC}" \
    --argjson secrets_store "${SECRETS_STORE}" \
    --argjson ai_search "${AI_SEARCH}" \
    --argjson containers "${CONTAINERS}" \
    '
      {
        generated_at: $generated_at,
        probes: [$pipelines, $vpc, $secrets_store, $ai_search, $containers]
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured open-beta surface probe outputs."
echo "${REPORT_JSON}" | jq '.probes'
cf_print_log_footer
echo "${OUTPUT_FILE}"
