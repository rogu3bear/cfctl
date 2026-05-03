#!/usr/bin/env bash

# Reads /accounts/:id/workers/scripts/:name/secrets and emits a
# normalized {secrets: [{name, type, script}]} payload that the cfctl
# runtime extracts via .secrets in cfctl_collect_surface_items. The CF
# API only returns the secret name + type — values are write-only.
# WORKER_SCRIPT (the parent script) is required.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-worker-secrets" "build"

WORKER_SCRIPT="${WORKER_SCRIPT:-}"
if [[ -z "${WORKER_SCRIPT}" ]]; then
  echo "WORKER_SCRIPT (the parent script name) must be set; pass --script <name>" >&2
  exit 1
fi

SECRETS_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${WORKER_SCRIPT}/secrets")"
OUTPUT_FILE="$(cf_inventory_file "worker-secrets" "${WORKER_SCRIPT}")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg script "${WORKER_SCRIPT}" \
    --argjson raw "${SECRETS_JSON}" \
    '
      ($raw.result // []) as $entries
      | {
          generated_at: $generated_at,
          script: $script,
          secrets: ($entries | map({
            name: .name,
            type: (.type // "secret_text"),
            script: $script
          })),
          summary: {
            secret_count: ($entries | length),
            secret_names: ($entries | map(.name) | sort)
          }
        }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured worker secrets inventory for script ${WORKER_SCRIPT}."
echo "${REPORT_JSON}" | jq '{
  script: .script,
  secret_count: .summary.secret_count,
  secret_names: (.summary.secret_names[:10])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
