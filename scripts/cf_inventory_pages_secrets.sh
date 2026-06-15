#!/usr/bin/env bash

# Reads /accounts/:id/pages/projects/:project and emits a normalized
# {secrets: [{name, type, environment, project}]} payload listing only the
# env_vars of type secret_text (values are write-only). Extracted via .secrets
# in cfctl_collect_surface_items. PAGES_PROJECT is required (--project).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-pages-secrets" "build"

PAGES_PROJECT="${PAGES_PROJECT:-}"
if [[ -z "${PAGES_PROJECT}" ]]; then
  echo "PAGES_PROJECT (the Pages project name) must be set; pass --project <name>" >&2
  exit 1
fi

PROJECT_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/pages/projects/${PAGES_PROJECT}")"
OUTPUT_FILE="$(cf_inventory_file "pages-secrets" "${PAGES_PROJECT}")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg project "${PAGES_PROJECT}" \
    --argjson raw "${PROJECT_JSON}" \
    '
      ($raw.result.deployment_configs // {}) as $dc
      | {
          generated_at: $generated_at,
          project: $project,
          secrets: ([
            $dc | to_entries[] | .key as $env
            | ((.value.env_vars // {}) | to_entries[]
               | select(.value.type == "secret_text")
               | {name: .key, type: .value.type, environment: $env, project: $project})
          ]),
          summary: {
            secret_count: ([
              $dc | to_entries[] | (.value.env_vars // {}) | to_entries[]
              | select(.value.type == "secret_text")
            ] | length)
          }
        }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Pages secrets inventory for project ${PAGES_PROJECT}."
echo "${REPORT_JSON}" | jq '{
  project: .project,
  secret_count: .summary.secret_count,
  secrets: [.secrets[] | {name, environment}]
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
