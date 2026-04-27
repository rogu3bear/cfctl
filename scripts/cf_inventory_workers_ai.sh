#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq awk sed
cf_require_api_auth
cf_setup_log_pipe "inventory-workers-ai" "build"

latest_topology_file() {
  find "${ROOT_DIR}/var/inventory/workers" -type f -name 'worker-topology-*.json' | sort | tail -n 1
}

TOPOLOGY_FILE="$(latest_topology_file)"
if [[ -z "${TOPOLOGY_FILE}" ]]; then
  TOPOLOGY_FILE="$("${ROOT_DIR}/scripts/cf_inventory_worker_topology.sh" | tail -n 1)"
fi

TOPOLOGY_JSON="$(jq '.' "${TOPOLOGY_FILE}")"
AI_MODELS_RAW="$("${ROOT_DIR}/scripts/cf_wrangler.sh" ai models 2>&1 || true)"
AI_MODELS_PARSED="$(
  printf '%s\n' "${AI_MODELS_RAW}" \
    | sed $'s/\033\\[[0-9;]*[A-Za-z]//g' \
    | awk -F'│' '
        /^│/ {
          model_id=$2; model_name=$3; task=$5
          gsub(/^ +| +$/, "", model_id)
          gsub(/^ +| +$/, "", model_name)
          gsub(/^ +| +$/, "", task)
          if (model_id != "" && model_id != "model") {
            printf "%s\t%s\t%s\n", model_id, model_name, task
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
            task: .[2]
          })
      '
)"

OUTPUT_FILE="$(cf_inventory_file "workers" "workers-ai")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg topology_file "${TOPOLOGY_FILE}" \
    --arg raw_models "${AI_MODELS_RAW}" \
    --argjson topology "${TOPOLOGY_JSON}" \
    --argjson models "${AI_MODELS_PARSED}" \
    '
      {
        generated_at: $generated_at,
        source_worker_topology_file: $topology_file,
        model_catalog: $models,
        raw_model_catalog_output: $raw_models,
        worker_ai_usage: (
          $topology.summary.scripts_with_ai_related_bindings
          // []
        ),
        summary: {
          worker_ai_binding_script_count: (($topology.summary.scripts_with_ai_related_bindings // []) | length),
          worker_ai_binding_scripts: (($topology.summary.scripts_with_ai_related_bindings // []) | map(.script_name) | sort),
          catalog_model_count: ($models | length),
          catalog_task_counts: (
            $models
            | map(.task)
            | group_by(.)
            | map({task: .[0], count: length})
          )
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Workers AI posture."
echo "${REPORT_JSON}" | jq '{
  worker_ai_binding_script_count: .summary.worker_ai_binding_script_count,
  worker_ai_binding_scripts: .summary.worker_ai_binding_scripts,
  catalog_model_count: .summary.catalog_model_count,
  catalog_task_counts: (.summary.catalog_task_counts[:12])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
