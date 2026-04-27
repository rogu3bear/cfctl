#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-worker-topology" "build"

SCRIPTS_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts")"
TOPOLOGY='[]'

while IFS= read -r row; do
  script_name="$(jq -r '.id' <<< "${row}")"
  echo "Fetching worker settings for ${script_name}"
  settings="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${script_name}/settings")"

  TOPOLOGY="$(
    jq \
      --arg script_name "${script_name}" \
      --argjson settings "${settings}" \
      '
        . + [
          {
            script_name: $script_name,
            status_code: $settings.status_code,
            success: ($settings.success // false),
            usage_model: ($settings.result.usage_model // null),
            compatibility_date: ($settings.result.compatibility_date // null),
            logpush: ($settings.result.logpush // false),
            observability: ($settings.result.observability // null),
            binding_types: (($settings.result.bindings // []) | map(.type)),
            bindings: ($settings.result.bindings // []),
            tags: ($settings.result.tags // [])
          }
        ]
      ' \
      <<< "${TOPOLOGY}"
  )"
done < <(jq -c '.result[]' <<< "${SCRIPTS_JSON}")

OUTPUT_FILE="$(cf_inventory_file "workers" "worker-topology")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson scripts "${TOPOLOGY}" \
    '
      {
        generated_at: $generated_at,
        scripts: $scripts,
        summary: {
          script_count: ($scripts | length),
          binding_type_counts: (
            $scripts
            | map(.binding_types[])
            | group_by(.)
            | map({type: .[0], count: length})
          ),
          scripts_with_durable_objects: (
            $scripts
            | map(select(.bindings | any(.type == "durable_object_namespace")))
            | map({
                script_name,
                durable_objects: (.bindings | map(select(.type == "durable_object_namespace") | {name, class_name, namespace_id}))
              })
          ),
          scripts_with_ai_related_bindings: (
            $scripts
            | map(
                . as $script
                | {
                    script_name: .script_name,
                    ai_related_bindings: (
                      .bindings
                      | map(select(
                          (.type == "ai")
                          or (.type == "vectorize")
                          or (.name | test("(^AI$|AI_|_AI$|_AI_|VECTORIZE|EMBED|MODEL)"; "i"))
                        ))
                      | map({name, type})
                    )
                  }
              )
            | map(select((.ai_related_bindings | length) > 0))
          ),
          scripts_with_logpush_enabled: (
            $scripts
            | map(select(.logpush == true))
            | map(.script_name)
          ),
          scripts_with_observability_enabled: (
            $scripts
            | map(select(.observability.enabled == true))
            | map(.script_name)
          )
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured worker topology inventory."
echo "${REPORT_JSON}" | jq '{
  script_count: .summary.script_count,
  binding_type_counts: .summary.binding_type_counts,
  durable_object_script_count: (.summary.scripts_with_durable_objects | length),
  ai_related_script_count: (.summary.scripts_with_ai_related_bindings | length),
  logpush_enabled_script_count: (.summary.scripts_with_logpush_enabled | length)
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
