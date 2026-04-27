#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-tunnels" "build"

INCLUDE_CONFIG="${INCLUDE_CONFIG:-0}"
TUNNELS_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel")"
CONFIGS_JSON='[]'

if [[ "${INCLUDE_CONFIG}" == "1" ]]; then
  CONFIGS_JSON="$(
    jq -n --argjson tunnels "${TUNNELS_JSON}" '
      ($tunnels.result // [])
      | map({id, name})
    '
  )"

  MERGED_CONFIGS='[]'
  while IFS= read -r tunnel_row; do
    tunnel_id="$(jq -r '.id' <<< "${tunnel_row}")"
    tunnel_name="$(jq -r '.name' <<< "${tunnel_row}")"
    tunnel_config="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${tunnel_id}/configurations")"
    MERGED_CONFIGS="$(
      jq \
        --arg tunnel_id "${tunnel_id}" \
        --arg tunnel_name "${tunnel_name}" \
        --argjson tunnel_config "${tunnel_config}" \
        '
          . + [
            {
              id: $tunnel_id,
              name: $tunnel_name,
              configuration: ($tunnel_config.result // null)
            }
          ]
        ' \
        <<< "${MERGED_CONFIGS}"
    )"
  done < <(jq -c '.[]' <<< "${CONFIGS_JSON}")
  CONFIGS_JSON="${MERGED_CONFIGS}"
fi

OUTPUT_FILE="$(cf_inventory_file "tunnels" "tunnels")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg include_config "${INCLUDE_CONFIG}" \
    --argjson tunnels "${TUNNELS_JSON}" \
    --argjson tunnel_configs "${CONFIGS_JSON}" \
    '
      {
        generated_at: $generated_at,
        tunnels: ($tunnels.result // []),
        tunnel_configurations: (if $include_config == "1" then $tunnel_configs else [] end),
        summary: {
          tunnel_count: (($tunnels.result // []) | length),
          tunnels: (
            ($tunnels.result // [])
            | map({
                id,
                name,
                status,
                remote_config,
                created_at,
                deleted_at
              })
          )
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured tunnel inventory."
echo "${REPORT_JSON}" | jq '{
  tunnel_count: .summary.tunnel_count,
  tunnels: (.summary.tunnels[:10])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
