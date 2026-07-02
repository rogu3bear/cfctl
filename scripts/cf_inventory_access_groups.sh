#!/usr/bin/env bash

# Reads /accounts/:id/access/groups and emits a normalized
# {groups: [{id, name, ...}]} payload that the cfctl runtime extracts via
# .groups in cfctl_collect_surface_items. Rule structures (include/exclude/
# require) are carried verbatim: they describe policy shape, not secrets.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-access-groups" "build"

GROUPS_JSON="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/groups")"
OUTPUT_FILE="$(cf_inventory_file "access" "access-groups")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson raw "${GROUPS_JSON}" \
    '
      ($raw.result // []) as $entries
      | {
          generated_at: $generated_at,
          groups: ($entries | map({
            id: .id,
            name: (.name // null),
            include: (.include // []),
            exclude: (.exclude // []),
            require: (.require // []),
            created_at: (.created_at // null),
            updated_at: (.updated_at // null)
          })),
          summary: {
            group_count: ($entries | length),
            group_names: ($entries | map(.name // "unnamed") | sort)
          }
        }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Access group inventory."
echo "${REPORT_JSON}" | jq '{
  group_count: .summary.group_count,
  group_names: (.summary.group_names[:20])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
