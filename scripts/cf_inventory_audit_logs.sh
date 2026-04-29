#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-audit-logs" "build"

AUDIT_LOGS_SINCE="${AUDIT_LOGS_SINCE:-}"
AUDIT_LOGS_BEFORE="${AUDIT_LOGS_BEFORE:-}"
AUDIT_LOGS_ACTOR="${AUDIT_LOGS_ACTOR:-}"
AUDIT_LOGS_ACTION_TYPE="${AUDIT_LOGS_ACTION_TYPE:-}"
AUDIT_LOGS_RESOURCE_TYPE="${AUDIT_LOGS_RESOURCE_TYPE:-}"
AUDIT_LOGS_LIMIT="${AUDIT_LOGS_LIMIT:-50}"

if [[ -z "${AUDIT_LOGS_SINCE}" ]]; then
  AUDIT_LOGS_SINCE="$(jq -nr '((now - 86400) | strftime("%Y-%m-%dT%H:%M:%SZ"))')"
fi

if [[ -z "${AUDIT_LOGS_BEFORE}" ]]; then
  AUDIT_LOGS_BEFORE="$(jq -nr '(now | strftime("%Y-%m-%dT%H:%M:%SZ"))')"
fi

if ! jq -en --arg limit "${AUDIT_LOGS_LIMIT}" '$limit | test("^[0-9]+$") and (($limit | tonumber) >= 1) and (($limit | tonumber) <= 1000)' >/dev/null; then
  echo "AUDIT_LOGS_LIMIT must be an integer from 1 to 1000." >&2
  exit 1
fi

QUERY_JSON="$(
  jq -n \
    --arg since "${AUDIT_LOGS_SINCE}" \
    --arg before "${AUDIT_LOGS_BEFORE}" \
    --arg limit "${AUDIT_LOGS_LIMIT}" \
    '
      {
        since: $since,
        before: $before,
        limit: $limit
      }
      | with_entries(select(.value != ""))
    '
)"

QUERY_STRING="$(jq -r 'to_entries | map(.key + "=" + (.value | @uri)) | join("&")' <<< "${QUERY_JSON}")"
AUDIT_LOGS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/logs/audit?${QUERY_STRING}")"

OUTPUT_FILE="$(cf_inventory_file "account" "audit-logs")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson query "${QUERY_JSON}" \
    --argjson response "${AUDIT_LOGS_JSON}" \
    --arg actor "${AUDIT_LOGS_ACTOR}" \
    --arg action_type "${AUDIT_LOGS_ACTION_TYPE}" \
    --arg resource_type "${AUDIT_LOGS_RESOURCE_TYPE}" \
    '
      ($response.result // []) as $events
      | {
          generated_at: $generated_at,
          query: $query,
          local_filters: {
            actor: (if $actor == "" then null else $actor end),
            action_type: (if $action_type == "" then null else $action_type end),
            resource_type: (if $resource_type == "" then null else $resource_type end)
          } | with_entries(select(.value != null)),
          response: $response,
          events: $events,
          summary: {
            readable: ($response.success // false),
            status_code: ($response.status_code // null),
            event_count: ($events | length),
            action_types: ($events | map(.action.type // .action // empty) | unique | sort),
            actor_emails: ($events | map(.actor.email // empty) | unique | sort),
            resource_types: ($events | map(.resource.type // .resource_type // empty) | unique | sort)
          }
        }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured account audit log inventory."
echo "${REPORT_JSON}" | jq '{
  readable: .summary.readable,
  status_code: .summary.status_code,
  event_count: .summary.event_count,
  action_types: .summary.action_types,
  resource_types: .summary.resource_types
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
