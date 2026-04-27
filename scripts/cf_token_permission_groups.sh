#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id

usage() {
  cat <<'EOF'
Usage:
  cfctl token permission-groups [--name <filter>] [--scope <scope>]

Examples:
  cfctl token permission-groups
  cfctl token permission-groups --name "DNS"
  cfctl token permission-groups --scope com.cloudflare.api.account.zone
EOF
}

NAME_FILTER=""
SCOPE_FILTER=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --name)
      NAME_FILTER="$2"
      shift 2
      ;;
    --name=*)
      NAME_FILTER="${1#*=}"
      shift
      ;;
    --scope)
      SCOPE_FILTER="$2"
      shift 2
      ;;
    --scope=*)
      SCOPE_FILTER="${1#*=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

encode_uri_component() {
  jq -rn --arg value "$1" '$value|@uri'
}

query_string=""
if [[ -n "${SCOPE_FILTER}" ]]; then
  query_string="?scope=$(encode_uri_component "${SCOPE_FILTER}")"
fi

capture_json="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/permission_groups${query_string}")"
artifact_path="$(cf_inventory_file "auth" "token-permission-groups")"

filtered_capture_json="${capture_json}"
if [[ -n "${NAME_FILTER}" ]]; then
  filtered_capture_json="$(
    jq \
      --arg needle "$(printf '%s' "${NAME_FILTER}" | tr '[:upper:]' '[:lower:]')" \
      '
        .result = [
          (.result // [])[]
          | select((.name | ascii_downcase) | contains($needle))
        ]
      ' <<< "${capture_json}"
  )"
fi

result_json="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg scheme "${CF_ACTIVE_AUTH_SCHEME:-unknown}" \
    --arg credential_env "${CF_ACTIVE_TOKEN_ENV:-unknown}" \
    --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" \
    --arg name_filter "${NAME_FILTER}" \
    --arg scope_filter "${SCOPE_FILTER}" \
    --arg artifact_path "${artifact_path}" \
    --argjson capture "${filtered_capture_json}" \
    '
      {
        generated_at: $generated_at,
        ok: ($capture.success // false),
        action: "token.permission-groups",
        auth: {
          lane: $lane,
          scheme: $scheme,
          credential_env: $credential_env
        },
        account_id: $account_id,
        filters: {
          name: (if $name_filter == "" then null else $name_filter end),
          scope: (if $scope_filter == "" then null else $scope_filter end)
        },
        artifact_path: $artifact_path,
        result: {
          count: (($capture.result // []) | length),
          permission_groups: ($capture.result // [])
        },
        error: (
          if ($capture.success // false) then
            null
          else
            {
              status_code: ($capture.status_code // null),
              errors: ($capture.errors // []),
              request: ($capture.request // null)
            }
          end
        )
      }
    '
)"

cf_write_json_file "${artifact_path}" "${result_json}"
jq '.' <<< "${result_json}"

if [[ "$(jq -r '.ok' <<< "${result_json}")" != "true" ]]; then
  exit 1
fi
