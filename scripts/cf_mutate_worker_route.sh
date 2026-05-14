#!/usr/bin/env bash

# Mutates Worker routes through the Cloudflare Workers Routes API.
#
#   delete: DELETE /zones/:zone_id/workers/routes/:route_id
#
# Required env from cfctl:
#   OPERATION       delete
#   ZONE_NAME or ZONE_ID
#   ROUTE_ID or ROUTE_PATTERN

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_backend_dispatch "cfctl apply worker.route <operation> ..."

OPERATION="${OPERATION:-delete}"
ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"
ROUTE_ID="${ROUTE_ID:-}"
ROUTE_PATTERN="${ROUTE_PATTERN:-}"

if [[ -z "${ZONE_ID}" ]]; then
  if [[ -z "${ZONE_NAME}" ]]; then
    echo "ZONE_NAME or ZONE_ID must be set" >&2
    exit 1
  fi
  ZONE_ID="$(cf_resolve_zone_id "${ZONE_NAME}")"
fi

if [[ -z "${ZONE_ID}" || "${ZONE_ID}" == "null" ]]; then
  echo "Unable to resolve zone" >&2
  exit 1
fi

resolve_route_id() {
  if [[ -n "${ROUTE_ID}" ]]; then
    printf '%s\n' "${ROUTE_ID}"
    return
  fi

  if [[ -z "${ROUTE_PATTERN}" ]]; then
    echo ""
    return
  fi

  local routes
  routes="$(cf_api_capture GET "/zones/${ZONE_ID}/workers/routes")"
  if jq -e '.success == true' <<< "${routes}" >/dev/null 2>&1; then
    jq -r --arg pattern "${ROUTE_PATTERN}" '
      (.result // [])
      | map(select(.pattern == $pattern))
      | if length == 1 then .[0].id else empty end
    ' <<< "${routes}"
  fi
}

TARGET_ROUTE_ID="$(resolve_route_id)"

if [[ -z "${TARGET_ROUTE_ID}" ]]; then
  echo "ROUTE_ID or exactly one resolvable ROUTE_PATTERN must be set" >&2
  exit 1
fi

export SURFACE="worker-route"
export OUTPUT_STEM="worker-route-mutation"
export APPLY="${APPLY:-0}"

case "${OPERATION}" in
  delete)
    export REQUEST_METHOD="DELETE"
    export REQUEST_PATH="/zones/${ZONE_ID}/workers/routes/${TARGET_ROUTE_ID}"
    export VERIFY_PATH="/zones/${ZONE_ID}/workers/routes"
    unset BODY_JSON BODY_FILE
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

set +e
mutation_report="$("${ROOT_DIR}/scripts/cf_api_apply.sh")"
status=$?
set -e
printf '%s\n' "${mutation_report}"

report_file="$(printf '%s\n' "${mutation_report}" | tail -n 1)"
if [[ "${APPLY}" == "1" && "${status}" -eq 0 && -f "${report_file}" ]]; then
  if jq -e --arg id "${TARGET_ROUTE_ID}" --arg pattern "${ROUTE_PATTERN}" '
    (.verification.response.result // [])
    | any(.[]; .id == $id or ($pattern != "" and .pattern == $pattern))
    | not
  ' "${report_file}" >/dev/null; then
    exit 0
  fi

  echo "Worker route verification failed: deleted route is still present" >&2
  exit 1
fi

exit "${status}"
