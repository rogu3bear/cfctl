#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_backend_dispatch "cfctl apply security.txt <operation> ..."

OPERATION="${OPERATION:-upsert}"
ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"

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

build_payload() {
  if [[ -n "${BODY_JSON:-}" || -n "${BODY_FILE:-}" ]]; then
    cf_resolve_json_payload "${BODY_JSON:-}" "${BODY_FILE:-}"
    return
  fi

  echo "BODY_JSON or BODY_FILE must be set for security.txt ${OPERATION}" >&2
  exit 1
}

export SURFACE="security-txt"
export OUTPUT_STEM="security-txt-mutation"
export APPLY="${APPLY:-0}"

case "${OPERATION}" in
  upsert|update)
    export REQUEST_METHOD="PUT"
    export REQUEST_PATH="/zones/${ZONE_ID}/security-center/securitytxt"
    export VERIFY_PATH="/zones/${ZONE_ID}/security-center/securitytxt"
    export BODY_JSON="$(build_payload)"
    ;;
  delete)
    export REQUEST_METHOD="DELETE"
    export REQUEST_PATH="/zones/${ZONE_ID}/security-center/securitytxt"
    export VERIFY_PATH="/zones/${ZONE_ID}/security-center/securitytxt"
    unset BODY_JSON BODY_FILE
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
