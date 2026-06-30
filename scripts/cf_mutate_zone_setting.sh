#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_backend_dispatch "cfctl apply zone.setting set ..."

OPERATION="${OPERATION:-set}"
ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"
SETTING_NAME="${SETTING_NAME:-}"
SETTING_VALUE="${SETTING_VALUE:-}"

if [[ "${OPERATION}" != "set" ]]; then
  echo "Unsupported OPERATION: ${OPERATION}" >&2
  exit 1
fi

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

if [[ -z "${SETTING_NAME}" ]]; then
  echo "SETTING_NAME must be set" >&2
  exit 1
fi

build_payload() {
  if [[ -n "${BODY_JSON:-}" || -n "${BODY_FILE:-}" ]]; then
    local resolved
    resolved="$(cf_resolve_json_payload "${BODY_JSON:-}" "${BODY_FILE:-}")"
    jq -c '
      if type == "object" and has("value") then
        .
      else
        {value: .}
      end
    ' <<< "${resolved}"
    return
  fi

  if [[ -z "${SETTING_VALUE}" ]]; then
    echo "SETTING_VALUE, BODY_JSON, or BODY_FILE must be set" >&2
    exit 1
  fi

  jq -n --arg value "${SETTING_VALUE}" '{value: $value}'
}

export SURFACE="zone-setting"
export OUTPUT_STEM="zone-setting-mutation"
export APPLY="${APPLY:-0}"
export REQUEST_METHOD="PATCH"
export REQUEST_PATH="/zones/${ZONE_ID}/settings/${SETTING_NAME}"
export VERIFY_PATH="/zones/${ZONE_ID}/settings/${SETTING_NAME}"
export BODY_JSON="$(build_payload)"

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
