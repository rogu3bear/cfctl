#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_backend_dispatch "cfctl apply dns.record <operation> ..."

OPERATION="${OPERATION:-upsert}"
ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"
RECORD_ID="${RECORD_ID:-}"
RECORD_TYPE="${RECORD_TYPE:-}"
RECORD_NAME="${RECORD_NAME:-}"
RECORD_CONTENT="${RECORD_CONTENT:-}"
TTL="${TTL:-}"
PROXIED="${PROXIED:-}"
PRIORITY="${PRIORITY:-}"
COMMENT="${COMMENT:-}"
TAGS_JSON="${TAGS_JSON:-}"
DATA_JSON="${DATA_JSON:-}"

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

resolve_record_id() {
  if [[ -n "${RECORD_ID}" ]]; then
    printf '%s\n' "${RECORD_ID}"
    return
  fi

  if [[ -z "${RECORD_NAME}" || -z "${RECORD_TYPE}" ]]; then
    echo ""
    return
  fi

  local lookup_response
  lookup_response="$(cf_api_capture GET "/zones/${ZONE_ID}/dns_records?type=${RECORD_TYPE}&name=${RECORD_NAME}")"

  if jq -e '.success == true' <<< "${lookup_response}" >/dev/null 2>&1; then
    jq -r '.result[0].id // empty' <<< "${lookup_response}"
  else
    echo "Unable to resolve existing DNS record for ${RECORD_TYPE} ${RECORD_NAME}; continuing without pre-resolved record id." >&2
    echo ""
  fi
}

build_payload() {
  if [[ -n "${BODY_JSON:-}" || -n "${BODY_FILE:-}" ]]; then
    cf_resolve_json_payload "${BODY_JSON:-}" "${BODY_FILE:-}"
    return
  fi

  if [[ -z "${RECORD_TYPE}" || -z "${RECORD_NAME}" ]]; then
    echo "RECORD_TYPE and RECORD_NAME must be set when BODY_JSON/BODY_FILE is not provided" >&2
    exit 1
  fi

  if [[ -z "${RECORD_CONTENT}" && -z "${DATA_JSON}" ]]; then
    echo "RECORD_CONTENT or DATA_JSON must be set when BODY_JSON/BODY_FILE is not provided" >&2
    exit 1
  fi

  jq -n \
    --arg type "${RECORD_TYPE}" \
    --arg name "${RECORD_NAME}" \
    --arg content "${RECORD_CONTENT}" \
    --arg ttl "${TTL}" \
    --arg proxied "${PROXIED}" \
    --arg priority "${PRIORITY}" \
    --arg comment "${COMMENT}" \
    --argjson tags "${TAGS_JSON:-null}" \
    --argjson data "${DATA_JSON:-null}" \
    '
      {
        type: $type,
        name: $name
      }
      + (if $content != "" then {content: $content} else {} end)
      + (if $ttl != "" then {ttl: ($ttl | tonumber)} else {} end)
      + (if $proxied != "" then {proxied: ($proxied == "true")} else {} end)
      + (if $priority != "" then {priority: ($priority | tonumber)} else {} end)
      + (if $comment != "" then {comment: $comment} else {} end)
      + (if $tags != null then {tags: $tags} else {} end)
      + (if $data != null then {data: $data} else {} end)
    '
}

TARGET_RECORD_ID="$(resolve_record_id)"

export SURFACE="dns-record"
export OUTPUT_STEM="dns-record-mutation"
export APPLY="${APPLY:-0}"

case "${OPERATION}" in
  create)
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/zones/${ZONE_ID}/dns_records"
    export BODY_JSON="$(build_payload)"
    export VERIFY_JQ="\"/zones/${ZONE_ID}/dns_records/\" + (.result.id // \"\")"
    ;;
  upsert)
    export BODY_JSON="$(build_payload)"
    if [[ -n "${TARGET_RECORD_ID}" ]]; then
      export REQUEST_METHOD="PATCH"
      export REQUEST_PATH="/zones/${ZONE_ID}/dns_records/${TARGET_RECORD_ID}"
      export VERIFY_PATH="/zones/${ZONE_ID}/dns_records/${TARGET_RECORD_ID}"
    else
      export REQUEST_METHOD="POST"
      export REQUEST_PATH="/zones/${ZONE_ID}/dns_records"
      export VERIFY_JQ="\"/zones/${ZONE_ID}/dns_records/\" + (.result.id // \"\")"
    fi
    ;;
  update)
    if [[ -z "${TARGET_RECORD_ID}" ]]; then
      echo "RECORD_ID or a resolvable RECORD_NAME/RECORD_TYPE must be set for OPERATION=update" >&2
      exit 1
    fi
    export REQUEST_METHOD="PATCH"
    export REQUEST_PATH="/zones/${ZONE_ID}/dns_records/${TARGET_RECORD_ID}"
    export BODY_JSON="$(build_payload)"
    export VERIFY_PATH="/zones/${ZONE_ID}/dns_records/${TARGET_RECORD_ID}"
    ;;
  delete)
    if [[ -z "${TARGET_RECORD_ID}" ]]; then
      echo "RECORD_ID or a resolvable RECORD_NAME/RECORD_TYPE must be set for OPERATION=delete" >&2
      exit 1
    fi
    export REQUEST_METHOD="DELETE"
    export REQUEST_PATH="/zones/${ZONE_ID}/dns_records/${TARGET_RECORD_ID}"
    export VERIFY_PATH="/zones/${ZONE_ID}/dns_records?type=${RECORD_TYPE}&name=${RECORD_NAME}"
    unset BODY_JSON BODY_FILE
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
