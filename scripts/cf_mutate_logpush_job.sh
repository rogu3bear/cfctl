#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_account_id
cf_require_backend_dispatch "cfctl apply logpush.job <operation> ..."

OPERATION="${OPERATION:-update}"
SCOPE_KIND="${SCOPE_KIND:-account}"
ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"
JOB_ID="${JOB_ID:-}"

case "${SCOPE_KIND}" in
  account)
    SCOPE_PATH="accounts/${CLOUDFLARE_ACCOUNT_ID}"
    ;;
  zone)
    if [[ -z "${ZONE_ID}" ]]; then
      if [[ -z "${ZONE_NAME}" ]]; then
        echo "ZONE_NAME or ZONE_ID must be set for SCOPE_KIND=zone" >&2
        exit 1
      fi
      ZONE_ID="$(cf_resolve_zone_id "${ZONE_NAME}")"
    fi
    if [[ -z "${ZONE_ID}" || "${ZONE_ID}" == "null" ]]; then
      echo "Unable to resolve zone" >&2
      exit 1
    fi
    SCOPE_PATH="zones/${ZONE_ID}"
    ;;
  *)
    echo "Unsupported SCOPE_KIND: ${SCOPE_KIND}" >&2
    exit 1
    ;;
esac

export SURFACE="logpush-job"
export OUTPUT_STEM="logpush-job-mutation"
export APPLY="${APPLY:-0}"
export BODY_JSON="${BODY_JSON:-}"
export BODY_FILE="${BODY_FILE:-}"

case "${OPERATION}" in
  create)
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/${SCOPE_PATH}/logpush/jobs"
    export VERIFY_JQ="\"/${SCOPE_PATH}/logpush/jobs/\" + ((.result.id // \"\") | tostring)"
    ;;
  update)
    if [[ -z "${JOB_ID}" ]]; then
      echo "JOB_ID must be set for OPERATION=update" >&2
      exit 1
    fi
    export REQUEST_METHOD="PUT"
    export REQUEST_PATH="/${SCOPE_PATH}/logpush/jobs/${JOB_ID}"
    export VERIFY_PATH="/${SCOPE_PATH}/logpush/jobs/${JOB_ID}"
    ;;
  delete)
    if [[ -z "${JOB_ID}" ]]; then
      echo "JOB_ID must be set for OPERATION=delete" >&2
      exit 1
    fi
    export REQUEST_METHOD="DELETE"
    export REQUEST_PATH="/${SCOPE_PATH}/logpush/jobs/${JOB_ID}"
    export VERIFY_PATH="/${SCOPE_PATH}/logpush/jobs"
    unset BODY_JSON BODY_FILE
    ;;
  ownership)
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/${SCOPE_PATH}/logpush/ownership"
    unset VERIFY_PATH VERIFY_JQ
    ;;
  validate-ownership)
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/${SCOPE_PATH}/logpush/ownership/validate"
    unset VERIFY_PATH VERIFY_JQ
    ;;
  validate-destination)
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/${SCOPE_PATH}/logpush/validate/destination"
    unset VERIFY_PATH VERIFY_JQ
    ;;
  validate-origin)
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/${SCOPE_PATH}/logpush/validate/origin"
    unset VERIFY_PATH VERIFY_JQ
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
