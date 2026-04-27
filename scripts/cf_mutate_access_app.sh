#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_account_id
cf_require_backend_dispatch "cfctl apply access.app <operation> ..."

OPERATION="${OPERATION:-update}"
APP_ID="${APP_ID:-}"

export SURFACE="access-app"
export OUTPUT_STEM="access-app-mutation"
export APPLY="${APPLY:-0}"
export BODY_JSON="${BODY_JSON:-}"
export BODY_FILE="${BODY_FILE:-}"

case "${OPERATION}" in
  create)
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps"
    export VERIFY_JQ="\"/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps/\" + (.result.id // \"\")"
    ;;
  update)
    if [[ -z "${APP_ID}" ]]; then
      echo "APP_ID must be set for OPERATION=update" >&2
      exit 1
    fi
    export REQUEST_METHOD="PUT"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps/${APP_ID}"
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps/${APP_ID}"
    ;;
  delete)
    if [[ -z "${APP_ID}" ]]; then
      echo "APP_ID must be set for OPERATION=delete" >&2
      exit 1
    fi
    export REQUEST_METHOD="DELETE"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps/${APP_ID}"
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps"
    unset BODY_JSON BODY_FILE
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
