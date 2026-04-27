#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_account_id
cf_require_backend_dispatch "cfctl apply turnstile.widget <operation> ..."

OPERATION="${OPERATION:-update}"
SITEKEY="${SITEKEY:-}"

export SURFACE="turnstile-widget"
export OUTPUT_STEM="turnstile-widget-mutation"
export APPLY="${APPLY:-0}"
export BODY_JSON="${BODY_JSON:-}"
export BODY_FILE="${BODY_FILE:-}"

case "${OPERATION}" in
  create)
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/challenges/widgets"
    export VERIFY_JQ="\"/accounts/${CLOUDFLARE_ACCOUNT_ID}/challenges/widgets/\" + (.result.sitekey // \"\")"
    ;;
  update)
    if [[ -z "${SITEKEY}" ]]; then
      echo "SITEKEY must be set for OPERATION=update" >&2
      exit 1
    fi
    export REQUEST_METHOD="PUT"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/challenges/widgets/${SITEKEY}"
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/challenges/widgets/${SITEKEY}"
    ;;
  rotate-secret)
    if [[ -z "${SITEKEY}" ]]; then
      echo "SITEKEY must be set for OPERATION=rotate-secret" >&2
      exit 1
    fi
    if [[ -z "${BODY_JSON}" && -z "${BODY_FILE}" ]]; then
      export BODY_JSON='{"invalidate_immediately":false}'
    fi
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/challenges/widgets/${SITEKEY}/rotate_secret"
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/challenges/widgets/${SITEKEY}"
    ;;
  delete)
    if [[ -z "${SITEKEY}" ]]; then
      echo "SITEKEY must be set for OPERATION=delete" >&2
      exit 1
    fi
    export REQUEST_METHOD="DELETE"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/challenges/widgets/${SITEKEY}"
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/challenges/widgets"
    unset BODY_JSON BODY_FILE
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
