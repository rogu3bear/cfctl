#!/usr/bin/env bash

# Mutates Worker secrets via the CF Workers API:
#   upsert: PUT /accounts/:id/workers/scripts/:name/secrets
#           body: {"name": "...", "text": "...", "type": "secret_text"}
#           Idempotent — replaces any existing secret with the same name.
#   delete: DELETE /accounts/:id/workers/scripts/:name/secrets/:secret
#
# Required inputs (env from cfctl apply dispatch):
#   OPERATION       upsert | delete
#   WORKER_SCRIPT   parent script name (e.g., "founder")
#   SECRET_NAME     secret env-var name (e.g., "MLN_FOUNDER_D1_API_TOKEN")
# upsert also requires:
#   VALUE_FILE or BODY_JSON or BODY_FILE
#   (VALUE_FILE: a path whose contents become the secret value)
#   (BODY_JSON / BODY_FILE: full JSON body for advanced cases)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_backend_dispatch "cfctl apply worker.secret <operation> ..."

OPERATION="${OPERATION:-upsert}"
WORKER_SCRIPT="${WORKER_SCRIPT:-}"
SECRET_NAME="${SECRET_NAME:-}"
SECRET_TYPE="${SECRET_TYPE:-secret_text}"
VALUE_FILE="${VALUE_FILE:-}"

if [[ -z "${WORKER_SCRIPT}" ]]; then
  echo "WORKER_SCRIPT must be set (--script <name>)" >&2
  exit 1
fi
if [[ -z "${SECRET_NAME}" ]]; then
  echo "SECRET_NAME must be set (--name <secret>)" >&2
  exit 1
fi

build_payload() {
  if [[ -n "${BODY_JSON:-}" || -n "${BODY_FILE:-}" ]]; then
    cf_resolve_json_payload "${BODY_JSON:-}" "${BODY_FILE:-}"
    return
  fi

  if [[ -z "${VALUE_FILE}" ]]; then
    echo "VALUE_FILE (--file <path>) or BODY_JSON/BODY_FILE must be set for upsert" >&2
    exit 1
  fi
  if [[ ! -r "${VALUE_FILE}" ]]; then
    echo "VALUE_FILE not readable: ${VALUE_FILE}" >&2
    exit 1
  fi

  # The CF API expects raw text in `text`; we read the file contents
  # without trailing-newline trimming (operator's responsibility to
  # provide the exact secret value).
  jq -n \
    --arg name "${SECRET_NAME}" \
    --rawfile text "${VALUE_FILE}" \
    --arg type "${SECRET_TYPE}" \
    '{name: $name, text: $text, type: $type}'
}

export SURFACE="worker-secret"
export OUTPUT_STEM="worker-secret-mutation"
export APPLY="${APPLY:-0}"

case "${OPERATION}" in
  upsert)
    export REQUEST_METHOD="PUT"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${WORKER_SCRIPT}/secrets"
    export BODY_JSON="$(build_payload)"
    # Verify the secret now appears in the listing. Names-only check;
    # the API never returns values, so we cannot compare content.
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${WORKER_SCRIPT}/secrets"
    ;;
  delete)
    export REQUEST_METHOD="DELETE"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${WORKER_SCRIPT}/secrets/${SECRET_NAME}"
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${WORKER_SCRIPT}/secrets"
    unset BODY_JSON BODY_FILE
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
