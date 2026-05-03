#!/usr/bin/env bash

# Mutates a Workers script via the CF Workers Scripts API.
#
#   upsert: PUT  /accounts/:id/workers/scripts/:name
#           multipart/form-data with parts:
#             metadata          → application/json (bindings, vars,
#                                 compatibility_date/flags, migrations,
#                                 containers — the worker's full config)
#             <main_module>     → application/javascript+module (the
#                                 bundled JS; field name MUST match
#                                 metadata.main_module)
#           Idempotent — re-uploading the same script content increments
#           the worker version but produces an identical runtime.
#
#   delete: DELETE /accounts/:id/workers/scripts/:name
#
# Required env (from cfctl apply dispatch):
#   OPERATION       upsert | delete
#   SCRIPT_NAME     worker name (e.g., "founder")
# upsert also requires:
#   METADATA_FILE   absolute path to metadata.json
#   MODULE_FILE     absolute path to the main module bundle
#
# Bundling (TypeScript → JS, dependency resolution) is the operator's
# job; this surface only ships pre-bundled modules. Recommended toolchain:
# `bun build` or `esbuild`. Containers and DO migrations are supported
# via the metadata payload — Phase 2 of the cfctl Node-retirement work.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_account_id
cf_require_backend_dispatch "cfctl apply worker.script <operation> ..."

OPERATION="${OPERATION:-upsert}"
SCRIPT_NAME="${SCRIPT_NAME:-}"
METADATA_FILE="${METADATA_FILE:-}"
MODULE_FILE="${MODULE_FILE:-}"

if [[ -z "${SCRIPT_NAME}" ]]; then
  echo "SCRIPT_NAME must be set (--name <script>)" >&2
  exit 1
fi

export SURFACE="worker-script"
export OUTPUT_STEM="worker-script-mutation"
export APPLY="${APPLY:-0}"

case "${OPERATION}" in
  upsert)
    if [[ -z "${METADATA_FILE}" || -z "${MODULE_FILE}" ]]; then
      echo "METADATA_FILE (--metadata) and MODULE_FILE (--module) must be set for upsert" >&2
      exit 1
    fi
    if [[ ! -r "${METADATA_FILE}" ]]; then
      echo "METADATA_FILE not readable: ${METADATA_FILE}" >&2
      exit 1
    fi
    if [[ ! -r "${MODULE_FILE}" ]]; then
      echo "MODULE_FILE not readable: ${MODULE_FILE}" >&2
      exit 1
    fi

    # Pull main_module name from metadata. The multipart form field
    # holding the module bytes MUST match this string — otherwise CF
    # rejects with "main_module references unknown part".
    main_module_name="$(jq -r '.main_module // empty' "${METADATA_FILE}")"
    if [[ -z "${main_module_name}" || "${main_module_name}" == "null" ]]; then
      echo "metadata.main_module must be set in ${METADATA_FILE}" >&2
      exit 1
    fi

    export REQUEST_METHOD="PUT"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${SCRIPT_NAME}"
    export MULTIPART_PARTS="$(
      jq -nc \
        --arg metadata_file "${METADATA_FILE}" \
        --arg module_name "${main_module_name}" \
        --arg module_file "${MODULE_FILE}" \
        '[
           {name: "metadata", file: $metadata_file, type: "application/json"},
           {name: $module_name, file: $module_file, type: "application/javascript+module"}
         ]'
    )"
    # Verify via /settings — returns JSON (compatibility_date, tags,
    # bindings shape, etc.) which cf_api_apply.sh can parse for
    # .success. The bare /scripts/:name endpoint returns the raw JS
    # body and would never satisfy the JSON-success check.
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${SCRIPT_NAME}/settings"
    ;;
  delete)
    export REQUEST_METHOD="DELETE"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${SCRIPT_NAME}"
    # Verify the listing no longer contains this script name.
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts"
    unset BODY_JSON BODY_FILE MULTIPART_PARTS
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
