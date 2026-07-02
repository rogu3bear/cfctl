#!/usr/bin/env bash

# Mutates Cloudflare Access groups (reusable rule groups):
#   create: POST   /accounts/:id/access/groups     (body required)
#   update: PUT    /accounts/:id/access/groups/:id (body required)
#   delete: DELETE /accounts/:id/access/groups/:id
#
# Inputs (env from cfctl apply dispatch):
#   OPERATION  create | update | delete
#   GROUP_ID   group id (update/delete; --id)
#   BODY_JSON / BODY_FILE  group body with name/include/exclude/require
#   APPLY      0 plan-only | 1 apply
#
# Preview/ack gating is enforced centrally by cfctl_handle_apply; this backend
# only prepares the request and hands off to cf_api_apply.sh.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_account_id
cf_require_backend_dispatch "cfctl apply access.group <operation> ..."

OPERATION="${OPERATION:-update}"
GROUP_ID="${GROUP_ID:-}"

export SURFACE="access-group"
export OUTPUT_STEM="access-group-mutation"
export APPLY="${APPLY:-0}"
export BODY_JSON="${BODY_JSON:-}"
export BODY_FILE="${BODY_FILE:-}"

case "${OPERATION}" in
  create)
    if [[ -z "${BODY_JSON}" && -z "${BODY_FILE}" ]]; then
      echo "BODY_JSON or BODY_FILE (--body / --body-file) required for create" >&2
      exit 1
    fi
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/groups"
    export VERIFY_JQ="\"/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/groups/\" + (.result.id // \"\")"
    ;;
  update)
    if [[ -z "${GROUP_ID}" ]]; then
      echo "GROUP_ID (--id <group-id>) must be set for OPERATION=update" >&2
      exit 1
    fi
    if [[ -z "${BODY_JSON}" && -z "${BODY_FILE}" ]]; then
      echo "BODY_JSON or BODY_FILE (--body / --body-file) required for update" >&2
      exit 1
    fi
    export REQUEST_METHOD="PUT"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/groups/${GROUP_ID}"
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/groups/${GROUP_ID}"
    ;;
  delete)
    if [[ -z "${GROUP_ID}" ]]; then
      echo "GROUP_ID (--id <group-id>) must be set for OPERATION=delete" >&2
      exit 1
    fi
    export REQUEST_METHOD="DELETE"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/groups/${GROUP_ID}"
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/groups"
    unset BODY_JSON BODY_FILE
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
