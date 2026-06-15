#!/usr/bin/env bash

# Mutates Cloudflare Access service tokens (non-identity machine credentials):
#   create: POST   /accounts/:id/access/service_tokens   body {"name": "..."}
#           The minted client_secret is returned exactly once. It is delivered
#           to the --value-out sink via cf_api_apply.sh's SECRET_SINK hook and
#           never printed; client_id + id are surfaced (non-secret).
#   delete: DELETE /accounts/:id/access/service_tokens/:id
#
# Inputs (env from cfctl apply dispatch):
#   OPERATION    create | delete
#   SECRET_NAME  service-token name              (create; --name)
#   VALUE_OUT    absolute sink for client_secret (create; --value-out)
#   TOKEN_ID     service-token id                (delete; --id)
#
# Preview/ack gating is enforced centrally by cfctl_handle_apply; this backend
# only prepares the request and (on apply) hands off to cf_api_apply.sh.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_account_id
cf_require_backend_dispatch "cfctl apply access.service_token <operation> ..."

OPERATION="${OPERATION:-create}"
TOKEN_ID="${TOKEN_ID:-}"
SECRET_NAME="${SECRET_NAME:-}"
VALUE_OUT="${VALUE_OUT:-}"

export SURFACE="access-service-token"
export OUTPUT_STEM="access-service-token-mutation"
export APPLY="${APPLY:-0}"

case "${OPERATION}" in
  create)
    if [[ -z "${SECRET_NAME}" ]]; then
      echo "SECRET_NAME (--name <token-name>) required for create" >&2
      exit 1
    fi
    # A real mint must deliver the one-time client_secret to a sink, never
    # stdout. In plan mode (APPLY=0) cf_api_apply.sh only previews the request.
    if [[ "${APPLY}" == "1" && -z "${VALUE_OUT}" ]]; then
      echo "VALUE_OUT (--value-out <abs path>) required to receive the minted client_secret" >&2
      exit 1
    fi
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/service_tokens"
    if [[ -n "${BODY_JSON:-}" || -n "${BODY_FILE:-}" ]]; then
      export BODY_JSON="$(cf_resolve_json_payload "${BODY_JSON:-}" "${BODY_FILE:-}")"
    else
      export BODY_JSON="$(jq -n --arg name "${SECRET_NAME}" '{name: $name}')"
    fi
    unset BODY_FILE
    export SECRET_SINK_PATH="${VALUE_OUT}"
    export SECRET_SINK_JQ='.result.client_secret'
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/service_tokens"
    ;;
  delete)
    if [[ -z "${TOKEN_ID}" ]]; then
      echo "TOKEN_ID (--id <token-id>) required for delete" >&2
      exit 1
    fi
    export REQUEST_METHOD="DELETE"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/service_tokens/${TOKEN_ID}"
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/service_tokens"
    unset BODY_JSON BODY_FILE
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
