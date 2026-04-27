#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_account_id
cf_require_backend_dispatch "cfctl apply tunnel <operation> ..."

OPERATION="${OPERATION:-update}"
TUNNEL_ID="${TUNNEL_ID:-}"
CLIENT_ID="${CLIENT_ID:-}"

export SURFACE="tunnel"
export OUTPUT_STEM="tunnel-mutation"
export APPLY="${APPLY:-0}"
export BODY_JSON="${BODY_JSON:-}"
export BODY_FILE="${BODY_FILE:-}"
export ALLOW_EMPTY_BODY="0"

case "${OPERATION}" in
  create)
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel"
    export VERIFY_JQ="\"/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/\" + (.result.id // \"\")"
    ;;
  update)
    if [[ -z "${TUNNEL_ID}" ]]; then
      echo "TUNNEL_ID must be set for OPERATION=update" >&2
      exit 1
    fi
    export REQUEST_METHOD="PUT"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}"
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}"
    ;;
  configure)
    if [[ -z "${TUNNEL_ID}" ]]; then
      echo "TUNNEL_ID must be set for OPERATION=configure" >&2
      exit 1
    fi
    export REQUEST_METHOD="PUT"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}/configurations"
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}/configurations"
    ;;
  delete)
    if [[ -z "${TUNNEL_ID}" ]]; then
      echo "TUNNEL_ID must be set for OPERATION=delete" >&2
      exit 1
    fi
    export REQUEST_METHOD="DELETE"
    export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}"
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel"
    unset BODY_JSON BODY_FILE
    ;;
  cleanup-connections)
    if [[ -z "${TUNNEL_ID}" ]]; then
      echo "TUNNEL_ID must be set for OPERATION=cleanup-connections" >&2
      exit 1
    fi
    export REQUEST_METHOD="DELETE"
    if [[ -n "${CLIENT_ID}" ]]; then
      export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}/connections?client_id=${CLIENT_ID}"
    else
      export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}/connections"
    fi
    export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}/connections"
    unset BODY_JSON BODY_FILE
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
