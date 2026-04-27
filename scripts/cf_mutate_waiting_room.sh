#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_backend_dispatch "cfctl apply waiting_room <operation> ..."

OPERATION="${OPERATION:-patch}"
ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"
WAITING_ROOM_ID="${WAITING_ROOM_ID:-}"

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

export SURFACE="waiting-room"
export OUTPUT_STEM="waiting-room-mutation"
export APPLY="${APPLY:-0}"
export BODY_JSON="${BODY_JSON:-}"
export BODY_FILE="${BODY_FILE:-}"

case "${OPERATION}" in
  create)
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/zones/${ZONE_ID}/waiting_rooms"
    export VERIFY_JQ="\"/zones/${ZONE_ID}/waiting_rooms/\" + (.result.id // .result[0].id // \"\")"
    ;;
  update)
    if [[ -z "${WAITING_ROOM_ID}" ]]; then
      echo "WAITING_ROOM_ID must be set for OPERATION=update" >&2
      exit 1
    fi
    export REQUEST_METHOD="PUT"
    export REQUEST_PATH="/zones/${ZONE_ID}/waiting_rooms/${WAITING_ROOM_ID}"
    export VERIFY_PATH="/zones/${ZONE_ID}/waiting_rooms/${WAITING_ROOM_ID}"
    ;;
  patch)
    if [[ -z "${WAITING_ROOM_ID}" ]]; then
      echo "WAITING_ROOM_ID must be set for OPERATION=patch" >&2
      exit 1
    fi
    export REQUEST_METHOD="PATCH"
    export REQUEST_PATH="/zones/${ZONE_ID}/waiting_rooms/${WAITING_ROOM_ID}"
    export VERIFY_PATH="/zones/${ZONE_ID}/waiting_rooms/${WAITING_ROOM_ID}"
    ;;
  delete)
    if [[ -z "${WAITING_ROOM_ID}" ]]; then
      echo "WAITING_ROOM_ID must be set for OPERATION=delete" >&2
      exit 1
    fi
    export REQUEST_METHOD="DELETE"
    export REQUEST_PATH="/zones/${ZONE_ID}/waiting_rooms/${WAITING_ROOM_ID}"
    export VERIFY_PATH="/zones/${ZONE_ID}/waiting_rooms"
    unset BODY_JSON BODY_FILE
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
