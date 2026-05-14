#!/usr/bin/env bash

# Mutates zone rulesets through the Cloudflare Rulesets API.
#
#   update: PUT /zones/:zone_id/rulesets/:ruleset_id
#
# Required env from cfctl:
#   OPERATION       update
#   ZONE_NAME or ZONE_ID
#   RULESET_ID
#   BODY_JSON or BODY_FILE

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_api_auth
cf_require_backend_dispatch "cfctl apply zone.ruleset <operation> ..."

OPERATION="${OPERATION:-update}"
ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"
RULESET_ID="${RULESET_ID:-}"
BODY_JSON="${BODY_JSON:-}"
BODY_FILE="${BODY_FILE:-}"

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

if [[ -z "${RULESET_ID}" ]]; then
  echo "RULESET_ID must be set" >&2
  exit 1
fi

export SURFACE="zone-ruleset"
export OUTPUT_STEM="zone-ruleset-mutation"
export APPLY="${APPLY:-0}"

case "${OPERATION}" in
  update)
    export REQUEST_METHOD="PUT"
    export REQUEST_PATH="/zones/${ZONE_ID}/rulesets/${RULESET_ID}"
    export VERIFY_PATH="/zones/${ZONE_ID}/rulesets/${RULESET_ID}"
    export BODY_JSON
    export BODY_FILE
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

set +e
mutation_report="$("${ROOT_DIR}/scripts/cf_api_apply.sh")"
status=$?
set -e
printf '%s\n' "${mutation_report}"

exit "${status}"
