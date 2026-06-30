#!/usr/bin/env bash

# Mutates Cloudflare Email Sending sender subdomains.
#
#   enable: POST /zones/:zone_id/email/sending/subdomains
#
# Required env from cfctl:
#   OPERATION       enable
#   ZONE_NAME or ZONE_ID
#   SENDER_DOMAIN   subdomain/domain name to enable for Email Sending

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_backend_dispatch "cfctl apply sender_domain <operation> ..."

OPERATION="${OPERATION:-enable}"
ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"
SENDER_DOMAIN="${SENDER_DOMAIN:-${DOMAIN_NAME:-}}"

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

if [[ -z "${SENDER_DOMAIN}" ]]; then
  echo "SENDER_DOMAIN must be set" >&2
  exit 1
fi

if [[ -n "${ZONE_NAME}" ]]; then
  zone_lc="$(printf '%s' "${ZONE_NAME}" | tr '[:upper:]' '[:lower:]')"
  sender_lc="$(printf '%s' "${SENDER_DOMAIN}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${sender_lc}" != "${zone_lc}" && "${sender_lc}" != *".${zone_lc}" ]]; then
    echo "SENDER_DOMAIN must be within ZONE_NAME" >&2
    exit 1
  fi
fi

build_payload() {
  if [[ -n "${BODY_JSON:-}" || -n "${BODY_FILE:-}" ]]; then
    cf_resolve_json_payload "${BODY_JSON:-}" "${BODY_FILE:-}"
    return
  fi

  jq -n --arg name "${SENDER_DOMAIN}" '{name: $name}'
}

export SURFACE="sender-domain"
export OUTPUT_STEM="sender-domain-mutation"
export APPLY="${APPLY:-0}"

case "${OPERATION}" in
  enable)
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/zones/${ZONE_ID}/email/sending/subdomains"
    export VERIFY_PATH="/zones/${ZONE_ID}/email/sending/subdomains"
    export BODY_JSON="$(build_payload)"
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

report_file="$(printf '%s\n' "${mutation_report}" | tail -n 1)"
if [[ "${APPLY}" == "1" && "${status}" -eq 0 && -f "${report_file}" ]]; then
  if jq -e --arg name "${SENDER_DOMAIN}" '
    (.verification.response.result // [])
    | any(
        .[]?;
        (((.name // .domain // "") | ascii_downcase) == ($name | ascii_downcase))
        and (.enabled == true)
      )
  ' "${report_file}" >/dev/null; then
    exit 0
  fi

  echo "Email Sending sender-domain verification failed for ${SENDER_DOMAIN}" >&2
  exit 1
fi

exit "${status}"
