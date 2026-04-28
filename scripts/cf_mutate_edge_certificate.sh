#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_backend_dispatch "cfctl apply edge.certificate <operation> ..."

OPERATION="${OPERATION:-order}"
ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"
HOSTS_JSON="${HOSTS_JSON:-[]}"
CERTIFICATE_AUTHORITY="${CERTIFICATE_AUTHORITY:-lets_encrypt}"
VALIDATION_METHOD="${VALIDATION_METHOD:-txt}"
VALIDITY_DAYS="${VALIDITY_DAYS:-90}"
CLOUDFLARE_BRANDING="${CLOUDFLARE_BRANDING:-false}"

case "${CERTIFICATE_AUTHORITY}" in
  google|lets_encrypt|ssl_com) ;;
  *)
    echo "CERTIFICATE_AUTHORITY must be one of: google, lets_encrypt, ssl_com" >&2
    exit 1
    ;;
esac

case "${VALIDATION_METHOD}" in
  txt|http|email) ;;
  *)
    echo "VALIDATION_METHOD must be one of: txt, http, email" >&2
    exit 1
    ;;
esac

case "${VALIDITY_DAYS}" in
  14|30|90|365) ;;
  *)
    echo "VALIDITY_DAYS must be one of: 14, 30, 90, 365" >&2
    exit 1
    ;;
esac

case "${CLOUDFLARE_BRANDING}" in
  true|false) ;;
  *)
    echo "CLOUDFLARE_BRANDING must be true or false" >&2
    exit 1
    ;;
esac

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

if [[ -z "${ZONE_NAME}" ]]; then
  ZONE_NAME="$(cf_api GET "/zones/${ZONE_ID}" | jq -r '.result.name // empty')"
fi

export SURFACE="edge-certificate"
export OUTPUT_STEM="edge-certificate-mutation"
export APPLY="${APPLY:-0}"
export BODY_JSON="${BODY_JSON:-}"
export BODY_FILE="${BODY_FILE:-}"

if [[ -z "${BODY_JSON}" && -z "${BODY_FILE}" ]]; then
  if [[ "$(jq 'length' <<< "${HOSTS_JSON}")" == "0" ]]; then
    echo "At least one --host is required when BODY_JSON/BODY_FILE is not provided" >&2
    exit 1
  fi

  BODY_JSON="$(
    jq -n -c \
      --arg zone_name "${ZONE_NAME}" \
      --arg certificate_authority "${CERTIFICATE_AUTHORITY}" \
      --arg validation_method "${VALIDATION_METHOD}" \
      --arg validity_days "${VALIDITY_DAYS}" \
      --arg cloudflare_branding "${CLOUDFLARE_BRANDING}" \
      --argjson hosts "${HOSTS_JSON}" \
      '
        ($hosts + [$zone_name] | unique) as $covered_hosts
        | {
            type: "advanced",
            hosts: $covered_hosts,
            certificate_authority: $certificate_authority,
            validation_method: $validation_method,
            validity_days: ($validity_days | tonumber),
            cloudflare_branding: ($cloudflare_branding == "true")
          }
      '
  )"
  export BODY_JSON
fi

case "${OPERATION}" in
  order)
    export REQUEST_METHOD="POST"
    export REQUEST_PATH="/zones/${ZONE_ID}/ssl/certificate_packs/order"
    export VERIFY_JQ="\"/zones/${ZONE_ID}/ssl/certificate_packs/\" + (.result.id // \"\")"
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
