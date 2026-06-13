#!/usr/bin/env bash

# Mutates Cloudflare Email Routing rules through the zone Email Routing API.
#
#   upsert: POST/PUT /zones/:zone_id/email/routing/rules
#
# Required env from cfctl:
#   OPERATION       upsert
#   ZONE_NAME or ZONE_ID
#   RULE_ADDRESS    literal recipient address, for example founders@example.com
#   WORKER_NAME     Email Worker script name

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_backend_dispatch "cfctl apply email.routing_rule <operation> ..."

OPERATION="${OPERATION:-upsert}"
ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"
RULE_ID="${RULE_ID:-}"
RULE_ADDRESS="${RULE_ADDRESS:-}"
WORKER_NAME="${WORKER_NAME:-}"
PRIORITY="${PRIORITY:-0}"

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

build_payload() {
  if [[ -n "${BODY_JSON:-}" || -n "${BODY_FILE:-}" ]]; then
    cf_resolve_json_payload "${BODY_JSON:-}" "${BODY_FILE:-}"
    return
  fi

  if [[ -z "${RULE_ADDRESS}" || -z "${WORKER_NAME}" ]]; then
    echo "RULE_ADDRESS and WORKER_NAME must be set when BODY_JSON/BODY_FILE is not provided" >&2
    exit 1
  fi

  jq -n \
    --arg address "${RULE_ADDRESS}" \
    --arg worker_name "${WORKER_NAME}" \
    --arg priority "${PRIORITY}" \
    '
      {
        name: ("Maildesk " + $address),
        matchers: [
          {
            type: "literal",
            field: "to",
            value: $address
          }
        ],
        actions: [
          {
            type: "worker",
            value: [$worker_name]
          }
        ],
        enabled: true,
        priority: ($priority | tonumber)
      }
    '
}

resolve_rule_id() {
  if [[ -n "${RULE_ID}" ]]; then
    printf '%s\n' "${RULE_ID}"
    return
  fi

  if [[ -z "${RULE_ADDRESS}" ]]; then
    echo ""
    return
  fi

  local rules
  local matches
  local match_count
  rules="$(cf_api_capture GET "/zones/${ZONE_ID}/email/routing/rules")"
  if ! jq -e '.success == true' <<< "${rules}" >/dev/null 2>&1; then
    echo "Unable to read existing Email Routing rules before upsert" >&2
    exit 1
  fi

  matches="$(
    jq -c --arg address "${RULE_ADDRESS}" '
      [
        (.result // [])[]
        | select(
            any(.matchers[]?; .field == "to" and (.value | ascii_downcase) == ($address | ascii_downcase))
        )
      ]
    ' <<< "${rules}"
  )"
  match_count="$(jq -r 'length' <<< "${matches}")"

  case "${match_count}" in
    0)
      echo ""
      ;;
    1)
      jq -r '.[0].id' <<< "${matches}"
      ;;
    *)
      echo "Ambiguous Email Routing rule selector: ${RULE_ADDRESS} matched ${match_count} rules" >&2
      jq -c '[.[] | {id, name, enabled, priority}]' <<< "${matches}" >&2
      exit 1
      ;;
  esac
}

TARGET_RULE_ID="$(resolve_rule_id)"

export SURFACE="email-routing-rule"
export OUTPUT_STEM="email-routing-rule-mutation"
export APPLY="${APPLY:-0}"

case "${OPERATION}" in
  upsert)
    BODY_JSON="$(build_payload)"
    export BODY_JSON
    if [[ -n "${TARGET_RULE_ID}" ]]; then
      export REQUEST_METHOD="PUT"
      export REQUEST_PATH="/zones/${ZONE_ID}/email/routing/rules/${TARGET_RULE_ID}"
    else
      export REQUEST_METHOD="POST"
      export REQUEST_PATH="/zones/${ZONE_ID}/email/routing/rules"
    fi
    export VERIFY_PATH="/zones/${ZONE_ID}/email/routing/rules"
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
  if [[ -n "${BODY_JSON:-}" || -n "${BODY_FILE:-}" ]]; then
    if jq -e --arg address "${RULE_ADDRESS}" '
      (.verification.response.result // [])
      | any(
          .[]?;
          (
            any(.matchers[]?; .field == "to" and (.value | ascii_downcase) == ($address | ascii_downcase))
            and (.enabled == true)
          )
        )
    ' "${report_file}" >/dev/null; then
      exit 0
    fi

    echo "Email Routing rule verification failed for ${RULE_ADDRESS}" >&2
    exit 1
  fi

  if jq -e --arg address "${RULE_ADDRESS}" --arg worker_name "${WORKER_NAME}" '
    (.verification.response.result // [])
    | any(
        .[]?;
        (
          any(.matchers[]?; .field == "to" and (.value | ascii_downcase) == ($address | ascii_downcase))
          and any(.actions[]?; .type == "worker" and ((.value // []) | index($worker_name) != null))
          and (.enabled == true)
        )
      )
  ' "${report_file}" >/dev/null; then
    exit 0
  fi

  echo "Email Routing rule verification failed for ${RULE_ADDRESS} -> ${WORKER_NAME}" >&2
  exit 1
fi

exit "${status}"
