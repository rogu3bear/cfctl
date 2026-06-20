#!/usr/bin/env bash

# Sets a zone's Cloudflare Email Routing catch-all rule to hand every
# otherwise-unmatched recipient to an Email Worker. This is the backstop that
# guarantees no inbound address bounces: literal-address rules still match
# first, and anything else falls through to the worker, whose policy decides
# the route (including its own per-domain catch_all).
#
#   PUT /zones/:zone_id/email/routing/rules/catch_all
#
# Required env from cfctl:
#   ZONE_NAME or ZONE_ID
#   WORKER_NAME     Email Worker script name (e.g. star-maildesk-cf-router)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_backend_dispatch "cfctl apply email.routing_catch_all ..."

ZONE_NAME="${ZONE_NAME:-}"
ZONE_ID="${ZONE_ID:-}"
WORKER_NAME="${WORKER_NAME:-}"

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

  if [[ -z "${WORKER_NAME}" ]]; then
    echo "WORKER_NAME must be set when BODY_JSON/BODY_FILE is not provided" >&2
    exit 1
  fi

  # The catch-all rule must carry a single "all" matcher and (here) a worker
  # action. Cloudflare rejects a catch_all with any other matcher shape.
  jq -n \
    --arg worker_name "${WORKER_NAME}" \
    '
      {
        name: "Maildesk catch-all",
        enabled: true,
        matchers: [
          { type: "all" }
        ],
        actions: [
          {
            type: "worker",
            value: [$worker_name]
          }
        ]
      }
    '
}

export SURFACE="email-routing-catch-all"
export OUTPUT_STEM="email-routing-catch-all-mutation"
export APPLY="${APPLY:-0}"

BODY_JSON="$(build_payload)"
export BODY_JSON
export REQUEST_METHOD="PUT"
export REQUEST_PATH="/zones/${ZONE_ID}/email/routing/rules/catch_all"
export VERIFY_PATH="/zones/${ZONE_ID}/email/routing/rules/catch_all"

set +e
mutation_report="$("${ROOT_DIR}/scripts/cf_api_apply.sh")"
status=$?
set -e
printf '%s\n' "${mutation_report}"

report_file="$(printf '%s\n' "${mutation_report}" | tail -n 1)"
if [[ "${APPLY}" == "1" && "${status}" -eq 0 && -f "${report_file}" ]]; then
  if jq -e --arg worker_name "${WORKER_NAME}" '
    (.verification.response.result // {})
    | (
        (.enabled == true)
        and any(.matchers[]?; .type == "all")
        and any(.actions[]?; .type == "worker" and ((.value // []) | index($worker_name) != null))
      )
  ' "${report_file}" >/dev/null; then
    exit 0
  fi

  echo "Email Routing catch-all verification failed for zone ${ZONE_NAME:-$ZONE_ID} -> ${WORKER_NAME}" >&2
  exit 1
fi

exit "${status}"
