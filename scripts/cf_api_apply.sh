#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_backend_dispatch "cfctl apply <surface> <operation> ..."
cf_setup_log_pipe "operations" "build"

SURFACE="${SURFACE:-generic}"
REQUEST_METHOD="${REQUEST_METHOD:-}"
REQUEST_PATH="${REQUEST_PATH:-}"
VERIFY_METHOD="${VERIFY_METHOD:-GET}"
VERIFY_PATH="${VERIFY_PATH:-}"
VERIFY_JQ="${VERIFY_JQ:-}"
OUTPUT_STEM="${OUTPUT_STEM:-api-apply}"
APPLY="${APPLY:-0}"
BODY_JSON="${BODY_JSON:-}"
BODY_FILE="${BODY_FILE:-}"
ALLOW_EMPTY_BODY="${ALLOW_EMPTY_BODY:-0}"

if [[ -z "${REQUEST_METHOD}" ]]; then
  echo "REQUEST_METHOD must be set" >&2
  exit 1
fi

if [[ -z "${REQUEST_PATH}" ]]; then
  echo "REQUEST_PATH must be set" >&2
  exit 1
fi

REQUEST_METHOD="$(printf '%s' "${REQUEST_METHOD}" | tr '[:lower:]' '[:upper:]')"
VERIFY_METHOD="$(printf '%s' "${VERIFY_METHOD}" | tr '[:lower:]' '[:upper:]')"
REQUEST_BODY="$(cf_resolve_json_payload "${BODY_JSON}" "${BODY_FILE}")"

case "${REQUEST_METHOD}" in
  POST|PUT|PATCH)
    if [[ -z "${REQUEST_BODY}" && "${ALLOW_EMPTY_BODY}" != "1" ]]; then
      echo "${REQUEST_METHOD} requests require BODY_JSON or BODY_FILE" >&2
      exit 1
    fi
    ;;
esac

REQUEST_BODY_REDACTED="null"
if [[ -n "${REQUEST_BODY}" ]]; then
  REQUEST_BODY_REDACTED="$(cf_redact_json "${REQUEST_BODY}")"
fi

REPORT_FILE="$(cf_inventory_file "operations" "${OUTPUT_STEM}")"

report_json() {
  local mutation_response="${1:-null}"
  local verification_response="${2:-null}"
  local resolved_verify_path="${3:-}"

  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg surface "${SURFACE}" \
    --arg request_method "${REQUEST_METHOD}" \
    --arg request_path "${REQUEST_PATH}" \
    --arg verify_method "${VERIFY_METHOD}" \
    --arg verify_path "${resolved_verify_path}" \
    --arg apply "${APPLY}" \
    --argjson request_body "${REQUEST_BODY_REDACTED}" \
    --argjson mutation "${mutation_response}" \
    --argjson verification "${verification_response}" \
    '
      {
        generated_at: $generated_at,
        surface: $surface,
        apply: ($apply == "1"),
        request: {
          method: $request_method,
          path: $request_path,
          body: $request_body
        },
        verification: {
          method: $verify_method,
          path: (if $verify_path == "" then null else $verify_path end),
          response: $verification
        },
        mutation_response: $mutation
      }
    '
}

echo "Prepared ${SURFACE} mutation"
jq -n \
  --arg surface "${SURFACE}" \
  --arg method "${REQUEST_METHOD}" \
  --arg path "${REQUEST_PATH}" \
  --arg apply "${APPLY}" \
  --argjson body "${REQUEST_BODY_REDACTED}" \
  '{
    surface: $surface,
    apply: ($apply == "1"),
    method: $method,
    path: $path,
    body: $body
  }'

if [[ "${APPLY}" != "1" ]]; then
  REPORT_JSON="$(report_json "null" "null" "${VERIFY_PATH}")"
  cf_write_json_file "${REPORT_FILE}" "${REPORT_JSON}"
  echo "Dry run only. Set APPLY=1 to perform the Cloudflare API mutation."
  cf_print_log_footer
  echo "${REPORT_FILE}"
  exit 0
fi

perform_request() {
  local method="$1"
  local path="$2"
  local body="${3:-}"

  if [[ -n "${body}" ]]; then
    cf_api_capture "${method}" "${path}" \
      -H "Content-Type: application/json" \
      --data "${body}"
  else
    cf_api_capture "${method}" "${path}"
  fi
}

MUTATION_RESPONSE="$(perform_request "${REQUEST_METHOD}" "${REQUEST_PATH}" "${REQUEST_BODY}")"
MUTATION_RESPONSE_REDACTED="$(cf_redact_json "${MUTATION_RESPONSE}")"
MUTATION_SUCCESS="$(jq -r '.success == true' <<< "${MUTATION_RESPONSE}")"

RESOLVED_VERIFY_PATH="${VERIFY_PATH}"
if [[ "${MUTATION_SUCCESS}" == "true" && -z "${RESOLVED_VERIFY_PATH}" && -n "${VERIFY_JQ}" ]]; then
  RESOLVED_VERIFY_PATH="$(
    jq -r "${VERIFY_JQ}" <<< "${MUTATION_RESPONSE}" \
    | head -n 1
  )"
  if [[ "${RESOLVED_VERIFY_PATH}" == "null" ]]; then
    RESOLVED_VERIFY_PATH=""
  fi
fi

VERIFICATION_RESPONSE="null"
if [[ "${MUTATION_SUCCESS}" == "true" && -n "${RESOLVED_VERIFY_PATH}" ]]; then
  VERIFICATION_RESPONSE="$(perform_request "${VERIFY_METHOD}" "${RESOLVED_VERIFY_PATH}")"
fi

VERIFICATION_RESPONSE_REDACTED="null"
if [[ "${VERIFICATION_RESPONSE}" != "null" ]]; then
  VERIFICATION_RESPONSE_REDACTED="$(cf_redact_json "${VERIFICATION_RESPONSE}")"
fi

REPORT_JSON="$(
  report_json \
    "${MUTATION_RESPONSE_REDACTED}" \
    "${VERIFICATION_RESPONSE_REDACTED}" \
    "${RESOLVED_VERIFY_PATH}"
)"
cf_write_json_file "${REPORT_FILE}" "${REPORT_JSON}"

echo "${MUTATION_RESPONSE_REDACTED}" | jq '{success, errors, messages, result}'
if [[ "${VERIFICATION_RESPONSE_REDACTED}" != "null" ]]; then
  echo "${VERIFICATION_RESPONSE_REDACTED}" | jq '{verify_success: .success, verify_errors: .errors, verify_result: .result}'
fi

cf_print_log_footer
echo "${REPORT_FILE}"

if [[ "${MUTATION_SUCCESS}" != "true" ]]; then
  exit 1
fi
