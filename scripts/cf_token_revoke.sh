#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_require_backend_dispatch "cfctl token revoke ..."

usage() {
  cat <<'EOF'
Usage:
  cfctl token revoke --id <token-id> [options]

Options:
  --id <token-id>          Account API token id to revoke/delete.
  --ack-plan <operation>   Confirm execution of a previously reviewed preview.
  --confirm delete         Required for the real revocation.
  --plan                   Print token metadata and do not revoke.
  -h, --help               Show this help.

Examples:
  cfctl token revoke --id <token-id> --plan
  cfctl token revoke --id <token-id> --ack-plan <operation-id> --confirm delete
EOF
}

TOKEN_ID=""
PLAN_MODE="0"
ACK_PLAN=""
CONFIRMATION=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --id)
      TOKEN_ID="$2"
      shift 2
      ;;
    --id=*)
      TOKEN_ID="${1#*=}"
      shift
      ;;
    --ack-plan)
      ACK_PLAN="$2"
      shift 2
      ;;
    --ack-plan=*)
      ACK_PLAN="${1#*=}"
      shift
      ;;
    --confirm)
      CONFIRMATION="$2"
      shift 2
      ;;
    --confirm=*)
      CONFIRMATION="${1#*=}"
      shift
      ;;
    --plan)
      PLAN_MODE="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${TOKEN_ID}" ]]; then
  echo "--id is required" >&2
  exit 1
fi

if [[ ! "${TOKEN_ID}" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "--id contains unsupported characters" >&2
  exit 1
fi

artifact_path="$(cf_inventory_file "auth" "token-revoke")"
runtime_policy_json="$(cf_runtime_policy_json)"
token_policy_json="$(
  jq -n \
    --argjson runtime_policy "${runtime_policy_json}" \
    '
      ($runtime_policy.operation_defaults.destructive // {}) as $defaults
      | ($runtime_policy.special_operations["token.revoke"] // {}) as $special
      | $defaults + $special + {preview_ack_flag: ($runtime_policy.preview_ack_flag // "--ack-plan")}
    '
)"
policy_version="$(jq -r '.version // 0' "$(cf_runtime_catalog_path)")"
target_json="$(jq -n --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" --arg token_id "${TOKEN_ID}" '{account_id: $account_id, token_id: $token_id}')"
request_intent_json="$(jq -n --arg token_id "${TOKEN_ID}" '{token_id: $token_id}')"
request_fingerprint="$(cf_hash_json "${request_intent_json}")"
target_fingerprint="$(cf_hash_json "${target_json}")"
policy_fingerprint="$(cf_hash_json "${token_policy_json}")"
preview_ttl_seconds="$(jq -r '.preview_ttl_seconds // 900' <<< "${token_policy_json}")"
lock_key="$(cf_runtime_lock_key "token" "token" "revoke" "${target_json}")"

fetch_token_metadata() {
  local capture_json
  capture_json="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/${TOKEN_ID}")"
  jq '
    if (.result | type) == "object" then
      .result |= {
        id,
        name,
        status,
        issued_on,
        modified_on,
        expires_on,
        not_before,
        policies,
        condition
      }
    else
      .
    end
  ' <<< "${capture_json}"
}

token_metadata_json="null"

trust_json="$(
  jq -n \
    --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg policy_version "${policy_version}" \
    --arg policy_fingerprint "${policy_fingerprint}" \
    --arg request_fingerprint "${request_fingerprint}" \
    --arg target_fingerprint "${target_fingerprint}" \
    --argjson policy "${token_policy_json}" \
    --argjson request "${request_intent_json}" \
    --argjson target "${target_json}" \
    --arg preview_expires_at "$(cf_seconds_from_now_iso8601 "${preview_ttl_seconds}")" \
    --arg lock_key "${lock_key}" \
    '
      {
        action: "token.revoke",
        surface: "token",
        operation: "revoke",
        lane: $lane,
        policy_version: $policy_version,
        policy_fingerprint: $policy_fingerprint,
        request_fingerprint: $request_fingerprint,
        target_fingerprint: $target_fingerprint,
        policy: $policy,
        request: $request,
        target: $target,
        preview_expires_at: $preview_expires_at,
        lock_key: $lock_key,
        lock_mode: ($policy.lock_strategy // "lease"),
        secret_policy: ($policy.secret_policy // "redacted")
      }
    '
)"

emit_failure_json() {
  local code="$1"
  local message="$2"
  local operation_id="${3:-}"
  local preview_artifact_path="${4:-}"
  local trust_payload="${5:-null}"
  local metadata_payload="${6:-null}"
  local failure_json

  failure_json="$(
    jq -n \
      --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
      --arg operation_id "${operation_id}" \
      --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
      --arg scheme "${CF_ACTIVE_AUTH_SCHEME:-unknown}" \
      --arg credential_env "${CF_ACTIVE_TOKEN_ENV:-unknown}" \
      --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" \
      --arg artifact_path "${artifact_path}" \
      --arg preview_artifact_path "${preview_artifact_path}" \
      --arg code "${code}" \
      --arg message "${message}" \
      --argjson trust "${trust_payload}" \
      --argjson metadata "${metadata_payload}" \
      '
        {
          generated_at: $generated_at,
          ok: false,
          action: "token.revoke",
          planned: false,
          operation_id: (if $operation_id == "" then null else $operation_id end),
          auth: {
            lane: $lane,
            scheme: $scheme,
            credential_env: $credential_env
          },
          trust: (if $trust == null then null else $trust end),
          account_id: $account_id,
          artifact_path: $artifact_path,
          result: {
            preview_artifact_path: (
              if $preview_artifact_path == "" then null else $preview_artifact_path end
            ),
            token_metadata: (if $metadata == null then null else $metadata end)
          },
          error: {
            code: $code,
            message: $message
          }
        }
      '
  )"

  cf_write_json_file "${artifact_path}" "${failure_json}"
  printf '%s\n' "${failure_json}"
}

find_matching_plan_receipt() {
  local operation_id="$1"
  local current_lane="${CF_ACTIVE_TOKEN_LANE:-unknown}"
  local file

  for file in "${ROOT_DIR}"/var/inventory/auth/token-revoke-*.json; do
    [[ -f "${file}" ]] || continue
    if jq -e \
      --arg operation_id "${operation_id}" \
      --arg lane "${current_lane}" \
      '
        .action == "token.revoke"
        and .planned == true
        and .operation_id == $operation_id
        and .auth.lane == $lane
      ' "${file}" >/dev/null 2>&1; then
      printf '%s\n' "${file}"
      return 0
    fi
  done

  return 1
}

validate_plan_receipt() {
  local receipt_path="$1"
  local receipt_trust_json
  local preview_expires_at
  local preview_expires_epoch

  TOKEN_PLAN_RECEIPT_ERROR_CODE=""
  TOKEN_PLAN_RECEIPT_ERROR_MESSAGE=""
  TOKEN_PLAN_RECEIPT_TRUST_JSON="null"

  receipt_trust_json="$(jq -c '.trust // null' "${receipt_path}")"
  if [[ "${receipt_trust_json}" == "null" ]]; then
    TOKEN_PLAN_RECEIPT_ERROR_CODE="preview_receipt_missing"
    TOKEN_PLAN_RECEIPT_ERROR_MESSAGE="Token revoke preview receipt is missing trust metadata"
    return 1
  fi

  preview_expires_at="$(jq -r '.preview_expires_at // empty' <<< "${receipt_trust_json}")"
  if [[ -n "${preview_expires_at}" ]]; then
    preview_expires_epoch="$(cf_iso8601_to_epoch "${preview_expires_at}" 2>/dev/null || true)"
    if [[ -z "${preview_expires_epoch}" || "${preview_expires_epoch}" -le "$(cf_now_epoch)" ]]; then
      TOKEN_PLAN_RECEIPT_ERROR_CODE="preview_expired"
      TOKEN_PLAN_RECEIPT_ERROR_MESSAGE="Token revoke preview receipt has expired"
      return 1
    fi
  fi

  if [[ "$(jq -r '.lane // empty' <<< "${receipt_trust_json}")" != "$(jq -r '.lane // empty' <<< "${trust_json}")" ]]; then
    TOKEN_PLAN_RECEIPT_ERROR_CODE="preview_lane_mismatch"
    TOKEN_PLAN_RECEIPT_ERROR_MESSAGE="Token revoke preview receipt was created on a different auth lane"
    return 1
  fi

  if [[ "$(jq -r '.policy_fingerprint' <<< "${receipt_trust_json}")" != "${policy_fingerprint}" ]]; then
    TOKEN_PLAN_RECEIPT_ERROR_CODE="preview_version_mismatch"
    TOKEN_PLAN_RECEIPT_ERROR_MESSAGE="Token revoke preview receipt no longer matches the current runtime policy"
    return 1
  fi

  if [[ "$(jq -r '.request_fingerprint' <<< "${receipt_trust_json}")" != "${request_fingerprint}" || "$(jq -r '.target_fingerprint' <<< "${receipt_trust_json}")" != "${target_fingerprint}" ]]; then
    TOKEN_PLAN_RECEIPT_ERROR_CODE="preview_payload_mismatch"
    TOKEN_PLAN_RECEIPT_ERROR_MESSAGE="Token revoke preview receipt does not match the current revoke request"
    return 1
  fi

  if ! cf_runtime_lock_validate_lease "${lock_key}" "${ACK_PLAN}"; then
    TOKEN_PLAN_RECEIPT_ERROR_CODE="lock_unavailable"
    TOKEN_PLAN_RECEIPT_ERROR_MESSAGE="Token revoke preview lease lock is no longer valid"
    return 1
  fi

  TOKEN_PLAN_RECEIPT_TRUST_JSON="${receipt_trust_json}"
  return 0
}

cleanup_lock() {
  if [[ -n "${lock_key:-}" && "${RELEASE_LOCK_ON_EXIT:-0}" == "1" ]]; then
    cf_runtime_lock_release "${lock_key}"
  fi
}

if [[ "${PLAN_MODE}" == "1" ]]; then
  token_metadata_json="$(fetch_token_metadata)"
  if [[ "$(jq -r '.success == true' <<< "${token_metadata_json}")" != "true" ]]; then
    emit_failure_json \
      "token_lookup_failed" \
      "Unable to read token metadata before planning revocation." \
      "" \
      "" \
      "${trust_json}" \
      "${token_metadata_json}" | jq '.'
    exit 1
  fi

  operation_id="${CFCTL_OPERATION_ID:-$(cf_runtime_operation_id)}"
  if ! cf_runtime_lock_acquire "${lock_key}" "${operation_id}" "lease" "${preview_ttl_seconds}" "$(jq -n --arg action "token.revoke" --arg operation_id "${operation_id}" --arg token_id "${TOKEN_ID}" '{action: $action, operation_id: $operation_id, token_id: $token_id}')"; then
    emit_failure_json \
      "lock_unavailable" \
      "Another operation already holds the token revoke preview lease." \
      "${operation_id}" \
      "" \
      "${trust_json}" \
      "${token_metadata_json}" | jq '.'
    exit 1
  fi

  plan_json="$(
    jq -n \
      --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
      --arg operation_id "${operation_id}" \
      --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
      --arg scheme "${CF_ACTIVE_AUTH_SCHEME:-unknown}" \
      --arg credential_env "${CF_ACTIVE_TOKEN_ENV:-unknown}" \
      --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" \
      --arg artifact_path "${artifact_path}" \
      --argjson trust "${trust_json}" \
      --argjson metadata "${token_metadata_json}" \
      '
        {
          generated_at: $generated_at,
          ok: true,
          action: "token.revoke",
          planned: true,
          operation_id: $operation_id,
          auth: {
            lane: $lane,
            scheme: $scheme,
            credential_env: $credential_env
          },
          trust: $trust,
          account_id: $account_id,
          artifact_path: $artifact_path,
          result: {
            token_metadata: $metadata,
            warning: "Plan only. No token was revoked. Real revocation also requires --confirm delete."
          },
          error: null
        }
      '
  )"
  cf_write_json_file "${artifact_path}" "${plan_json}"
  jq '.' <<< "${plan_json}"
  exit 0
fi

if [[ -z "${ACK_PLAN}" ]]; then
  emit_failure_json \
    "preview_required" \
    "token revoke requires a reviewed preview first. Run with --plan, then re-run with --ack-plan <operation-id> --confirm delete." \
    "" \
    "" \
    "${trust_json}" \
    "null" | jq '.'
  exit 1
fi

if [[ "${CONFIRMATION}" != "delete" ]]; then
  emit_failure_json \
    "confirmation_required" \
    "token revoke requires --confirm delete for the real mutation." \
    "${ACK_PLAN}" \
    "" \
    "${trust_json}" \
    "null" | jq '.'
  exit 1
fi

if ! preview_artifact_path="$(find_matching_plan_receipt "${ACK_PLAN}")"; then
  emit_failure_json \
    "preview_receipt_missing" \
    "No matching token revoke preview receipt was found for --ack-plan ${ACK_PLAN}" \
    "${ACK_PLAN}" \
    "" \
    "${trust_json}" \
    "${token_metadata_json}" | jq '.'
  exit 1
fi

if ! validate_plan_receipt "${preview_artifact_path}"; then
  emit_failure_json \
    "${TOKEN_PLAN_RECEIPT_ERROR_CODE}" \
    "${TOKEN_PLAN_RECEIPT_ERROR_MESSAGE}" \
    "${ACK_PLAN}" \
    "${preview_artifact_path}" \
    "${trust_json}" \
    "${token_metadata_json}" | jq '.'
  exit 1
fi

token_metadata_json="$(fetch_token_metadata)"
if [[ "$(jq -r '.success == true' <<< "${token_metadata_json}")" != "true" ]]; then
  emit_failure_json \
    "token_lookup_failed" \
    "Unable to read token metadata before revocation." \
    "${ACK_PLAN}" \
    "${preview_artifact_path}" \
    "${TOKEN_PLAN_RECEIPT_TRUST_JSON}" \
    "${token_metadata_json}" | jq '.'
  exit 1
fi

operation_id="${ACK_PLAN}"
RELEASE_LOCK_ON_EXIT="1"
trap cleanup_lock EXIT

capture_json="$(cf_api_capture DELETE "/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/${TOKEN_ID}")"

report_json="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg operation_id "${operation_id}" \
    --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg scheme "${CF_ACTIVE_AUTH_SCHEME:-unknown}" \
    --arg credential_env "${CF_ACTIVE_TOKEN_ENV:-unknown}" \
    --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" \
    --arg artifact_path "${artifact_path}" \
    --arg preview_artifact_path "${preview_artifact_path}" \
    --argjson token_metadata "${token_metadata_json}" \
    --argjson response "${capture_json}" \
    --argjson trust "${TOKEN_PLAN_RECEIPT_TRUST_JSON}" \
    '
      {
        generated_at: $generated_at,
        ok: ($response.success // false),
        action: "token.revoke",
        planned: false,
        operation_id: $operation_id,
        auth: {
          lane: $lane,
          scheme: $scheme,
          credential_env: $credential_env
        },
        trust: $trust,
        account_id: $account_id,
        artifact_path: $artifact_path,
        result: {
          preview_artifact_path: $preview_artifact_path,
          token_metadata: $token_metadata,
          response: $response,
          warning: "Token revocation artifacts include token id/name/status/expiry metadata only. No token secret value is logged."
        },
        error: (
          if ($response.success // false) then
            null
          else
            {
              status_code: ($response.status_code // null),
              errors: ($response.errors // []),
              request: ($response.request // null)
            }
          end
        )
      }
    '
)"

cf_write_json_file "${artifact_path}" "${report_json}"

if [[ "$(jq -r '.success == true' <<< "${capture_json}")" != "true" ]]; then
  jq '.' <<< "${report_json}"
  exit 1
fi

stdout_json="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg operation_id "${operation_id}" \
    --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg scheme "${CF_ACTIVE_AUTH_SCHEME:-unknown}" \
    --arg credential_env "${CF_ACTIVE_TOKEN_ENV:-unknown}" \
    --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" \
    --arg artifact_path "${artifact_path}" \
    --arg preview_artifact_path "${preview_artifact_path}" \
    --argjson token_metadata "${token_metadata_json}" \
    --argjson response "${capture_json}" \
    --argjson trust "${TOKEN_PLAN_RECEIPT_TRUST_JSON}" \
    '
      {
        generated_at: $generated_at,
        ok: true,
        action: "token.revoke",
        planned: false,
        operation_id: $operation_id,
        auth: {
          lane: $lane,
          scheme: $scheme,
          credential_env: $credential_env
        },
        trust: $trust,
        account_id: $account_id,
        artifact_path: $artifact_path,
        result: {
          preview_artifact_path: $preview_artifact_path,
          token_id: ($token_metadata.result.id // $trust.target.token_id // null),
          name: ($token_metadata.result.name // null),
          prior_status: ($token_metadata.result.status // null),
          issued_on: ($token_metadata.result.issued_on // null),
          expires_on: ($token_metadata.result.expires_on // null),
          response_id: ($response.result.id // null),
          warning: "Token revocation completed. No token secret value was logged."
        },
        error: null
      }
    '
)"

jq '.' <<< "${stdout_json}"
