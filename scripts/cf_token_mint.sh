#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_require_backend_dispatch "cfctl token mint ..."

usage() {
  cat <<'EOF'
Usage:
  cfctl token mint --name <token-name> [options]

Options:
  --permission <name>         Permission group name. Repeatable.
  --permission-id <id>        Permission group id. Repeatable.
  --zone <zone-name>          Zone resource target. Repeatable.
  --zone-id <zone-id>         Zone resource target by id. Repeatable.
  --all-zones-in-account      Target all zones in the current account.
  --expires-on <iso8601>      Explicit token expiry.
  --ttl-hours <hours>         Relative expiry in hours from now.
  --condition-json <json>     Top-level token condition JSON.
  --condition-file <path>     File containing top-level token condition JSON.
  --policy-json <json>        Full policies array JSON. Bypasses convenience builders.
  --policy-file <path>        File containing full policies array JSON.
  --ack-plan <operation-id>   Confirm execution of a previously reviewed preview.
  --value-out <path>          Write the raw minted token value to a file instead of stdout JSON.
  --reveal-token-once         Print the raw minted token once only when runtime policy explicitly allows it.
  --plan                      Print the prepared request and do not mint.
  -h, --help                  Show this help.

Examples:
  cfctl token permission-groups --name "DNS"
  cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --plan
  cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --ack-plan <operation-id> --value-out /tmp/dns-editor.token
  cfctl token mint --name account-audit --permission "Account Settings Read" --ttl-hours 24 --plan
  cfctl token mint --name zone-admin --permission "DNS Write" --permission "Zone Read" --all-zones-in-account --ttl-hours 12 --plan
EOF
}

TOKEN_NAME=""
PLAN_MODE="0"
EXPIRES_ON=""
TTL_HOURS=""
CONDITION_JSON=""
CONDITION_FILE=""
POLICY_JSON=""
POLICY_FILE=""
ACK_PLAN=""
VALUE_OUT=""
REVEAL_TOKEN_ONCE="0"
ALL_ZONES_IN_ACCOUNT="0"

declare -a PERMISSION_NAMES=()
declare -a PERMISSION_IDS=()
declare -a ZONE_NAMES=()
declare -a ZONE_IDS=()

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --name)
      TOKEN_NAME="$2"
      shift 2
      ;;
    --name=*)
      TOKEN_NAME="${1#*=}"
      shift
      ;;
    --permission)
      PERMISSION_NAMES+=("$2")
      shift 2
      ;;
    --permission=*)
      PERMISSION_NAMES+=("${1#*=}")
      shift
      ;;
    --permission-id)
      PERMISSION_IDS+=("$2")
      shift 2
      ;;
    --permission-id=*)
      PERMISSION_IDS+=("${1#*=}")
      shift
      ;;
    --zone)
      ZONE_NAMES+=("$2")
      shift 2
      ;;
    --zone=*)
      ZONE_NAMES+=("${1#*=}")
      shift
      ;;
    --zone-id)
      ZONE_IDS+=("$2")
      shift 2
      ;;
    --zone-id=*)
      ZONE_IDS+=("${1#*=}")
      shift
      ;;
    --all-zones-in-account)
      ALL_ZONES_IN_ACCOUNT="1"
      shift
      ;;
    --expires-on)
      EXPIRES_ON="$2"
      shift 2
      ;;
    --expires-on=*)
      EXPIRES_ON="${1#*=}"
      shift
      ;;
    --ttl-hours)
      TTL_HOURS="$2"
      shift 2
      ;;
    --ttl-hours=*)
      TTL_HOURS="${1#*=}"
      shift
      ;;
    --condition-json)
      CONDITION_JSON="$2"
      shift 2
      ;;
    --condition-json=*)
      CONDITION_JSON="${1#*=}"
      shift
      ;;
    --condition-file)
      CONDITION_FILE="$2"
      shift 2
      ;;
    --condition-file=*)
      CONDITION_FILE="${1#*=}"
      shift
      ;;
    --policy-json)
      POLICY_JSON="$2"
      shift 2
      ;;
    --policy-json=*)
      POLICY_JSON="${1#*=}"
      shift
      ;;
    --policy-file)
      POLICY_FILE="$2"
      shift 2
      ;;
    --policy-file=*)
      POLICY_FILE="${1#*=}"
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
    --value-out)
      VALUE_OUT="$2"
      shift 2
      ;;
    --value-out=*)
      VALUE_OUT="${1#*=}"
      shift
      ;;
    --reveal-token-once)
      REVEAL_TOKEN_ONCE="1"
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

if [[ -z "${TOKEN_NAME}" ]]; then
  echo "--name is required" >&2
  exit 1
fi

if [[ -n "${EXPIRES_ON}" && -n "${TTL_HOURS}" ]]; then
  echo "Specify either --expires-on or --ttl-hours, not both." >&2
  exit 1
fi

REQUESTED_EXPIRES_ON="${EXPIRES_ON}"

if [[ -n "${TTL_HOURS}" ]]; then
  EXPIRES_ON="$(
    jq -nr --arg hours "${TTL_HOURS}" \
      '((now + (($hours | tonumber) * 3600)) | strftime("%Y-%m-%dT%H:%M:%SZ"))'
  )"
fi

if [[ -n "${POLICY_JSON}" && -n "${POLICY_FILE}" ]]; then
  echo "Specify either --policy-json or --policy-file, not both." >&2
  exit 1
fi

if [[ -n "${CONDITION_JSON}" && -n "${CONDITION_FILE}" ]]; then
  echo "Specify either --condition-json or --condition-file, not both." >&2
  exit 1
fi

if [[ "${ALL_ZONES_IN_ACCOUNT}" == "1" && "${#ZONE_NAMES[@]}" -gt 0 ]]; then
  echo "Do not combine --all-zones-in-account with --zone." >&2
  exit 1
fi

if [[ "${ALL_ZONES_IN_ACCOUNT}" == "1" && "${#ZONE_IDS[@]}" -gt 0 ]]; then
  echo "Do not combine --all-zones-in-account with --zone-id." >&2
  exit 1
fi

condition_payload="$(cf_resolve_json_payload "${CONDITION_JSON}" "${CONDITION_FILE}")"
policies_payload="$(cf_resolve_json_payload "${POLICY_JSON}" "${POLICY_FILE}")"

resolve_permission_groups() {
  local all_groups_json="$1"
  local name
  local permission_id
  local names_json='[]'
  local ids_json='[]'

  if [[ "${#PERMISSION_NAMES[@]}" -gt 0 ]]; then
    for name in "${PERMISSION_NAMES[@]}"; do
      if [[ "$(jq --arg name "${name}" '[.result[]? | select(.name == $name)] | length' <<< "${all_groups_json}")" == "0" ]]; then
        local suggestions
        suggestions="$(
          jq -r \
            --arg needle "$(printf '%s' "${name}" | tr '[:upper:]' '[:lower:]')" \
            '
              [
                .result[]?
                | select((.name | ascii_downcase) | contains($needle))
                | .name
              ][0:10] | join(", ")
            ' <<< "${all_groups_json}"
        )"
        if [[ -n "${suggestions}" ]]; then
          echo "Unknown permission group name: ${name}. Suggestions: ${suggestions}" >&2
        else
          echo "Unknown permission group name: ${name}" >&2
        fi
        exit 1
      fi
    done
    names_json="$(printf '%s\n' "${PERMISSION_NAMES[@]}" | jq -R . | jq -s '.')"
  fi

  if [[ "${#PERMISSION_IDS[@]}" -gt 0 ]]; then
    for permission_id in "${PERMISSION_IDS[@]}"; do
      if [[ "$(jq --arg id "${permission_id}" '[.result[]? | select(.id == $id)] | length' <<< "${all_groups_json}")" == "0" ]]; then
        echo "Unknown permission group id: ${permission_id}" >&2
        exit 1
      fi
    done
    ids_json="$(printf '%s\n' "${PERMISSION_IDS[@]}" | jq -R . | jq -s '.')"
  fi

  jq \
    -n \
    --argjson groups "${all_groups_json}" \
    --argjson names "${names_json}" \
    --argjson ids "${ids_json}" \
    '
      ($groups.result // [])
      | map(
          . as $group
          | select((($names | index($group.name)) != null) or (($ids | index($group.id)) != null))
        )
      | map({id, name, scopes})
      | unique_by(.id)
    '
}

build_zone_resources_json() {
  if [[ "${ALL_ZONES_IN_ACCOUNT}" == "1" ]]; then
    jq -n \
      --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" \
      '
        {
          ("com.cloudflare.api.account." + $account_id): {
            "com.cloudflare.api.account.zone.*": "*"
          }
        }
      '
    return
  fi

  local zone_id
  local resources='{}'

  if [[ "${#ZONE_IDS[@]}" -gt 0 ]]; then
    for zone_id in "${ZONE_IDS[@]}"; do
      resources="$(
        jq --arg zone_id "${zone_id}" '. + {("com.cloudflare.api.account.zone." + $zone_id): "*"}' <<< "${resources}"
      )"
    done
  fi

  local zone_name
  if [[ "${#ZONE_NAMES[@]}" -gt 0 ]]; then
    for zone_name in "${ZONE_NAMES[@]}"; do
      zone_id="$(cf_resolve_zone_id "${zone_name}")"
      if [[ -z "${zone_id}" || "${zone_id}" == "null" ]]; then
        echo "Unable to resolve zone id for ${zone_name}" >&2
        exit 1
      fi
      resources="$(
        jq --arg zone_id "${zone_id}" '. + {("com.cloudflare.api.account.zone." + $zone_id): "*"}' <<< "${resources}"
      )"
    done
  fi

  printf '%s\n' "${resources}"
}

build_account_policy_json() {
  local permission_groups_json="$1"

  jq -n \
    --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" \
    --argjson permission_groups "${permission_groups_json}" \
    '
      {
        effect: "allow",
        resources: {
          ("com.cloudflare.api.account." + $account_id): "*"
        },
        permission_groups: ($permission_groups | map({id, name}))
      }
    '
}

build_zone_policy_json() {
  local permission_groups_json="$1"
  local resources_json="$2"

  jq -n \
    --argjson permission_groups "${permission_groups_json}" \
    --argjson resources "${resources_json}" \
    '
      {
        effect: "allow",
        resources: $resources,
        permission_groups: ($permission_groups | map({id, name}))
      }
    '
}

build_policies_json() {
  if [[ -n "${policies_payload}" ]]; then
    printf '%s\n' "${policies_payload}"
    return
  fi

  if [[ "${#PERMISSION_NAMES[@]}" -eq 0 && "${#PERMISSION_IDS[@]}" -eq 0 ]]; then
    echo "When not using --policy-json or --policy-file, provide at least one --permission or --permission-id." >&2
    exit 1
  fi

  local groups_capture
  groups_capture="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/permission_groups")"
  if [[ "$(jq -r '.success == true' <<< "${groups_capture}")" != "true" ]]; then
    echo "Unable to list token permission groups for this account." >&2
    jq '{success, errors, messages, request, status_code}' <<< "${groups_capture}" >&2
    exit 1
  fi

  local permission_groups_json
  permission_groups_json="$(resolve_permission_groups "${groups_capture}")"

  local account_permission_groups
  local zone_permission_groups
  local policies='[]'

  account_permission_groups="$(jq '[.[] | select((.scopes // []) | index("com.cloudflare.api.account"))]' <<< "${permission_groups_json}")"
  zone_permission_groups="$(jq '[.[] | select((.scopes // []) | index("com.cloudflare.api.account.zone"))]' <<< "${permission_groups_json}")"

  if [[ "$(jq 'length > 0' <<< "${account_permission_groups}")" == "true" ]]; then
    policies="$(
      jq -n --argjson policies "${policies}" --argjson policy "$(build_account_policy_json "${account_permission_groups}")" '$policies + [$policy]'
    )"
  fi

  if [[ "$(jq 'length > 0' <<< "${zone_permission_groups}")" == "true" ]]; then
    if [[ "${ALL_ZONES_IN_ACCOUNT}" != "1" && "${#ZONE_NAMES[@]}" -eq 0 && "${#ZONE_IDS[@]}" -eq 0 ]]; then
      echo "Zone-scoped permission groups require --zone, --zone-id, or --all-zones-in-account." >&2
      exit 1
    fi

    local zone_resources_json
    zone_resources_json="$(build_zone_resources_json)"
    if [[ "${zone_resources_json}" == "{}" ]]; then
      echo "Zone-scoped permission groups require zone resources." >&2
      exit 1
    fi

    policies="$(
      jq -n --argjson policies "${policies}" --argjson policy "$(build_zone_policy_json "${zone_permission_groups}" "${zone_resources_json}")" '$policies + [$policy]'
    )"
  fi

  if [[ "$(jq 'length == 0' <<< "${policies}")" == "true" ]]; then
    echo "No policies were generated from the provided permissions." >&2
    exit 1
  fi

  printf '%s\n' "${policies}"
}

policies_json="$(build_policies_json)"

request_body="$(
  jq -n \
    --arg name "${TOKEN_NAME}" \
    --arg expires_on "${EXPIRES_ON}" \
    --argjson policies "${policies_json}" \
    --argjson condition "$(if [[ -n "${condition_payload}" ]]; then printf '%s\n' "${condition_payload}"; else echo 'null'; fi)" \
    '
      {
        name: $name,
        policies: $policies
      }
      + (if $expires_on == "" then {} else {expires_on: $expires_on} end)
      + (if $condition == null then {} else {condition: $condition} end)
    '
)"

request_intent_json="$(
  jq -n \
    --arg name "${TOKEN_NAME}" \
    --arg expires_on "${REQUESTED_EXPIRES_ON}" \
    --arg ttl_hours "${TTL_HOURS}" \
    --argjson policies "${policies_json}" \
    --argjson condition "$(if [[ -n "${condition_payload}" ]]; then printf '%s\n' "${condition_payload}"; else echo 'null'; fi)" \
    '
      {
        name: $name,
        policies: $policies
      }
      + (if $expires_on == "" then {} else {expires_on: $expires_on} end)
      + (if $ttl_hours == "" then {} else {ttl_hours: ($ttl_hours | tonumber? // $ttl_hours)} end)
      + (if $condition == null then {} else {condition: $condition} end)
    '
)"

artifact_path="$(cf_inventory_file "auth" "token-mint")"
runtime_policy_json="$(cf_runtime_policy_json)"
token_policy_json="$(
  jq -n \
    --argjson runtime_policy "${runtime_policy_json}" \
    '
      ($runtime_policy.operation_defaults.secret_sensitive // {}) as $defaults
      | ($runtime_policy.special_operations["token.mint"] // {}) as $special
      | $defaults + $special + {preview_ack_flag: ($runtime_policy.preview_ack_flag // "--ack-plan")}
    '
)"
policy_version="$(jq -r '.version // 0' "$(cf_runtime_catalog_path)")"
target_json="$(jq -n --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" --arg name "${TOKEN_NAME}" '{account_id: $account_id, name: $name}')"
request_fingerprint="$(cf_hash_json "${request_intent_json}")"
target_fingerprint="$(cf_hash_json "${target_json}")"
policy_fingerprint="$(cf_hash_json "${token_policy_json}")"
preview_ttl_seconds="$(jq -r '.preview_ttl_seconds // 900' <<< "${token_policy_json}")"
lock_key="$(cf_runtime_lock_key "token" "token" "mint" "${target_json}")"
trust_json="$(
  jq -n \
    --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg policy_version "${policy_version}" \
    --arg policy_fingerprint "${policy_fingerprint}" \
    --arg request_fingerprint "${request_fingerprint}" \
    --arg target_fingerprint "${target_fingerprint}" \
    --argjson policy "${token_policy_json}" \
    --argjson request "${request_intent_json}" \
    --argjson request_body "${request_body}" \
    --argjson target "${target_json}" \
    --arg preview_expires_at "$(cf_seconds_from_now_iso8601 "${preview_ttl_seconds}")" \
    --arg lock_key "${lock_key}" \
    '
      {
        action: "token.mint",
        surface: "token",
        operation: "mint",
        lane: $lane,
        policy_version: $policy_version,
        policy_fingerprint: $policy_fingerprint,
        request_fingerprint: $request_fingerprint,
        target_fingerprint: $target_fingerprint,
        policy: $policy,
        request: $request,
        request_body: $request_body,
        target: $target,
        preview_expires_at: $preview_expires_at,
        lock_key: $lock_key,
        lock_mode: ($policy.lock_strategy // "lease"),
        secret_policy: ($policy.secret_policy // "sink_only")
      }
    '
)"

emit_failure_json() {
  local code="$1"
  local message="$2"
  local operation_id="${3:-}"
  local preview_artifact_path="${4:-}"
  local trust_payload="${5:-null}"
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
      '
        {
          generated_at: $generated_at,
          ok: false,
          action: "token.mint",
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
              if $preview_artifact_path == "" then
                null
              else
                $preview_artifact_path
              end
            )
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

  for file in "${ROOT_DIR}"/var/inventory/auth/token-mint-*.json; do
    [[ -f "${file}" ]] || continue
    if jq -e \
      --arg operation_id "${operation_id}" \
      --arg lane "${current_lane}" \
      '
        .action == "token.mint"
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
    TOKEN_PLAN_RECEIPT_ERROR_MESSAGE="Token preview receipt is missing trust metadata"
    return 1
  fi

  preview_expires_at="$(jq -r '.preview_expires_at // empty' <<< "${receipt_trust_json}")"
  if [[ -n "${preview_expires_at}" ]]; then
    preview_expires_epoch="$(cf_iso8601_to_epoch "${preview_expires_at}" 2>/dev/null || true)"
    if [[ -z "${preview_expires_epoch}" || "${preview_expires_epoch}" -le "$(cf_now_epoch)" ]]; then
      TOKEN_PLAN_RECEIPT_ERROR_CODE="preview_expired"
      TOKEN_PLAN_RECEIPT_ERROR_MESSAGE="Token preview receipt has expired"
      return 1
    fi
  fi

  if [[ "$(jq -r '.lane // empty' <<< "${receipt_trust_json}")" != "$(jq -r '.lane // empty' <<< "${trust_json}")" ]]; then
    TOKEN_PLAN_RECEIPT_ERROR_CODE="preview_lane_mismatch"
    TOKEN_PLAN_RECEIPT_ERROR_MESSAGE="Token preview receipt was created on a different auth lane"
    return 1
  fi

  if [[ "$(jq -r '.policy_fingerprint' <<< "${receipt_trust_json}")" != "${policy_fingerprint}" ]]; then
    TOKEN_PLAN_RECEIPT_ERROR_CODE="preview_version_mismatch"
    TOKEN_PLAN_RECEIPT_ERROR_MESSAGE="Token preview receipt no longer matches the current runtime policy"
    return 1
  fi

  if [[ "$(jq -r '.request_fingerprint' <<< "${receipt_trust_json}")" != "${request_fingerprint}" || "$(jq -r '.target_fingerprint' <<< "${receipt_trust_json}")" != "${target_fingerprint}" ]]; then
    TOKEN_PLAN_RECEIPT_ERROR_CODE="preview_payload_mismatch"
    TOKEN_PLAN_RECEIPT_ERROR_MESSAGE="Token preview receipt does not match the current mint request"
    return 1
  fi

  if ! cf_runtime_lock_validate_lease "${lock_key}" "${ACK_PLAN}"; then
    TOKEN_PLAN_RECEIPT_ERROR_CODE="lock_unavailable"
    TOKEN_PLAN_RECEIPT_ERROR_MESSAGE="Token preview lease lock is no longer valid"
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
  operation_id="${CFCTL_OPERATION_ID:-$(cf_runtime_operation_id)}"
  if ! cf_runtime_lock_acquire "${lock_key}" "${operation_id}" "lease" "${preview_ttl_seconds}" "$(jq -n --arg action "token.mint" --arg operation_id "${operation_id}" --arg name "${TOKEN_NAME}" '{action: $action, operation_id: $operation_id, name: $name}')"; then
    emit_failure_json \
      "lock_unavailable" \
      "Another operation already holds the token mint preview lease." \
      "${operation_id}" \
      "" \
      "${trust_json}" | jq '.'
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
      --argjson request_body "${request_body}" \
      --argjson trust "${trust_json}" \
      '
        {
          generated_at: $generated_at,
          ok: true,
          action: "token.mint",
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
            request_body: $request_body,
            warning: "Plan only. No token was minted."
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
    "token mint requires a reviewed preview first. Run with --plan, then re-run with --ack-plan <operation-id>." \
    "" \
    "" \
    "${trust_json}" | jq '.'
  exit 1
fi

if ! preview_artifact_path="$(find_matching_plan_receipt "${ACK_PLAN}")"; then
  emit_failure_json \
    "preview_receipt_missing" \
    "No matching token preview receipt was found for --ack-plan ${ACK_PLAN}" \
    "${ACK_PLAN}" \
    "" \
    "${trust_json}" | jq '.'
  exit 1
fi

if ! validate_plan_receipt "${preview_artifact_path}"; then
  emit_failure_json \
    "${TOKEN_PLAN_RECEIPT_ERROR_CODE}" \
    "${TOKEN_PLAN_RECEIPT_ERROR_MESSAGE}" \
    "${ACK_PLAN}" \
    "${preview_artifact_path}" \
    "${trust_json}" | jq '.'
  exit 1
fi

request_body="$(jq -c '.request_body // empty' <<< "${TOKEN_PLAN_RECEIPT_TRUST_JSON}")"
if [[ -z "${request_body}" || "${request_body}" == "null" ]]; then
  request_body="$(
    jq -c '.request // empty' <<< "${TOKEN_PLAN_RECEIPT_TRUST_JSON}"
  )"
fi

if [[ "${REVEAL_TOKEN_ONCE}" == "1" ]] && ! cf_runtime_token_reveal_allowed; then
  emit_failure_json \
    "unsafe_secret_sink" \
    "Token stdout reveal is disabled by runtime policy. Use --value-out <path> instead." \
    "${ACK_PLAN}" \
    "${preview_artifact_path}" \
    "${TOKEN_PLAN_RECEIPT_TRUST_JSON}" | jq '.'
  exit 1
fi

if [[ -z "${VALUE_OUT}" && "${REVEAL_TOKEN_ONCE}" != "1" ]]; then
  emit_failure_json \
    "unsafe_secret_sink" \
    "Real token mint requires --value-out <path>. Stdout reveal is not the default delivery path." \
    "${ACK_PLAN}" \
    "${preview_artifact_path}" \
    "${TOKEN_PLAN_RECEIPT_TRUST_JSON}" | jq '.'
  exit 1
fi

if [[ -n "${VALUE_OUT}" ]]; then
  sink_check_json="$(cf_runtime_secret_sink_check_json "${VALUE_OUT}")"
  if [[ "$(jq -r '.ok' <<< "${sink_check_json}")" != "true" ]]; then
    emit_failure_json \
      "$(jq -r '.code' <<< "${sink_check_json}")" \
      "$(jq -r '.message' <<< "${sink_check_json}")" \
      "${ACK_PLAN}" \
      "${preview_artifact_path}" \
      "${TOKEN_PLAN_RECEIPT_TRUST_JSON}" | jq '.'
    exit 1
  fi
fi

operation_id="${ACK_PLAN}"
RELEASE_LOCK_ON_EXIT="1"
trap cleanup_lock EXIT

capture_json="$(cf_api_capture POST "/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens" -H "Content-Type: application/json" --data "${request_body}")"
capture_redacted="$(
  jq '
    if (.result | type) == "object" and (.result | has("value")) then
      .result.value = "REDACTED"
    else
      .
    end
  ' <<< "${capture_json}"
)"

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
    --arg value_out "${VALUE_OUT}" \
    --argjson request_body "${request_body}" \
    --argjson response "${capture_redacted}" \
    --argjson trust "${TOKEN_PLAN_RECEIPT_TRUST_JSON}" \
    '
      {
        generated_at: $generated_at,
        ok: ($response.success // false),
        action: "token.mint",
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
          value_out: (if $value_out == "" then null else $value_out end),
          request_body: $request_body,
          response: $response,
          warning: "Token secret is redacted in the artifact."
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
        }
      }
    '
)"

cf_write_json_file "${artifact_path}" "${report_json}"

if [[ "$(jq -r '.success == true' <<< "${capture_json}")" != "true" ]]; then
  jq '.' <<< "${report_json}"
  exit 1
fi

token_value="$(jq -r '.result.value // empty' <<< "${capture_json}")"
if [[ -n "${VALUE_OUT}" ]]; then
  umask 077
  printf '%s\n' "${token_value}" > "${VALUE_OUT}"
  cf_runtime_secret_sink_verify_permissions "${VALUE_OUT}"
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
    --arg value_out "${VALUE_OUT}" \
    --arg reveal_token_once "${REVEAL_TOKEN_ONCE}" \
    --argjson response "${capture_json}" \
    --argjson trust "${TOKEN_PLAN_RECEIPT_TRUST_JSON}" \
    '
      {
        generated_at: $generated_at,
        ok: true,
        action: "token.mint",
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
          token_id: ($response.result.id // null),
          name: ($response.result.name // null),
          status: ($response.result.status // null),
          issued_on: ($response.result.issued_on // null),
          expires_on: ($response.result.expires_on // null),
          modified_on: ($response.result.modified_on // null),
          value_out: (if $value_out == "" then null else $value_out end),
          token_value: (
            if $value_out != "" then
              null
            elif $reveal_token_once == "1" then
              ($response.result.value // null)
            else
              null
            end
          ),
          warning: (
            if $value_out != "" then
              "Token secret was written to value_out. Artifact output is redacted."
            elif $reveal_token_once == "1" then
              "Token secret is shown once because runtime policy explicitly allowed --reveal-token-once. Artifact output is redacted."
            else
              "Token secret is sink-only by policy. Use --value-out <path>."
            end
          )
        },
        error: null
      }
    '
)"

jq '.' <<< "${stdout_json}"
