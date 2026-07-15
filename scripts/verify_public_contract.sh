#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFCTL="${ROOT_DIR}/cfctl"
ACCOUNT_ID="${CFCTL_PUBLIC_CONTRACT_ACCOUNT_ID:-}"
PROFILE="${CFCTL_PUBLIC_CONTRACT_PROFILE:-}"
PERMISSION_GROUP_ID="${CFCTL_PUBLIC_CONTRACT_PERMISSION_GROUP_ID:-}"
CONFIRM="${CFCTL_PUBLIC_CONTRACT_CONFIRM:-}"

die() {
  echo "public-contract verification failed: $*" >&2
  exit 1
}

require_value() {
  local name="$1"
  local value="$2"
  [[ -n "${value}" ]] || die "${name} must be set"
}

run_json() {
  local label="$1"
  shift
  local output
  if ! output="$("$@" 2>/dev/null)"; then
    die "${label}: command failed"
  fi
  jq -e '.schema_version == 2 and .ok == true' <<< "${output}" >/dev/null \
    || die "${label}: invalid or unsuccessful ResultEnvelopeV2"
  printf '%s\n' "${output}"
}

operation_id() {
  jq -r '.operation_id // .result.plan.operation_id // empty' <<< "$1"
}

approve_and_run() {
  local label="$1"
  local operation="$2"
  local approve_json
  local approved_plan_json
  local run_json_result
  [[ -n "${operation}" ]] || die "${label}: plan omitted operation ID"
  approve_json="$(run_json "${label} approval" "${CFCTL}" plans approve "${operation}" --yes --json)"
  jq -e --arg operation "${operation}" '
    .operation_id == $operation and .result.operation_id == $operation
  ' <<< "${approve_json}" >/dev/null || die "${label}: approval did not bind the exact operation"
  approved_plan_json="$(run_json "${label} approved-plan readback" "${CFCTL}" plans status "${operation}" --json)"
  jq -e --arg operation "${operation}" '
    .operation_id == $operation and .result.status == "approved"
  ' <<< "${approved_plan_json}" >/dev/null || die "${label}: approved plan was not durably readable"
  run_json_result="$(run_json "${label} execution" "${CFCTL}" plans run "${operation}" --json)"
  jq -e --arg operation "${operation}" '
    .operation_id == $operation
    and .performed == true
    and .verification.state == "passed"
  ' <<< "${run_json_result}" >/dev/null || die "${label}: apply or verification did not pass"
  printf '%s\n' "${run_json_result}"
}

file_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

require_value CFCTL_PUBLIC_CONTRACT_ACCOUNT_ID "${ACCOUNT_ID}"
require_value CFCTL_PUBLIC_CONTRACT_PROFILE "${PROFILE}"
require_value CFCTL_PUBLIC_CONTRACT_PERMISSION_GROUP_ID "${PERMISSION_GROUP_ID}"
[[ "${CONFIRM}" == "mint-rotate-revoke-disposable-token" ]] \
  || die "set CFCTL_PUBLIC_CONTRACT_CONFIRM=mint-rotate-revoke-disposable-token after reviewing this script"
command -v jq >/dev/null 2>&1 || die "jq is required"

cd "${ROOT_DIR}"

profile_json="$(run_json "profile status" "${CFCTL}" auth status "${PROFILE}" --json)"
jq -e --arg profile "${PROFILE}" --arg account "${ACCOUNT_ID}" '
  .result.profile.id == $profile
  and .result.profile.account_id == $account
  and .result.credential_available == true
  and .result.selected == true
' <<< "${profile_json}" >/dev/null \
  || die "the requested account-backed profile must already be selected and credentialed"

sync_json="$(run_json "catalog sync" "${CFCTL}" catalog sync --json)"
jq -e '
  .performed == false
  and .verification.state == "not_applicable"
  and .result.coverage.total > 3000
  and .result.coverage.blocked > 0
' <<< "${sync_json}" >/dev/null || die "live catalog coverage contract failed"

permissions_json="$(run_json "permission inventory" "${CFCTL}" keys permissions --account "${ACCOUNT_ID}" --json)"
jq -e --arg permission "${PERMISSION_GROUP_ID}" '
  .performed == true
  and any(.result.result[]; .id == $permission)
' <<< "${permissions_json}" >/dev/null \
  || die "permission group is not present in the live account inventory"

proof_root="$(mktemp -d "${TMPDIR:-/tmp}/cfctl-public-contract.XXXXXX")"
mint_value="${proof_root}/minted-token"
rotated_value="${proof_root}/rotated-token"
token_id=""
revoked=false

cleanup() {
  local cleanup_plan
  local cleanup_operation
  if [[ -n "${token_id}" && "${revoked}" != true ]]; then
    set +e
    cleanup_plan="$(${CFCTL} keys revoke --id "${token_id}" --account "${ACCOUNT_ID}" --json 2>/dev/null)"
    cleanup_operation="$(operation_id "${cleanup_plan}")"
    if [[ -n "${cleanup_operation}" ]]; then
      ${CFCTL} plans approve "${cleanup_operation}" --yes --json >/dev/null 2>&1
      ${CFCTL} plans run "${cleanup_operation}" --json >/dev/null 2>&1
    fi
    set -e
  fi
  case "${proof_root}" in
    "${TMPDIR:-/tmp}"/cfctl-public-contract.*) rm -rf -- "${proof_root}" ;;
    *) echo "refusing to remove unexpected proof path: ${proof_root}" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM

unique_suffix="$(date -u +%Y%m%d%H%M%S)-$$"
mint_plan="$(run_json "token mint plan" \
  "${CFCTL}" keys mint \
  --name "cfctl-disposable-smoke-${unique_suffix}" \
  --permission "${PERMISSION_GROUP_ID}" \
  --account "${ACCOUNT_ID}" \
  --ttl-hours 1 \
  --value-out "${mint_value}" \
  --json)"
mint_run="$(approve_and_run "token mint" "$(operation_id "${mint_plan}")")"
token_id="$(jq -r '.result.result.id // empty' <<< "${mint_run}")"
[[ -n "${token_id}" ]] || die "token mint response omitted the disposable token ID"
[[ -s "${mint_value}" ]] || die "token mint did not create the sink file"
[[ "$(file_mode "${mint_value}")" == "600" ]] || die "minted token sink is not mode 0600"

rotate_plan="$(run_json "token rotation plan" \
  "${CFCTL}" keys rotate \
  --id "${token_id}" \
  --account "${ACCOUNT_ID}" \
  --value-out "${rotated_value}" \
  --json)"
approve_and_run "token rotation" "$(operation_id "${rotate_plan}")" >/dev/null
[[ -s "${rotated_value}" ]] || die "token rotation did not create the sink file"
[[ "$(file_mode "${rotated_value}")" == "600" ]] || die "rotated token sink is not mode 0600"

revoke_plan="$(run_json "token revocation plan" \
  "${CFCTL}" keys revoke --id "${token_id}" --account "${ACCOUNT_ID}" --json)"
revoke_run="$(approve_and_run "token revocation" "$(operation_id "${revoke_plan}")")"
jq -e '
  .verification.state == "passed"
  and (.verification.basis | contains("not found"))
' <<< "${revoke_run}" >/dev/null || die "revocation was not proven by live not-found readback"
revoked=true

echo "public-contract verification passed: disposable token was minted, rotated, revoked, and verified"
