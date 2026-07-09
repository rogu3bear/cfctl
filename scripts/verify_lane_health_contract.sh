#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1091
source "${ROOT_DIR}/lib/runtime/cfctl.sh"
# shellcheck disable=SC1091
source "${ROOT_DIR}/commands/cfctl.sh"

fail() {
  echo "lane-health contract verification failed: $*" >&2
  exit 1
}

assert_jq() {
  local label="$1"
  local expr="$2"
  local payload="$3"

  jq -e "${expr}" <<< "${payload}" >/dev/null || fail "${label}: ${expr}"
}

CF_TEST_LANE=""
CF_TEST_DEV_STATUS="active"
CF_TEST_DEV_ACCOUNT_SUCCESS="true"

cf_token_available_for_lane() {
  return 0
}

cf_lane_requirements_met() {
  return 0
}

cf_current_auth_state_json() {
  printf '{}\n'
}

cf_use_token_lane() {
  CF_TEST_LANE="$1"
  export CF_TEST_LANE
  if [[ "${CF_TEST_LANE}" == "dev" ]]; then
    CF_ACTIVE_AUTH_SCHEME="api_token"
  else
    CF_ACTIVE_AUTH_SCHEME="global_api_key"
  fi
  export CF_ACTIVE_AUTH_SCHEME
}

cf_restore_auth_state_json() {
  return 0
}

cf_api_capture() {
  local method="$1"
  local path="$2"

  case "${CF_TEST_LANE}:${method}:${path}" in
    dev:GET:/accounts/account-1/tokens/verify)
      if [[ "${CF_TEST_DEV_STATUS}" == "malformed" ]]; then
        jq -n '{success:true,errors:[],messages:[],result:{}}'
      else
        jq -n \
          --arg status "${CF_TEST_DEV_STATUS}" \
          '{success:true,errors:[],messages:[],result:{id:"dev-token",status:$status}}'
      fi
      ;;
    global:GET:/user)
      jq -n '{success:true,errors:[],messages:[],result:{id:"global-user"}}'
      ;;
    dev:GET:/accounts/account-1)
      jq -n \
        --argjson success "${CF_TEST_DEV_ACCOUNT_SUCCESS}" \
        '{success:$success,errors:(if $success then [] else [{code:9109,message:"Invalid access token"}] end),messages:[],result:(if $success then {id:"account-1"} else null end)}'
      ;;
    global:GET:/accounts/account-1)
      jq -n '{success:true,errors:[],messages:[],result:{id:"account-1"}}'
      ;;
    *)
      jq -n \
        --arg method "${method}" \
        --arg path "${path}" \
        '{success:false,errors:[{code:9999,message:("unexpected fixture request " + $method + " " + $path)}],messages:[],result:null}'
      ;;
  esac
}

export CLOUDFLARE_ACCOUNT_ID="account-1"

CF_TEST_DEV_STATUS="active"
CF_TEST_DEV_ACCOUNT_SUCCESS="true"
ACTIVE_JSON="$(cfctl_lane_auth_probe_json dev)"
assert_jq "active token is healthy" '.auth_ok == true and .health_status == "healthy" and .token_status == "active" and .account_ok == true' "${ACTIVE_JSON}"

CF_TEST_DEV_STATUS="expired"
EXPIRED_JSON="$(cfctl_lane_auth_probe_json dev)"
assert_jq "expired token is unsafe despite HTTP success" '.auth_ok == false and .health_status == "expired" and .token_status == "expired"' "${EXPIRED_JSON}"

CF_TEST_DEV_STATUS="disabled"
DISABLED_JSON="$(cfctl_lane_auth_probe_json dev)"
assert_jq "disabled token is unsafe" '.auth_ok == false and .health_status == "disabled" and .token_status == "disabled"' "${DISABLED_JSON}"

CF_TEST_DEV_STATUS="malformed"
MALFORMED_JSON="$(cfctl_lane_auth_probe_json dev)"
assert_jq "missing token status fails closed" '.auth_ok == false and .health_status == "invalid_token_status" and .token_status == null' "${MALFORMED_JSON}"

CF_TEST_DEV_STATUS="active"
CF_TEST_DEV_ACCOUNT_SUCCESS="false"
ACCOUNT_DENIED_JSON="$(cfctl_lane_auth_probe_json dev)"
assert_jq "account denial makes an active token unusable" '.auth_ok == false and .health_status == "account_access_denied" and .token_status == "active" and .account_ok == false' "${ACCOUNT_DENIED_JSON}"

CF_TEST_DEV_STATUS="expired"
CF_TEST_DEV_ACCOUNT_SUCCESS="false"
LANES_JSON="$(cfctl_collect_lane_health_json)"
assert_jq "healthy emergency lane does not mask the default lane" '
  .summary.healthy_lanes == ["global"]
  and .summary.default_lane == "dev"
  and .summary.default_lane_healthy == false
  and .summary.default_lane_status == "expired"
  and .summary.emergency_healthy_lanes == ["global"]
' "${LANES_JSON}"

CLEAN_LANES='{"summary":{"configured_lane_count":2,"healthy_lane_count":2,"healthy_lanes":["dev","global"],"default_lane":"dev","default_lane_healthy":true,"default_lane_status":"healthy"}}'
UNSAFE_LANES='{"summary":{"configured_lane_count":2,"healthy_lane_count":1,"healthy_lanes":["global"],"default_lane":"dev","default_lane_healthy":false,"default_lane_status":"expired"}}'
NO_LANES='{"summary":{"configured_lane_count":0,"healthy_lane_count":0,"healthy_lanes":[],"default_lane":"dev","default_lane_healthy":false,"default_lane_status":"credential_missing"}}'
CLEAN_GUARDS='[{"path":"scripts/cf_api_apply.sh","guarded":true}]'
CLEAN_SECRETS='{"leak_count":0,"unsafe_secret_sink_count":0}'
CLEAN_REGISTRY='{"missing_count":0}'
CLEAN_PREVIEWS='{"expired_preview_count":0,"legacy_preview_count":0}'
EXPIRED_PREVIEWS='{"expired_preview_count":3,"legacy_preview_count":0}'
CLEAN_LOCKS='{"stale_lock_count":0,"orphaned_lock_count":0}'
STALE_LOCKS='{"stale_lock_count":1,"orphaned_lock_count":0}'
CLEAN_BYPASS='{"legacy_env_active":false,"legacy_env_allowed":false,"authorization_health":{"expired_count":0}}'
CLEAN_ENV='{"provenance":{"summary":{"drift_count":0}},"hygiene":{"stray_repo_env":{"present":false}}}'

doctor_dimensions() {
  cfctl_doctor_health_dimensions_json \
    "$1" \
    "${CLEAN_GUARDS}" \
    "${CLEAN_SECRETS}" \
    "${CLEAN_REGISTRY}" \
    "$2" \
    "$3" \
    "${CLEAN_BYPASS}" \
    "${CLEAN_ENV}"
}

CLEAN_HEALTH="$(doctor_dimensions "${CLEAN_LANES}" "${CLEAN_PREVIEWS}" "${CLEAN_LOCKS}")"
assert_jq "clean doctor dimensions" '.overall_status == "healthy" and .safety.status == "safe" and .readiness.status == "ready" and .hygiene.status == "clean"' "${CLEAN_HEALTH}"

UNSAFE_HEALTH="$(doctor_dimensions "${UNSAFE_LANES}" "${CLEAN_PREVIEWS}" "${CLEAN_LOCKS}")"
assert_jq "default lane failure is a safety blocker" '.overall_status == "unsafe" and .safety.status == "unsafe" and (.safety.blockers | map(.code) | index("default_lane_unhealthy")) != null' "${UNSAFE_HEALTH}"

BOOTSTRAP_HEALTH="$(doctor_dimensions "${NO_LANES}" "${CLEAN_PREVIEWS}" "${CLEAN_LOCKS}")"
assert_jq "missing credentials preserve actionable bootstrap semantics" '.overall_status == "bootstrap_required" and .safety.status == "bootstrap_required" and (.safety.blockers | length) == 0' "${BOOTSTRAP_HEALTH}"

HYGIENE_HEALTH="$(doctor_dimensions "${CLEAN_LANES}" "${EXPIRED_PREVIEWS}" "${CLEAN_LOCKS}")"
assert_jq "expired previews are visible hygiene, not false degraded trust" '.overall_status == "healthy" and .safety.status == "safe" and .readiness.status == "ready" and .hygiene.status == "attention" and (.hygiene.findings | map(.code) | index("expired_previews")) != null' "${HYGIENE_HEALTH}"

READINESS_HEALTH="$(doctor_dimensions "${CLEAN_LANES}" "${CLEAN_PREVIEWS}" "${STALE_LOCKS}")"
assert_jq "stale locks block readiness" '.overall_status == "degraded" and .safety.status == "safe" and .readiness.status == "blocked" and (.readiness.blockers | map(.code) | index("stale_locks")) != null' "${READINESS_HEALTH}"

echo "lane-health contract verification passed"
