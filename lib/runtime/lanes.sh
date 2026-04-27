#!/usr/bin/env bash

set -euo pipefail

cfctl_lane_auth_probe_json() {
  local lane="$1"
  local previous_state
  local lane_meta
  local auth_check="null"
  local account_check="null"
  local resolved_scheme="unknown"

  if ! lane_meta="$(cfctl_lane_meta "${lane}")" || [[ -z "${lane_meta}" || "${lane_meta}" == "null" ]]; then
    jq -n --arg lane "${lane}" '{lane: $lane, available: false, error: "unsupported_lane"}'
    return
  fi

  if ! cf_token_available_for_lane "${lane}"; then
    jq -n \
      --arg lane "${lane}" \
      --argjson lane_meta "${lane_meta}" \
      '
        {
          lane: $lane,
          available: false,
          credential_env: ($lane_meta.credential_env // null),
          auth_scheme: ($lane_meta.auth_scheme // null),
          error: "credential_missing"
        }
      '
    return
  fi

  previous_state="$(cf_current_auth_state_json)"
  cf_use_token_lane "${lane}"

  case "${CF_ACTIVE_AUTH_SCHEME:-unknown}" in
    api_token)
      if [[ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ]]; then
        auth_check="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/verify")"
        if [[ "$(jq -r '.success // false' <<< "${auth_check}")" == "true" ]]; then
          resolved_scheme="account_api_token"
        else
          auth_check="$(cf_api_capture GET "/user/tokens/verify")"
          resolved_scheme="user_api_token"
        fi
      else
        auth_check="$(cf_api_capture GET "/user/tokens/verify")"
        resolved_scheme="user_api_token"
      fi
      ;;
    global_api_key)
      auth_check="$(cf_api_capture GET "/user")"
      resolved_scheme="global_api_key"
      ;;
  esac

  if [[ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ]]; then
    account_check="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}")"
  fi

  cf_restore_auth_state_json "${previous_state}"

  jq -n \
    --arg lane "${lane}" \
    --arg resolved_scheme "${resolved_scheme}" \
    --argjson lane_meta "${lane_meta}" \
    --argjson auth_check "${auth_check}" \
    --argjson account_check "${account_check}" \
    '
      {
        lane: $lane,
        available: true,
        credential_env: ($lane_meta.credential_env // null),
        configured_auth_scheme: ($lane_meta.auth_scheme // null),
        resolved_auth_scheme: $resolved_scheme,
        wrangler_env: ($lane_meta.wrangler_env // null),
        auth_ok: ($auth_check.success // false),
        auth_check: $auth_check,
        account_check: $account_check
      }
    '
}

cfctl_collect_lane_health_json() {
  local lanes_json
  local reports='[]'
  local lane

  lanes_json="$(cfctl_supported_lanes_json)"
  while IFS= read -r lane; do
    reports="$(
      jq \
        --argjson report "$(cfctl_lane_auth_probe_json "${lane}")" \
        '. + [$report]' \
        <<< "${reports}"
    )"
  done < <(jq -r '.[]' <<< "${lanes_json}")

  jq -n \
    --arg active_lane "${CF_ACTIVE_TOKEN_LANE:-}" \
    --argjson lanes "${reports}" \
    '
      {
        active_lane: (if $active_lane == "" then null else $active_lane end),
        lanes: $lanes,
        summary: {
          configured_lane_count: ($lanes | map(select(.available == true)) | length),
          healthy_lane_count: ($lanes | map(select(.auth_ok == true)) | length),
          healthy_lanes: ($lanes | map(select(.auth_ok == true)) | map(.lane))
        }
      }
    '
}

cfctl_compare_permission_all_lanes() {
  local surface="$1"
  local action="$2"
  local operation="${3:-}"
  local previous_state
  local lanes_json
  local reports='[]'
  local lane

  previous_state="$(cf_current_auth_state_json)"
  lanes_json="$(cfctl_supported_lanes_json)"

  while IFS= read -r lane; do
    if ! cf_token_available_for_lane "${lane}"; then
      reports="$(
        jq \
          --arg lane "${lane}" \
          '. + [{lane: $lane, available: false, permission: {state: "unknown", basis: "credential_missing", errors: [], request: null, status_code: null, permission_family: "Cloudflare API"}}]' \
          <<< "${reports}"
      )"
      continue
    fi

    cf_use_token_lane "${lane}"
    reports="$(
      jq \
        --arg lane "${lane}" \
        --argjson permission "$(cfctl_probe_permission "${surface}" "${action}" "${operation}")" \
        '. + [{lane: $lane, available: true, permission: $permission}]' \
        <<< "${reports}"
    )"
  done < <(jq -r '.[]' <<< "${lanes_json}")

  cf_restore_auth_state_json "${previous_state}"

  jq -n \
    --arg active_lane "${CF_ACTIVE_TOKEN_LANE:-}" \
    --argjson lanes "${reports}" \
    '
      {
        active_lane: (if $active_lane == "" then null else $active_lane end),
        lanes: $lanes,
        summary: {
          allowed_lanes: ($lanes | map(select(.permission.state == "allowed")) | map(.lane)),
          denied_lanes: ($lanes | map(select(.permission.state == "denied")) | map(.lane)),
          unknown_lanes: ($lanes | map(select(.permission.state == "unknown")) | map(.lane))
        }
      }
    '
}
