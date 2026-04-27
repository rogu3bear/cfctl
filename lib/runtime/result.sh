#!/usr/bin/env bash

set -euo pipefail

cfctl_current_auth_json() {
  jq -n \
    --arg lane "${CF_ACTIVE_TOKEN_LANE:-}" \
    --arg scheme "${CF_ACTIVE_AUTH_SCHEME:-}" \
    --arg credential_env "${CF_ACTIVE_TOKEN_ENV:-}" \
    --arg token_env "$(if [[ "${CF_ACTIVE_AUTH_SCHEME:-}" == "global_api_key" ]]; then echo CLOUDFLARE_API_KEY; else echo CLOUDFLARE_API_TOKEN; fi)" \
    '
      {
        lane: (if $lane == "" then null else $lane end),
        scheme: (if $scheme == "" then null else $scheme end),
        credential_env: (if $credential_env == "" then null else $credential_env end),
        wrangler_env: (if $token_env == "" then null else $token_env end)
      }
    '
}

cfctl_emit_result() {
  local ok="$1"
  local action="$2"
  local surface="$3"
  local backend="$4"
  local performed="$5"
  local permission_json="$6"
  local verification_json="$7"
  local summary_json="$8"
  local result_json="${9:-null}"
  local backend_artifact_path="${10:-}"
  local error_code="${11:-}"
  local error_message="${12:-}"
  local operation="${13:-}"
  local error_guidance_json="${14:-null}"
  local runtime_file
  local target_json
  local report_json
  local auth_json
  local operation_id
  local trust_json

  runtime_file="$(cf_inventory_file "runtime" "$(cfctl_slugify "${action}-${surface}")")"
  target_json="$(cfctl_target_json)"
  auth_json="$(cfctl_current_auth_json)"
  operation_id="${CFCTL_OPERATION_ID:-}"
  trust_json="${CFCTL_TRUST_JSON:-null}"

  report_json="$(
    jq -n \
      --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
      --arg action "${action}" \
      --arg surface "${surface}" \
      --arg backend "${backend}" \
      --arg backend_artifact_path "${backend_artifact_path}" \
      --arg runtime_file "${runtime_file}" \
      --arg error_code "${error_code}" \
      --arg error_message "${error_message}" \
      --arg operation "${operation}" \
      --arg operation_id "${operation_id}" \
      --argjson ok "${ok}" \
      --argjson performed "${performed}" \
      --argjson auth "${auth_json}" \
      --argjson trust "${trust_json}" \
      --argjson target "${target_json}" \
      --argjson permission_status "${permission_json}" \
      --argjson verification_status "${verification_json}" \
      --argjson summary "${summary_json}" \
      --argjson result "${result_json}" \
      --argjson error_guidance "${error_guidance_json}" \
      '
        {
          generated_at: $generated_at,
          ok: $ok,
          action: $action,
          surface: $surface,
          operation: (if $operation == "" then null else $operation end),
          operation_id: (if $operation_id == "" then null else $operation_id end),
          auth: $auth,
          trust: (if $trust == null then null else $trust end),
          target: $target,
          backend: $backend,
          performed: $performed,
          permission_status: $permission_status,
          verification_status: $verification_status,
          summary: $summary,
          backend_artifact_path: (if $backend_artifact_path == "" then null else $backend_artifact_path end),
          artifact_path: $runtime_file,
          result: $result,
          error: (
            if $error_code == "" then
              null
            else
              {
                code: $error_code,
                message: $error_message,
                next_step: ($error_guidance.next_step // null),
                recommended_command: ($error_guidance.recommended_command // null),
                recommended_lane: ($error_guidance.recommended_lane // null)
              }
            end
          )
        }
      '
  )"

  cf_write_json_file "${runtime_file}" "${report_json}"
  jq '.' "${runtime_file}"

  if [[ "${ok}" != "true" ]]; then
    return 1
  fi
}
