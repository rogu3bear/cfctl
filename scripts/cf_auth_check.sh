#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_setup_log_pipe "auth-check" "build"

AUTH_CHECK_JSON='null'
TOKEN_VERIFY_JSON='null'
ACCOUNT_JSON='null'
SHARED_ENV_PRESENT='false'
REPO_ENV_PRESENT='false'
AUTH_SCHEME="${CF_ACTIVE_AUTH_SCHEME:-unknown}"

if [[ -f "${CF_SHARED_ENV_FILE:-${CF_SHARED_ENV_FILE_DEFAULT}}" ]]; then
  SHARED_ENV_PRESENT='true'
fi

if [[ -f "${CF_REPO_ENV_FILE:-${CF_REPO_ENV_FILE_DEFAULT}}" ]]; then
  REPO_ENV_PRESENT='true'
fi

case "${CF_ACTIVE_AUTH_SCHEME:-unknown}" in
  api_token)
    if [[ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ]]; then
      AUTH_CHECK_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/verify")"
      if [[ "$(jq -r '.success // false' <<< "${AUTH_CHECK_JSON}")" == "true" ]]; then
        TOKEN_VERIFY_JSON="${AUTH_CHECK_JSON}"
        AUTH_SCHEME='account_api_token'
      fi

      ACCOUNT_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}")"
    fi

    if [[ "${AUTH_SCHEME}" == "api_token" || "${AUTH_SCHEME}" == "unknown" ]]; then
      AUTH_CHECK_JSON="$(cf_api_capture GET "/user/tokens/verify")"
      TOKEN_VERIFY_JSON="${AUTH_CHECK_JSON}"
      AUTH_SCHEME='user_api_token'
    fi
    ;;
  global_api_key)
    AUTH_CHECK_JSON="$(cf_api_capture GET "/user")"
    AUTH_SCHEME='global_api_key'
    if [[ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ]]; then
      ACCOUNT_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}")"
    fi
    ;;
esac

OUTPUT_FILE="$(cf_inventory_file "auth" "auth-check")"

REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg shared_env_file "${CF_SHARED_ENV_FILE:-${CF_SHARED_ENV_FILE_DEFAULT}}" \
    --arg repo_env_file "${CF_REPO_ENV_FILE:-${CF_REPO_ENV_FILE_DEFAULT}}" \
    --arg cloudflare_account_id "${CLOUDFLARE_ACCOUNT_ID:-}" \
    --arg auth_scheme "${AUTH_SCHEME}" \
    --arg active_auth_scheme "${CF_ACTIVE_AUTH_SCHEME:-unknown}" \
    --arg active_token_lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg active_token_env "${CF_ACTIVE_TOKEN_ENV:-unknown}" \
    --arg wrangler_auth_env "$(if [[ "${CF_ACTIVE_AUTH_SCHEME:-unknown}" == "global_api_key" ]]; then echo CLOUDFLARE_API_KEY; else echo CLOUDFLARE_API_TOKEN; fi)" \
    --argjson shared_env_present "${SHARED_ENV_PRESENT}" \
    --argjson repo_env_present "${REPO_ENV_PRESENT}" \
    --argjson dev_token_present "$(if [[ -n "${CF_DEV_TOKEN:-}" ]]; then echo true; else echo false; fi)" \
    --argjson global_token_present "$(if [[ -n "${CF_GLOBAL_TOKEN:-}" ]]; then echo true; else echo false; fi)" \
    --argjson auth_check "${AUTH_CHECK_JSON}" \
    --argjson token_verify "${TOKEN_VERIFY_JSON}" \
    --argjson account "${ACCOUNT_JSON}" \
    '
      {
        generated_at: $generated_at,
        auth: {
          primary_token_env: "CF_DEV_TOKEN",
          emergency_token_env: "CF_GLOBAL_TOKEN",
          active_auth_scheme: $active_auth_scheme,
          active_token_lane: $active_token_lane,
          active_token_env: $active_token_env,
          auth_scheme: $auth_scheme,
          shared_env_file: $shared_env_file,
          shared_env_file_present: $shared_env_present,
          repo_env_file: $repo_env_file,
          repo_env_file_present: $repo_env_present,
          derived_wrangler_env: $wrangler_auth_env,
          available_tokens: {
            dev: $dev_token_present,
            global: $global_token_present
          }
        },
        auth_check: $auth_check,
        token_verify: $token_verify,
        account_context: {
          account_id: ($cloudflare_account_id | select(length > 0)),
          account: ($account.result // null)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Verified ${CF_ACTIVE_TOKEN_ENV:-CF_ACTIVE_API_TOKEN} against the Cloudflare API."
if [[ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ]]; then
  echo "Pinned account: ${CLOUDFLARE_ACCOUNT_ID}"
fi
echo "${REPORT_JSON}" | jq '{
  active_token_lane: .auth.active_token_lane,
  active_token_env: .auth.active_token_env,
  active_auth_scheme: .auth.active_auth_scheme,
  auth_scheme: .auth.auth_scheme,
  auth_status: (.auth_check.result.status // (if .auth_check.success == true then "ok" else "failed" end)),
  token_id: .token_verify.result.id,
  account_id: .account_context.account_id,
  account_name: .account_context.account.name
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
