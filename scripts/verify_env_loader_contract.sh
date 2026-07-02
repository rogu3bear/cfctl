#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"
# shellcheck disable=SC1091
source "${ROOT_DIR}/lib/runtime/env.sh"

fail() {
  echo "env-loader contract verification failed: $*" >&2
  exit 1
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cfctl-env-loader.XXXXXX")"
cleanup_env_loader_tmp() {
  local base
  if [[ -z "${TMP_DIR:-}" || ! -d "${TMP_DIR}" ]]; then
    return 0
  fi
  base="$(basename "${TMP_DIR}")"
  if [[ "${base}" != cfctl-env-loader.* || "${TMP_DIR}" == "${ROOT_DIR}" || "${TMP_DIR}" == "${ROOT_DIR}/"* ]]; then
    printf 'refusing to remove unexpected env-loader temp dir: %s\n' "${TMP_DIR}" >&2
    return 1
  fi
  rm -rf -- "${TMP_DIR}"
}
trap cleanup_env_loader_tmp EXIT

WORKSPACE_ENV="${TMP_DIR}/workspace.env"
{
  printf '%s\n' '# workspace env fixture'
  printf '%s\n' 'export CF_DEV_TOKEN=ws-dev-token'
  printf '%s\n' 'CF_GLOBAL_TOKEN="ws-global-token"'
  printf '%s\n' "CLOUDFLARE_EMAIL='ops@example.com'"
  printf '%s\r\n' 'CLOUDFLARE_ACCOUNT_ID=ws-account-id'
  printf '%s\n' 'STRIPE_SECRET_KEY=sk_disallowed'
  printf '%s\n' 'RESEND=disallowed'
  printf '%s\n' 'MLN_ADVISOR_ACCESS_CLIENT_ID=disallowed'
  printf '%s\n' 'CF_TOKEN_LANE=global'
  printf '%s\n' 'not a KEY=VALUE line'
} > "${WORKSPACE_ENV}"

SHARED_ENV="${TMP_DIR}/shared.env"
printf 'CF_DEV_TOKEN=shared-dev-token\n' > "${SHARED_ENV}"

SHARED_ENV_TWIN="${TMP_DIR}/shared-twin.env"
printf 'CF_DEV_TOKEN=shared-dev-token\n' > "${SHARED_ENV_TWIN}"

ALLOWLIST_JSON="$(cf_env_import_allowlist_json)"
jq -e '
  index("CF_DEV_TOKEN") != null
  and index("CF_GLOBAL_TOKEN") != null
  and index("CLOUDFLARE_EMAIL") != null
  and index("CLOUDFLARE_ACCOUNT_ID") != null
' <<< "${ALLOWLIST_JSON}" >/dev/null || fail "allowlist missing lane credentials, requirements, or catalog entries"
jq -e '
  index("STRIPE_SECRET_KEY") == null
  and index("RESEND") == null
  and index("MLN_ADVISOR_ACCESS_CLIENT_ID") == null
  and index("CF_TOKEN_LANE") == null
  and index("CF_SHARED_ENV_FILE") == null
  and index("CF_WORKSPACE_ENV_FILE") == null
  and index("CLOUDFLARE_API_TOKEN") == null
  and index("CLOUDFLARE_API_KEY") == null
' <<< "${ALLOWLIST_JSON}" >/dev/null || fail "allowlist must exclude unrelated secrets, control knobs, and derived auth vars"

(
  unset CF_DEV_TOKEN CF_GLOBAL_TOKEN CLOUDFLARE_EMAIL CLOUDFLARE_ACCOUNT_ID
  unset STRIPE_SECRET_KEY RESEND MLN_ADVISOR_ACCESS_CLIENT_ID CF_TOKEN_LANE
  cf_import_env_file_strict "${WORKSPACE_ENV}"
  [[ "${CF_DEV_TOKEN:-}" == "ws-dev-token" ]] || exit 1
  [[ "${CF_GLOBAL_TOKEN:-}" == "ws-global-token" ]] || exit 1
  [[ "${CLOUDFLARE_EMAIL:-}" == "ops@example.com" ]] || exit 1
  [[ "${CLOUDFLARE_ACCOUNT_ID:-}" == "ws-account-id" ]] || exit 1
  [[ -z "${STRIPE_SECRET_KEY:-}" ]] || exit 1
  [[ -z "${RESEND:-}" ]] || exit 1
  [[ -z "${MLN_ADVISOR_ACCESS_CLIENT_ID:-}" ]] || exit 1
  [[ -z "${CF_TOKEN_LANE:-}" ]] || exit 1
) || fail "strict import grammar (export prefix, quotes, CRLF) or allowlist rejection"

(
  export CF_DEV_TOKEN="already-set"
  unset CF_GLOBAL_TOKEN CLOUDFLARE_EMAIL CLOUDFLARE_ACCOUNT_ID CF_TOKEN_LANE
  cf_import_env_file_strict "${WORKSPACE_ENV}"
  [[ "${CF_DEV_TOKEN}" == "already-set" ]] || exit 1
  [[ "${CF_GLOBAL_TOKEN:-}" == "ws-global-token" ]] || exit 1
) || fail "fill-gaps-only precedence"

EVAL_ENV="${TMP_DIR}/eval.env"
printf 'CF_DEV_TOKEN=$(touch %s/pwned)\n' "${TMP_DIR}" > "${EVAL_ENV}"
(
  unset CF_DEV_TOKEN
  cf_import_env_file_strict "${EVAL_ENV}"
  [[ "${CF_DEV_TOKEN:-}" == "\$(touch ${TMP_DIR}/pwned)" ]] || exit 1
) || fail "command substitution must import as a literal"
[[ ! -e "${TMP_DIR}/pwned" ]] || fail "importer executed embedded command substitution"

(
  unset CF_DEV_TOKEN CF_GLOBAL_TOKEN CLOUDFLARE_EMAIL CLOUDFLARE_ACCOUNT_ID CF_TOKEN_LANE
  export CF_SHARED_ENV_FILE="${SHARED_ENV}"
  export CF_REPO_ENV_FILE="/nonexistent/cfctl-empty-env"
  export CF_WORKSPACE_ENV_FILE="${WORKSPACE_ENV}"
  cf_load_cloudflare_env_files
  [[ "${CF_DEV_TOKEN:-}" == "shared-dev-token" ]] || exit 1
  [[ "${CF_GLOBAL_TOKEN:-}" == "ws-global-token" ]] || exit 1
) || fail "loader must keep canonical shared value and fill gaps from workspace"

(
  unset CF_DEV_TOKEN CF_GLOBAL_TOKEN CLOUDFLARE_EMAIL CLOUDFLARE_ACCOUNT_ID CF_TOKEN_LANE
  export CF_SHARED_ENV_FILE="/nonexistent/cfctl-empty-env"
  export CF_REPO_ENV_FILE="/nonexistent/cfctl-empty-env"
  export CF_WORKSPACE_ENV_FILE=""
  cf_load_cloudflare_env_files
  [[ -z "${CF_DEV_TOKEN:-}" ]] || exit 1
) || fail "empty CF_WORKSPACE_ENV_FILE must disable the workspace import"

FP_WORKSPACE="$(cf_env_value_fingerprint_from_file "${WORKSPACE_ENV}" CF_DEV_TOKEN)"
FP_SHARED="$(cf_env_value_fingerprint_from_file "${SHARED_ENV}" CF_DEV_TOKEN)"
FP_SHARED_TWIN="$(cf_env_value_fingerprint_from_file "${SHARED_ENV_TWIN}" CF_DEV_TOKEN)"
[[ "${#FP_WORKSPACE}" -eq 12 ]] || fail "fingerprint must be 12 hex chars"
[[ "${FP_WORKSPACE}" != "${FP_SHARED}" ]] || fail "different values must produce different fingerprints"
[[ "${FP_SHARED}" == "${FP_SHARED_TWIN}" ]] || fail "equal values must produce equal fingerprints"
if cf_env_value_fingerprint_from_file "${SHARED_ENV}" CF_GLOBAL_TOKEN >/dev/null 2>&1; then
  fail "fingerprint of an absent variable must fail"
fi

(
  unset CF_DEV_TOKEN CF_GLOBAL_TOKEN CLOUDFLARE_EMAIL CLOUDFLARE_ACCOUNT_ID CF_TOKEN_LANE
  export CF_SHARED_ENV_FILE="${SHARED_ENV}"
  export CF_REPO_ENV_FILE="/nonexistent/cfctl-empty-env"
  export CF_WORKSPACE_ENV_FILE="${WORKSPACE_ENV}"
  cf_load_cloudflare_env_files
  provenance_json="$(cfctl_env_provenance_json)"
  jq -e '
    (.summary.drift_count >= 1)
    and ((.vars[] | select(.var == "CF_DEV_TOKEN") | .drift) == true)
    and ((.vars[] | select(.var == "CF_DEV_TOKEN") | .winner_source) == "shared")
    and ((.vars[] | select(.var == "CF_GLOBAL_TOKEN") | .drift) == false)
    and ((.vars[] | select(.var == "CF_GLOBAL_TOKEN") | .winner_source) == "workspace")
    and ((.summary.drift_vars | index("CF_DEV_TOKEN")) != null)
  ' <<< "${provenance_json}" >/dev/null || exit 1
  if grep -Eq 'ws-dev-token|shared-dev-token|ws-global-token|ops@example[.]com' <<< "${provenance_json}"; then
    exit 1
  fi
) || fail "provenance drift detection or value leakage"

echo "env-loader contract verification passed."
