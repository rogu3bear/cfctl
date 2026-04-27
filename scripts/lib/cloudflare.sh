#!/usr/bin/env bash

set -euo pipefail

CF_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CF_REPO_ROOT="$(cd "${CF_LIB_DIR}/../.." && pwd)"
CF_OPERATOR_HOME="${CF_OPERATOR_HOME:-${HOME}}"
CF_SHARED_ENV_FILE_DEFAULT="${CF_SHARED_ENV_FILE_DEFAULT:-${CF_OPERATOR_HOME}/dev/.env}"
CF_REPO_ENV_FILE_DEFAULT="${CF_REPO_ENV_FILE_DEFAULT:-${CF_REPO_ROOT}/.env.local}"
CF_API_BASE="${CF_API_BASE:-https://api.cloudflare.com/client/v4}"
CF_TOKEN_LANE_DEFAULT="${CF_TOKEN_LANE_DEFAULT:-dev}"
CF_RUNTIME_CATALOG_PATH_DEFAULT="${CF_RUNTIME_CATALOG_PATH_DEFAULT:-${CF_REPO_ROOT}/catalog/runtime.json}"

cf_repo_root() {
  printf '%s\n' "${CF_REPO_ROOT}"
}

cf_timestamp() {
  date -u +"%Y%m%dT%H%M%SZ"
}

cf_now_epoch() {
  date -u +"%s"
}

cf_seconds_from_now_iso8601() {
  local seconds="${1:-0}"
  jq -nr --arg seconds "${seconds}" '((now + ($seconds | tonumber)) | strftime("%Y-%m-%dT%H:%M:%SZ"))'
}

cf_iso8601_to_epoch() {
  local timestamp="${1:-}"
  jq -nr --arg timestamp "${timestamp}" '$timestamp | fromdateiso8601'
}

cf_runtime_catalog_path() {
  printf '%s\n' "${CF_RUNTIME_CATALOG_PATH:-${CF_RUNTIME_CATALOG_PATH_DEFAULT}}"
}

cf_runtime_catalog_json() {
  cat "$(cf_runtime_catalog_path)"
}

cf_runtime_policy_json() {
  jq -c '.policy // {}' "$(cf_runtime_catalog_path)"
}

cf_hash_text() {
  local text="${1:-}"

  if command -v shasum >/dev/null 2>&1; then
    printf '%s' "${text}" | shasum -a 256 | awk '{print $1}'
    return
  fi

  if command -v openssl >/dev/null 2>&1; then
    printf '%s' "${text}" | openssl dgst -sha256 | awk '{print $NF}'
    return
  fi

  echo "Missing required hash tool: shasum or openssl" >&2
  exit 1
}

cf_hash_json() {
  local payload="${1:-null}"
  local normalized

  normalized="$(jq -cS '.' <<< "${payload}")"
  cf_hash_text "${normalized}"
}

cf_realpath_best_effort() {
  local path="${1:-}"
  local directory
  local base

  if [[ -z "${path}" ]]; then
    return 1
  fi

  if [[ "${path}" != /* ]]; then
    path="${PWD}/${path}"
  fi

  directory="$(cd -P "$(dirname "${path}")" 2>/dev/null && pwd)" || return 1
  base="$(basename "${path}")"
  printf '%s/%s\n' "${directory}" "${base}"
}

cf_path_within_dir() {
  local path="${1:-}"
  local directory="${2:-}"
  local resolved_path
  local resolved_directory

  resolved_path="$(cf_realpath_best_effort "${path}")" || return 1
  resolved_directory="$(cf_realpath_best_effort "${directory}")" || return 1

  [[ "${resolved_path}" == "${resolved_directory}" || "${resolved_path}" == "${resolved_directory}/"* ]]
}

cf_repo_relative_path() {
  local path="${1:-}"
  local resolved_path
  local resolved_repo

  resolved_path="$(cf_realpath_best_effort "${path}")" || return 1
  resolved_repo="$(cf_realpath_best_effort "${CF_REPO_ROOT}")" || return 1

  if [[ "${resolved_path}" == "${resolved_repo}" ]]; then
    printf '.\n'
    return
  fi

  if [[ "${resolved_path}" == "${resolved_repo}/"* ]]; then
    printf '%s\n' "${resolved_path#${resolved_repo}/}"
    return
  fi

  printf '%s\n' "${resolved_path}"
}

cf_require_tools() {
  local tool
  for tool in "$@"; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
      echo "Missing required tool: ${tool}" >&2
      exit 1
    fi
  done
}

cf_token_env_name_for_lane() {
  local lane="${1:-}"

  case "${lane}" in
    dev)
      printf 'CF_DEV_TOKEN\n'
      ;;
    global)
      printf 'CF_GLOBAL_TOKEN\n'
      ;;
    *)
      return 1
      ;;
  esac
}

cf_token_available_for_lane() {
  local lane="${1:-}"
  local env_name

  if ! env_name="$(cf_token_env_name_for_lane "${lane}")"; then
    return 1
  fi

  [[ -n "${!env_name:-}" ]]
}

cf_select_active_token() {
  local requested_lane="${CF_TOKEN_LANE:-${CF_TOKEN_LANE_DEFAULT}}"

  if [[ -n "${CF_API_TOKEN_OVERRIDE:-}" ]]; then
    export CF_ACTIVE_TOKEN_LANE="override"
    export CF_ACTIVE_TOKEN_ENV="CF_API_TOKEN_OVERRIDE"
    export CF_ACTIVE_AUTH_SCHEME="api_token"
    export CF_ACTIVE_AUTH_SECRET="${CF_API_TOKEN_OVERRIDE}"
  else
    local env_name=""
    if ! env_name="$(cf_token_env_name_for_lane "${requested_lane}")"; then
      echo "Unsupported CF_TOKEN_LANE: ${requested_lane}. Expected one of: dev, global." >&2
      exit 1
    fi

    if [[ -z "${!env_name:-}" ]]; then
      echo "${env_name} must be set for CF_TOKEN_LANE=${requested_lane}" >&2
      exit 1
    fi

    export CF_ACTIVE_TOKEN_LANE="${requested_lane}"
    export CF_ACTIVE_TOKEN_ENV="${env_name}"
    export CF_ACTIVE_AUTH_SECRET="${!env_name}"

    case "${requested_lane}" in
      dev)
        export CF_ACTIVE_AUTH_SCHEME="api_token"
        ;;
      global)
        export CF_ACTIVE_AUTH_SCHEME="global_api_key"
        cf_require_var CLOUDFLARE_EMAIL
        ;;
    esac
  fi

  if [[ "${CF_ACTIVE_AUTH_SCHEME}" == "api_token" ]]; then
    export CF_ACTIVE_API_TOKEN="${CF_ACTIVE_AUTH_SECRET}"
    export CLOUDFLARE_API_TOKEN="${CF_ACTIVE_AUTH_SECRET}"
    unset CLOUDFLARE_API_KEY
  else
    unset CF_ACTIVE_API_TOKEN
    unset CLOUDFLARE_API_TOKEN
    export CLOUDFLARE_API_KEY="${CF_ACTIVE_AUTH_SECRET}"
  fi
}

cf_current_auth_state_json() {
  jq -n \
    --arg token_lane "${CF_TOKEN_LANE:-}" \
    --arg token_env "${CF_ACTIVE_TOKEN_ENV:-}" \
    --arg auth_scheme "${CF_ACTIVE_AUTH_SCHEME:-}" \
    --argjson override_active "$(if [[ -n "${CF_API_TOKEN_OVERRIDE:-}" ]]; then echo true; else echo false; fi)" \
    '
      {
        CF_TOKEN_LANE: $token_lane,
        CF_ACTIVE_TOKEN_ENV: $token_env,
        CF_ACTIVE_AUTH_SCHEME: $auth_scheme,
        CF_API_TOKEN_OVERRIDE_ACTIVE: $override_active
      }
    '
}

cf_restore_auth_state_json() {
  local state_json="$1"

  local token_lane
  token_lane="$(jq -r '.CF_TOKEN_LANE // empty' <<< "${state_json}")"
  if [[ -n "${token_lane}" ]]; then
    export CF_TOKEN_LANE="${token_lane}"
  else
    unset CF_TOKEN_LANE
  fi

  cf_select_active_token
}

cf_use_token_lane() {
  local lane="$1"
  export CF_TOKEN_LANE="${lane}"
  cf_select_active_token
}

cf_with_token_lane() {
  local lane="$1"
  shift

  local previous_state
  local status

  previous_state="$(cf_current_auth_state_json)"
  cf_use_token_lane "${lane}"
  set +e
  "$@"
  status="$?"
  set -e
  cf_restore_auth_state_json "${previous_state}"
  return "${status}"
}

cf_runtime_operation_id() {
  printf '%s-%s-%s\n' "$(cf_timestamp)" "$$" "${RANDOM}${RANDOM}"
}

cf_runtime_dir() {
  local dir="${CF_REPO_ROOT}/var/runtime"
  mkdir -p "${dir}"
  printf '%s\n' "${dir}"
}

cf_runtime_lock_dir() {
  local relative_dir
  local dir

  relative_dir="$(jq -r '.runtime_lock_dir // "var/runtime/locks"' <<< "$(cf_runtime_policy_json)")"
  dir="${CF_REPO_ROOT}/${relative_dir}"
  mkdir -p "${dir}"
  printf '%s\n' "${dir}"
}

cf_runtime_admin_dir() {
  local relative_dir
  local dir

  relative_dir="$(jq -r '.runtime_admin_dir // "var/runtime/admin"' <<< "$(cf_runtime_policy_json)")"
  dir="${CF_REPO_ROOT}/${relative_dir}"
  mkdir -p "${dir}"
  printf '%s\n' "${dir}"
}

cf_runtime_backend_bypass_env_name() {
  jq -r '.direct_script_override_env // "CF_BACKEND_BYPASS_FILE"' <<< "$(cf_runtime_policy_json)"
}

cf_runtime_legacy_bypass_env_name() {
  jq -r '.legacy_bypass_env // "CF_BACKEND_BYPASS"' <<< "$(cf_runtime_policy_json)"
}

cf_runtime_legacy_bypass_allowed() {
  [[ "$(jq -r '.legacy_bypass_env_allowed // false' <<< "$(cf_runtime_policy_json)")" == "true" ]]
}

cf_runtime_token_reveal_allowed() {
  [[ "$(jq -r '.token_reveal_allowed // false' <<< "$(cf_runtime_policy_json)")" == "true" ]]
}

cf_runtime_lock_ttl_seconds() {
  jq -r '.lock_ttl_seconds // 1800' <<< "$(cf_runtime_policy_json)"
}

cf_runtime_preview_ttl_seconds() {
  jq -r '.preview_ttl_seconds // 900' <<< "$(cf_runtime_policy_json)"
}

cf_runtime_lock_key() {
  local namespace="$1"
  local surface="$2"
  local operation="$3"
  local target_json="${4:-null}"

  cf_hash_json "$(
    jq -n \
      --arg namespace "${namespace}" \
      --arg surface "${surface}" \
      --arg operation "${operation}" \
      --argjson target "${target_json}" \
      '
        {
          namespace: $namespace,
          surface: $surface,
          operation: $operation,
          target: $target
        }
      '
  )"
}

cf_runtime_lock_path() {
  local lock_key="$1"
  printf '%s/%s.lock\n' "$(cf_runtime_lock_dir)" "${lock_key}"
}

cf_runtime_lock_metadata_path() {
  local lock_path="$1"
  printf '%s/lock.json\n' "${lock_path}"
}

cf_runtime_lock_status_json() {
  local lock_path="$1"
  local metadata_path
  local metadata='null'
  local now_epoch
  local expires_epoch
  local stale="false"
  local exists="false"
  local orphaned="false"
  local current_host
  local pid_value

  if [[ -d "${lock_path}" ]]; then
    exists="true"
    metadata_path="$(cf_runtime_lock_metadata_path "${lock_path}")"
    if [[ -f "${metadata_path}" ]]; then
      metadata="$(cat "${metadata_path}")"
    else
      stale="true"
    fi
  fi

  if [[ "${exists}" == "true" && "${stale}" != "true" ]]; then
    now_epoch="$(cf_now_epoch)"
    expires_epoch="$(jq -r '.expires_at // empty' <<< "${metadata}")"
    if [[ -n "${expires_epoch}" ]]; then
      if ! expires_epoch="$(cf_iso8601_to_epoch "${expires_epoch}" 2>/dev/null)"; then
        stale="true"
      elif (( expires_epoch <= now_epoch )); then
        stale="true"
      fi
    fi
  fi

  if [[ "${exists}" == "true" && "${stale}" != "true" ]]; then
    current_host="$(hostname)"
    if [[ "$(jq -r '.lock_mode // empty' <<< "${metadata}")" != "lease" && "$(jq -r '.hostname // empty' <<< "${metadata}")" == "${current_host}" ]]; then
      pid_value="$(jq -r '.pid // empty' <<< "${metadata}")"
      if [[ -n "${pid_value}" ]] && ! kill -0 "${pid_value}" 2>/dev/null; then
        orphaned="true"
        stale="true"
      fi
    fi
  fi

  jq -n \
    --arg lock_path "${lock_path}" \
    --argjson exists "${exists}" \
    --argjson stale "${stale}" \
    --argjson orphaned "${orphaned}" \
    --argjson metadata "${metadata}" \
    '
      {
        lock_path: $lock_path,
        exists: $exists,
        stale: $stale,
        orphaned: $orphaned,
        metadata: $metadata
      }
    '
}

cf_runtime_lock_acquire() {
  local lock_key="$1"
  local operation_id="$2"
  local lock_mode="$3"
  local ttl_seconds="${4:-$(cf_runtime_lock_ttl_seconds)}"
  local summary_json="${5:-null}"
  local lock_path
  local metadata_path
  local metadata_json
  local retry_count=0

  lock_path="$(cf_runtime_lock_path "${lock_key}")"

  while true; do
    if mkdir "${lock_path}" 2>/dev/null; then
      metadata_path="$(cf_runtime_lock_metadata_path "${lock_path}")"
      metadata_json="$(
        jq -n \
          --arg lock_key "${lock_key}" \
          --arg operation_id "${operation_id}" \
          --arg lock_mode "${lock_mode}" \
          --arg issued_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
          --arg expires_at "$(cf_seconds_from_now_iso8601 "${ttl_seconds}")" \
          --arg user "${USER:-unknown}" \
          --arg hostname "$(hostname)" \
          --arg pid "$$" \
          --argjson summary "${summary_json}" \
          '
            {
              lock_key: $lock_key,
              operation_id: $operation_id,
              lock_mode: $lock_mode,
              issued_at: $issued_at,
              expires_at: $expires_at,
              user: $user,
              hostname: $hostname,
              pid: ($pid | tonumber),
              summary: $summary
            }
          '
      )"
      cf_write_json_file "${metadata_path}" "${metadata_json}"
      CF_RUNTIME_LOCK_PATH="${lock_path}"
      CF_RUNTIME_LOCK_METADATA_JSON="${metadata_json}"
      return 0
    fi

    if [[ "$(jq -r '.stale' <<< "$(cf_runtime_lock_status_json "${lock_path}")")" == "true" && "${retry_count}" -lt 1 ]]; then
      rm -rf "${lock_path}"
      retry_count=$((retry_count + 1))
      continue
    fi

    CF_RUNTIME_LOCK_PATH="${lock_path}"
    CF_RUNTIME_LOCK_METADATA_JSON="$(jq -c '.metadata // null' <<< "$(cf_runtime_lock_status_json "${lock_path}")")"
    return 1
  done
}

cf_runtime_lock_validate_lease() {
  local lock_key="$1"
  local operation_id="$2"
  local status_json

  status_json="$(cf_runtime_lock_status_json "$(cf_runtime_lock_path "${lock_key}")")"
  if [[ "$(jq -r '.exists' <<< "${status_json}")" != "true" ]]; then
    return 1
  fi

  if [[ "$(jq -r '.stale' <<< "${status_json}")" == "true" ]]; then
    return 1
  fi

  [[ "$(jq -r '.metadata.operation_id // empty' <<< "${status_json}")" == "${operation_id}" ]]
}

cf_runtime_lock_release() {
  local lock_key="$1"
  local lock_path

  lock_path="$(cf_runtime_lock_path "${lock_key}")"
  if [[ -d "${lock_path}" ]]; then
    rm -rf "${lock_path}"
  fi
}

cf_runtime_lock_health_json() {
  local lock_dir
  local reports='[]'
  local lock_path
  local status_json

  lock_dir="$(cf_runtime_lock_dir)"
  for lock_path in "${lock_dir}"/*.lock; do
    [[ -d "${lock_path}" ]] || continue
    status_json="$(cf_runtime_lock_status_json "${lock_path}")"
    reports="$(
      jq --argjson status "${status_json}" '. + [$status]' <<< "${reports}"
    )"
  done

  jq -n \
    --arg lock_dir "${lock_dir}" \
    --argjson locks "${reports}" \
    '
      {
        lock_dir: $lock_dir,
        lock_count: ($locks | length),
        stale_lock_count: ($locks | map(select(.stale == true)) | length),
        orphaned_lock_count: ($locks | map(select(.orphaned == true)) | length),
        locks: $locks
      }
    '
}

cf_runtime_lock_clear_stale_json() {
  local lock_dir
  local reports='[]'
  local lock_path
  local status_json
  local removed="false"

  lock_dir="$(cf_runtime_lock_dir)"
  for lock_path in "${lock_dir}"/*.lock; do
    [[ -d "${lock_path}" ]] || continue
    status_json="$(cf_runtime_lock_status_json "${lock_path}")"
    removed="false"
    if [[ "$(jq -r '.stale' <<< "${status_json}")" == "true" ]]; then
      rm -rf "${lock_path}"
      removed="true"
    fi
    reports="$(
      jq \
        --arg path "${lock_path}" \
        --argjson removed "${removed}" \
        --argjson status "${status_json}" \
        '. + [{path: $path, removed: $removed, status: $status}]' \
        <<< "${reports}"
    )"
  done

  jq -n \
    --arg lock_dir "${lock_dir}" \
    --argjson results "${reports}" \
    '
      {
        lock_dir: $lock_dir,
        cleared_count: ($results | map(select(.removed == true)) | length),
        inspected_count: ($results | length),
        results: $results
      }
    '
}

cf_backend_authorization_issue() {
  local allowed_backends_json="$1"
  local reason="$2"
  local ttl_minutes="${3:-10}"
  local artifact_path
  local authorization_json

  artifact_path="$(cf_runtime_admin_dir)/backend-bypass-$(cf_runtime_operation_id).json"
  authorization_json="$(
    jq -n \
      --arg kind "backend_bypass_authorization" \
      --arg issued_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
      --arg expires_at "$(cf_seconds_from_now_iso8601 "$(( ttl_minutes * 60 ))")" \
      --arg user "${USER:-unknown}" \
      --arg hostname "$(hostname)" \
      --arg reason "${reason}" \
      --arg policy_version "$(jq -r '.version // 0' "$(cf_runtime_catalog_path)")" \
      --argjson allowed_backends "${allowed_backends_json}" \
      '
        {
          kind: $kind,
          issued_at: $issued_at,
          expires_at: $expires_at,
          issued_by: {
            user: $user,
            hostname: $hostname
          },
          reason: $reason,
          policy_version: $policy_version,
          allowed_backends: $allowed_backends
        }
      '
  )"
  cf_write_json_file "${artifact_path}" "${authorization_json}"
  printf '%s\n' "${artifact_path}"
}

cf_backend_authorization_validate() {
  local backend_path="$1"
  local env_name
  local authorization_path
  local backend_relative_path
  local authorization_json
  local expires_at
  local expires_epoch

  env_name="$(cf_runtime_backend_bypass_env_name)"
  authorization_path="${!env_name:-}"
  if [[ -z "${authorization_path}" || ! -f "${authorization_path}" ]]; then
    return 1
  fi

  authorization_json="$(cat "${authorization_path}")"
  if [[ "$(jq -r '.kind // empty' <<< "${authorization_json}")" != "backend_bypass_authorization" ]]; then
    return 1
  fi

  expires_at="$(jq -r '.expires_at // empty' <<< "${authorization_json}")"
  if [[ -z "${expires_at}" ]]; then
    return 1
  fi

  expires_epoch="$(cf_iso8601_to_epoch "${expires_at}" 2>/dev/null)" || return 1
  if (( expires_epoch <= $(cf_now_epoch) )); then
    return 1
  fi

  backend_relative_path="$(cf_repo_relative_path "${backend_path}")" || return 1
  if [[ "$(jq -r --arg backend "${backend_relative_path}" '.allowed_backends | index("*") != null or index($backend) != null' <<< "${authorization_json}")" != "true" ]]; then
    return 1
  fi

  CF_BACKEND_BYPASS_AUTH_PATH="${authorization_path}"
  CF_BACKEND_BYPASS_AUTH_JSON="${authorization_json}"
  return 0
}

cf_backend_authorization_health_json() {
  local admin_dir
  local reports='[]'
  local artifact_path
  local artifact_json
  local expires_epoch
  local expired

  admin_dir="$(cf_runtime_admin_dir)"
  for artifact_path in "${admin_dir}"/backend-bypass-*.json; do
    [[ -f "${artifact_path}" ]] || continue
    artifact_json="$(cat "${artifact_path}")"
    expired="false"
    if expires_epoch="$(cf_iso8601_to_epoch "$(jq -r '.expires_at // empty' <<< "${artifact_json}")" 2>/dev/null)"; then
      if (( expires_epoch <= $(cf_now_epoch) )); then
        expired="true"
      fi
    else
      expired="true"
    fi
    reports="$(
      jq \
        --arg path "${artifact_path}" \
        --argjson expired "${expired}" \
        --argjson artifact "${artifact_json}" \
        '. + [{path: $path, expired: $expired, authorization: $artifact}]' \
        <<< "${reports}"
    )"
  done

  jq -n \
    --arg admin_dir "${admin_dir}" \
    --argjson authorizations "${reports}" \
    '
      {
        admin_dir: $admin_dir,
        authorization_count: ($authorizations | length),
        expired_count: ($authorizations | map(select(.expired == true)) | length),
        authorizations: $authorizations
      }
    '
}

cf_backend_authorization_revoke() {
  local authorization_path="${1:-}"
  local admin_dir
  local resolved_admin_dir
  local resolved_authorization_path

  admin_dir="$(cf_runtime_admin_dir)"
  resolved_admin_dir="$(cf_realpath_best_effort "${admin_dir}")" || return 1
  resolved_authorization_path="$(cf_realpath_best_effort "${authorization_path}")" || return 1

  if [[ ! -f "${resolved_authorization_path}" ]]; then
    return 1
  fi

  if [[ "${resolved_authorization_path}" != "${resolved_admin_dir}/"* ]]; then
    return 1
  fi

  rm -f "${resolved_authorization_path}"
}

cf_runtime_secret_sink_check_json() {
  local sink_path="${1:-}"
  local require_absolute
  local reject_repo_paths
  local reject_var_paths
  local reject_symlinks
  local resolved_path
  local repo_root
  local var_root

  require_absolute="$(jq -r '.secret_sink_policy.require_absolute_path // true' <<< "$(cf_runtime_policy_json)")"
  reject_repo_paths="$(jq -r '.secret_sink_policy.reject_repo_paths // true' <<< "$(cf_runtime_policy_json)")"
  reject_var_paths="$(jq -r '.secret_sink_policy.reject_var_paths // true' <<< "$(cf_runtime_policy_json)")"
  reject_symlinks="$(jq -r '.secret_sink_policy.reject_symlinks // true' <<< "$(cf_runtime_policy_json)")"
  repo_root="$(cf_realpath_best_effort "${CF_REPO_ROOT}")"
  var_root="$(cf_realpath_best_effort "${CF_REPO_ROOT}/var")"

  if [[ -z "${sink_path}" ]]; then
    jq -n '{ok: false, code: "sink_path_missing", message: "Secret sink path is required"}'
    return
  fi

  if [[ "${require_absolute}" == "true" && "${sink_path}" != /* ]]; then
    jq -n --arg path "${sink_path}" '{ok: false, code: "unsafe_secret_sink", message: "Secret sink path must be absolute", path: $path}'
    return
  fi

  if [[ ! -d "$(dirname "${sink_path}")" ]]; then
    jq -n --arg path "${sink_path}" '{ok: false, code: "unsafe_secret_sink", message: "Secret sink parent directory does not exist", path: $path}'
    return
  fi

  if [[ "${reject_symlinks}" == "true" && -L "${sink_path}" ]]; then
    jq -n --arg path "${sink_path}" '{ok: false, code: "unsafe_secret_sink", message: "Secret sink path must not be a symlink", path: $path}'
    return
  fi

  resolved_path="$(cf_realpath_best_effort "${sink_path}")" || {
    jq -n --arg path "${sink_path}" '{ok: false, code: "unsafe_secret_sink", message: "Unable to resolve secret sink path", path: $path}'
    return
  }

  if [[ "${reject_repo_paths}" == "true" && ( "${resolved_path}" == "${repo_root}" || "${resolved_path}" == "${repo_root}/"* ) ]]; then
    jq -n --arg path "${resolved_path}" '{ok: false, code: "unsafe_secret_sink", message: "Secret sink path must not be inside the repo", path: $path}'
    return
  fi

  if [[ "${reject_var_paths}" == "true" && ( "${resolved_path}" == "${var_root}" || "${resolved_path}" == "${var_root}/"* ) ]]; then
    jq -n --arg path "${resolved_path}" '{ok: false, code: "unsafe_secret_sink", message: "Secret sink path must not be inside repo var/", path: $path}'
    return
  fi

  jq -n --arg path "${resolved_path}" '{ok: true, code: null, message: null, path: $path}'
}

cf_runtime_secret_sink_verify_permissions() {
  local sink_path="$1"
  local mode

  chmod 600 "${sink_path}"
  mode="$(cf_runtime_secret_sink_mode "${sink_path}")"
  if [[ -n "${mode}" && "${mode}" != "600" ]]; then
    echo "Secret sink permissions are not strict: ${mode}" >&2
    return 1
  fi

  return 0
}

cf_runtime_secret_sink_mode() {
  local sink_path="$1"

  if command -v stat >/dev/null 2>&1; then
    stat -f "%Lp" "${sink_path}" 2>/dev/null || stat -c "%a" "${sink_path}" 2>/dev/null || true
  fi
}

cf_require_backend_dispatch() {
  local replacement_command="$1"
  local backend_name="${2:-$(basename "$0")}"
  local backend_relative_path
  local legacy_env_name
  local legacy_env_value=""
  local bypass_env_name

  if [[ "${CF_RUNTIME_CALLER:-}" == "cfctl" ]]; then
    return 0
  fi

  backend_relative_path="$(cf_repo_relative_path "$0" 2>/dev/null || basename "$0")"
  if cf_backend_authorization_validate "$0"; then
    return 0
  fi

  legacy_env_name="$(cf_runtime_legacy_bypass_env_name)"
  legacy_env_value="${!legacy_env_name:-}"
  if [[ "${legacy_env_value}" == "1" ]]; then
    if cf_runtime_legacy_bypass_allowed; then
      echo "Warning: ${legacy_env_name}=1 is a deprecated backend bypass path." >&2
      return 0
    fi
  fi

  bypass_env_name="$(cf_runtime_backend_bypass_env_name)"
  echo "${backend_name} is backend-only." >&2
  echo "Use ${replacement_command}" >&2
  echo "For maintainer/debug use, run: cfctl admin authorize-backend --backend ${backend_relative_path} --reason \"maintainer debug\"" >&2
  echo "Then invoke the backend with ${bypass_env_name}=<authorization-file>." >&2
  exit 1
}

cf_build_curl_auth_args() {
  CF_CURL_AUTH_ARGS=()

  case "${CF_ACTIVE_AUTH_SCHEME:-}" in
    api_token)
      CF_CURL_AUTH_ARGS=(-H "Authorization: Bearer ${CF_ACTIVE_AUTH_SECRET}")
      ;;
    global_api_key)
      cf_require_var CLOUDFLARE_EMAIL
      CF_CURL_AUTH_ARGS=(-H "X-Auth-Email: ${CLOUDFLARE_EMAIL}" -H "X-Auth-Key: ${CF_ACTIVE_AUTH_SECRET}")
      ;;
    *)
      echo "Unsupported CF_ACTIVE_AUTH_SCHEME: ${CF_ACTIVE_AUTH_SCHEME:-unset}" >&2
      exit 1
      ;;
  esac
}

cf_load_cloudflare_env() {
  local shared_env_file="${CF_SHARED_ENV_FILE:-${CF_SHARED_ENV_FILE_DEFAULT}}"
  local repo_env_file="${CF_REPO_ENV_FILE:-${CF_REPO_ENV_FILE_DEFAULT}}"

  if [[ -f "${shared_env_file}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${shared_env_file}"
    set +a
  fi

  if [[ -f "${repo_env_file}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${repo_env_file}"
    set +a
  fi

  cf_select_active_token
}

cf_require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "${name} must be set" >&2
    exit 1
  fi
}

cf_require_api_auth() {
  cf_require_var CF_ACTIVE_AUTH_SECRET
}

cf_require_account_id() {
  cf_require_var CLOUDFLARE_ACCOUNT_ID
}

cf_log_dir() {
  local category="$1"
  local dir="${CF_REPO_ROOT}/var/logs/${category}"
  mkdir -p "${dir}"
  printf '%s\n' "${dir}"
}

cf_inventory_dir() {
  local category="$1"
  local dir="${CF_REPO_ROOT}/var/inventory/${category}"
  mkdir -p "${dir}"
  printf '%s\n' "${dir}"
}

cf_setup_log_pipe() {
  local category="$1"
  local stem="${2:-build}"
  local dir
  local log_id
  dir="$(cf_log_dir "${category}")"
  log_id="$(cf_runtime_operation_id)"
  CF_LOG_FILE="${dir}/${stem}-${log_id}.log"
  export CF_LOG_FILE
  CF_LOG_FIFO="${dir}/.${stem}-$$.fifo"
  export CF_LOG_FIFO
  rm -f "${CF_LOG_FIFO}"
  mkfifo "${CF_LOG_FIFO}"
  tee -a "${CF_LOG_FILE}" < "${CF_LOG_FIFO}" &
  CF_LOG_TEE_PID="$!"
  export CF_LOG_TEE_PID
  trap cf_cleanup_log_pipe EXIT
  exec > "${CF_LOG_FIFO}" 2>&1
}

cf_cleanup_log_pipe() {
  if [[ -n "${CF_LOG_FIFO:-}" && -p "${CF_LOG_FIFO}" ]]; then
    rm -f "${CF_LOG_FIFO}"
  fi
}

cf_inventory_file() {
  local category="$1"
  local stem="$2"
  local ext="${3:-json}"
  local dir
  local artifact_id
  dir="$(cf_inventory_dir "${category}")"
  artifact_id="$(cf_runtime_operation_id)"
  printf '%s/%s-%s.%s\n' "${dir}" "${stem}" "${artifact_id}" "${ext}"
}

cf_write_json_file() {
  local path="$1"
  local payload="$2"
  jq '.' <<< "${payload}" > "${path}"
}

cf_resolve_json_payload() {
  local inline_payload="${1:-}"
  local payload_file="${2:-}"

  if [[ -n "${inline_payload}" && -n "${payload_file}" ]]; then
    echo "Specify either inline JSON or a payload file, not both." >&2
    exit 1
  fi

  if [[ -n "${payload_file}" ]]; then
    if [[ ! -f "${payload_file}" ]]; then
      echo "JSON payload file not found: ${payload_file}" >&2
      exit 1
    fi
    jq -c '.' "${payload_file}"
    return
  fi

  if [[ -n "${inline_payload}" ]]; then
    jq -c '.' <<< "${inline_payload}"
    return
  fi

  echo ""
}

cf_redact_json() {
  local payload="${1:-null}"

  jq '
    walk(
      if type == "object" then
        with_entries(
          if (.key | test("^(authorization|api_key|api_token|client_secret|ownership_challenge|secret|token_value|auth_secret|x-auth-key|x-auth-email)$"; "i")) then
            .value = "REDACTED"
          else
            .
          end
        )
      elif type == "string" then
        if test("(^cf(at|k)_[A-Za-z0-9_-]+$|Authorization: Bearer [^[:space:]]+|X-Auth-Key: [^[:space:]]+)"; "i") then
          "REDACTED"
        else
          .
        end
      else
        .
      end
    )
  ' <<< "${payload}"
}

cf_api() {
  local method="$1"
  local path_or_url="$2"
  shift 2

  local url="${path_or_url}"
  if [[ "${url}" != http://* && "${url}" != https://* ]]; then
    url="${CF_API_BASE}${path_or_url}"
  fi

  cf_build_curl_auth_args

  curl -sS --fail-with-body -X "${method}" \
    "${CF_CURL_AUTH_ARGS[@]}" \
    "$@" \
    "${url}"
}

cf_api_capture() {
  local method="$1"
  local path_or_url="$2"
  shift 2

  local url="${path_or_url}"
  if [[ "${url}" != http://* && "${url}" != https://* ]]; then
    url="${CF_API_BASE}${path_or_url}"
  fi

  cf_build_curl_auth_args

  local body_file
  body_file="$(mktemp)"

  local status_code
  status_code="$(
    curl -sS \
      -X "${method}" \
      "${CF_CURL_AUTH_ARGS[@]}" \
      -o "${body_file}" \
      -w '%{http_code}' \
      "$@" \
      "${url}"
  )"

  if jq -e . "${body_file}" >/dev/null 2>&1; then
    jq \
      --arg method "${method}" \
      --arg url "${url}" \
      --arg status_code "${status_code}" \
      '
        . + {
          request: {
            method: $method,
            url: $url
          },
          status_code: ($status_code | tonumber)
        }
      ' \
      "${body_file}"
  else
    jq -n \
      --arg method "${method}" \
      --arg url "${url}" \
      --arg status_code "${status_code}" \
      --arg raw_body "$(cat "${body_file}")" \
      '
        {
          success: false,
          errors: [
            {
              code: -1,
              message: "Non-JSON response body"
            }
          ],
          messages: [],
          result: null,
          raw_body: $raw_body,
          request: {
            method: $method,
            url: $url
          },
          status_code: ($status_code | tonumber)
        }
      '
  fi

  rm -f "${body_file}"
}

cf_prepare_wrangler_env() {
  local wrangler_root="${CF_WRANGLER_HOME:-${CF_REPO_ROOT}/var/wrangler-home}"

  mkdir -p "${wrangler_root}/home" "${wrangler_root}/xdg-config" "${wrangler_root}/tmp"

  export HOME="${wrangler_root}/home"
  export XDG_CONFIG_HOME="${wrangler_root}/xdg-config"
  export TMPDIR="${wrangler_root}/tmp"

  if [[ "${CF_ACTIVE_AUTH_SCHEME}" == "api_token" ]]; then
    export CLOUDFLARE_API_TOKEN="${CF_ACTIVE_AUTH_SECRET}"
    unset CLOUDFLARE_API_KEY
  else
    export CLOUDFLARE_API_KEY="${CF_ACTIVE_AUTH_SECRET}"
    unset CLOUDFLARE_API_TOKEN
  fi
}

cf_resolve_zone_id() {
  local zone_name="$1"
  cf_api GET "/zones?name=${zone_name}" | jq -r '.result[0].id'
}

cf_print_log_footer() {
  if [[ -n "${CF_LOG_FILE:-}" ]]; then
    echo "Log written to ${CF_LOG_FILE}"
  fi
}
