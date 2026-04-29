#!/usr/bin/env bash

set -euo pipefail

cfctl_usage() {
  cat <<EOF
Cloudflare Agent Runtime

This command is the public Cloudflare control-plane interface for:
  ${CF_REPO_ROOT}

If you are an agent landing here, do this first:
  1. cfctl doctor
  2. cfctl bootstrap permissions
  3. cfctl surfaces
  4. cfctl docs
  5. cfctl standards <surface>
  6. cfctl standards audit
  7. cfctl explain <surface>
  8. cfctl classify <surface> <operation>
  9. cfctl guide <surface> <operation>

Core rules:
  - Use cfctl first. Do not improvise from random scripts.
  - Use CF_DEV_TOKEN first. Switch to CF_TOKEN_LANE=global only when needed.
  - Read current state before writing.
  - Backend scripts are backend-only. Direct maintainer/debug use requires a scoped authorization file from cfctl admin authorize-backend.
  - Use --plan first for any real mutation, then apply with --ack-plan <operation-id>.
  - High-risk previews and writes are lock-governed; do not bypass those locks.
  - Leave evidence in var/inventory/runtime/ and related var/inventory paths.
  - Token minting is sink-first. Use --value-out; stdout reveal is disabled unless runtime policy explicitly allows it.

Usage:
  cfctl doctor [--strict] [--repair-hints]
  cfctl audit trust
  cfctl admin authorize-backend --backend <path> --reason <why> [--ttl-minutes <n>]
  cfctl admin authorizations
  cfctl admin revoke-backend --path <authorization-path>
  cfctl bootstrap permissions
  cfctl lanes
  cfctl surfaces
  cfctl docs [topic]
  cfctl standards [surface]
  cfctl standards audit [root]
  cfctl previews
  cfctl previews purge-expired
  cfctl locks
  cfctl locks clear-stale
  cfctl wrangler [wrangler args]
  cfctl cloudflared [cloudflared args]
  cfctl hostname verify|diff|plan|apply [--file state/hostname/<name>.yaml]
  cfctl token permission-groups [--name <filter>] [--scope <scope>]
  cfctl token mint --name <token-name> [token options]
  cfctl list surfaces
  cfctl explain <surface>
  cfctl classify <surface> <operation>
  cfctl guide <surface> <operation> [selectors] [mutation args]
  cfctl can <surface> <operation> [selectors] [--all-lanes]
  cfctl list <surface> [selectors]
  cfctl snapshot <surface> [selectors]
  cfctl get <surface> [selectors]
  cfctl verify <surface> [selectors]
  cfctl diff <surface> [selectors] [--state-dir path]
  cfctl apply <surface> <operation> [selectors] [mutation args]

Verb intent:
  doctor    Validate trust health, lane health, registry policy, locks, previews, and artifact secrecy.
  audit     Alias for trust-focused doctor checks.
  admin     Inspect or issue scoped maintainer authorizations for backend-only workflows.
  bootstrap Show the credential and permission plan required to bootstrap cfctl.
  lanes     Show configured auth lanes and whether they work.
  surfaces  List supported surfaces with read/write support, lane fit, and desired-state support.
  docs      Show the compact official Cloudflare docs bank and tracked incoming capabilities.
  standards Show the canonical configuration standards for this runtime, one surface, or a workspace audit.
  previews  Inspect actionable, legacy, and expired preview receipts, and purge expired ones.
  locks     Inspect write locks and clear stale ones.
  wrangler  Run Wrangler through the cfctl envelope, logs, and preview gate for mutating commands.
  cloudflared Run cloudflared through the cfctl envelope, logs, and preview gate for mutating commands.
  hostname Composite hostname lifecycle evidence from checked-in state/hostname specs.
  token     List token permission groups or mint a new account-owned API token.
  list      List surfaces or resources.
  explain   Show the contract for one surface.
  classify  Explain write policy, lane fit, and confirmation rules for an operation.
  guide     Print exact discovery, preview, apply, and verification commands for a surface operation.
  can       Check whether an operation is supported and permitted.
  snapshot  Capture read evidence for a surface.
  get       Resolve one exact resource.
  verify    Re-read a targeted resource after changes.
  diff      Compare actual state against desired state on supported surfaces.
  apply     Perform a mutation or desired-state sync.

Auth lanes:
  dev       Default lane backed by CF_DEV_TOKEN.
  global    Emergency lane backed by CF_GLOBAL_TOKEN.

Examples:
  cfctl doctor
  cfctl doctor --strict
  cfctl doctor --repair-hints
  cfctl audit trust
  cfctl bootstrap permissions
  cfctl lanes
  cfctl surfaces
  cfctl docs
  cfctl docs watch
  cfctl docs ai-search
  cfctl standards dns.record
  cfctl standards worker.runtime
  cfctl standards audit
  cfctl standards audit /path/to/workspace
  cfctl previews
  cfctl previews purge-expired
  cfctl locks
  cfctl locks clear-stale
  cfctl wrangler --version
  cfctl wrangler deploy --plan
  cfctl cloudflared version
  cfctl cloudflared tunnel create preview-tunnel --plan
  cfctl hostname verify --file state/hostname/example.yaml
  cfctl hostname diff --file state/hostname/example.yaml
  cfctl hostname plan --file state/hostname/example.yaml
  cfctl admin authorizations
  cfctl admin authorize-backend --backend scripts/cf_api_apply.sh --reason "maintainer debug"
  cfctl admin revoke-backend --path var/runtime/admin/backend-bypass-<id>.json
  cfctl token permission-groups --name "DNS"
  cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --plan
  cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --ack-plan <operation-id> --value-out /tmp/dns-editor.token
  cfctl classify dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT
  cfctl guide dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120
  cfctl apply edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --validation-method txt --certificate-authority lets_encrypt --validity-days 90 --plan
  cfctl list surfaces
  cfctl standards access.app
  cfctl standards worker.build
  cfctl explain access.app
  cfctl list pages.project
  cfctl get access.app --domain docs.example.org
  cfctl list worker.route --zone example.com
  cfctl can dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --all-lanes
  CF_TOKEN_LANE=global cfctl diff dns.record --zone example.com
  CF_TOKEN_LANE=global cfctl apply dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120 --plan
  CF_TOKEN_LANE=global cfctl apply dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --content hello-world --ttl 120 --ack-plan <operation-id>
  CF_TOKEN_LANE=global cfctl apply edge.certificate order --zone example.com --host app.example.com --host deep.app.example.com --plan

Broad read-only bank refresh:
  ${CF_REPO_ROOT}/scripts/cf_agent_bootstrap.sh

Desired-state surfaces:
  access.app
  access.policy
  dns.record
  tunnel

Composite lifecycle state:
  hostname

Need more context?
  ${CF_REPO_ROOT}/AGENTS.md
  ${CF_REPO_ROOT}/README.md
EOF
}

cfctl_emit_failure() {
  local action="$1"
  local surface="$2"
  local backend="$3"
  local permission_json="$4"
  local error_code="$5"
  local error_message="$6"
  local operation="${7:-}"
  local guidance_json

  guidance_json="$(cfctl_failure_guidance_json "${action}" "${surface}" "${backend}" "${permission_json}" "${error_code}" "${error_message}" "${operation}")"
  cfctl_emit_result \
    "false" \
    "${action}" \
    "${surface}" \
    "${backend}" \
    "false" \
    "${permission_json}" \
    '{"state":"not_applicable"}' \
    "$(jq -n --arg message "${error_message}" '{message: $message}')" \
    "null" \
    "" \
    "${error_code}" \
    "${error_message}" \
    "${operation}" \
    "${guidance_json}"
}

cfctl_require_surface() {
  local surface="$1"
  if ! cfctl_has_surface "${surface}"; then
    cfctl_emit_failure "unknown" "${surface}" "registry" '{"state":"unknown","basis":"unknown_surface","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_surface" "Unknown surface: ${surface}"
    exit 1
  fi
}

cfctl_action_permission_gate() {
  local surface="$1"
  local action="$2"
  local operation="${3:-}"
  local permission_json
  local state

  permission_json="$(cfctl_probe_permission "${surface}" "${action}" "${operation}")"
  state="$(jq -r '.state' <<< "${permission_json}")"

  if [[ "${state}" == "denied" ]]; then
    cfctl_emit_result \
      "false" \
      "${action}" \
      "${surface}" \
      "permission_probe" \
      "false" \
      "${permission_json}" \
      '{"state":"not_applicable"}' \
      "$(jq -n --arg message "Permission denied for ${surface}" '{message: $message}')" \
      "null" \
      "" \
      "permission_denied" \
      "Permission denied for ${surface}" \
      "${operation}"
    exit 1
  fi

  CFCTL_PERMISSION_JSON="${permission_json}"
}

cfctl_backend_guard_report_json() {
  local script_paths=(
    "scripts/cf_api_apply.sh"
    "scripts/cf_token_mint.sh"
    "scripts/cf_mutate_access_app.sh"
    "scripts/cf_mutate_access_policy.sh"
    "scripts/cf_mutate_dns_record.sh"
    "scripts/cf_mutate_turnstile_widget.sh"
    "scripts/cf_mutate_waiting_room.sh"
    "scripts/cf_mutate_edge_certificate.sh"
    "scripts/cf_mutate_logpush_job.sh"
    "scripts/cf_mutate_tunnel.sh"
  )
  local report='[]'
  local path

  for path in "${script_paths[@]}"; do
    local guarded="false"
    if command -v rg >/dev/null 2>&1; then
      if rg -q 'cf_require_backend_dispatch' "${CF_REPO_ROOT}/${path}"; then
        guarded="true"
      fi
    elif grep -q 'cf_require_backend_dispatch' "${CF_REPO_ROOT}/${path}"; then
      guarded="true"
    fi
    report="$(
      jq \
        --arg path "${path}" \
        --argjson guarded "${guarded}" \
        '. + [{path: $path, guarded: $guarded}]' \
        <<< "${report}"
    )"
  done

  printf '%s\n' "${report}"
}

cfctl_secret_scan_json() {
  local artifact_root="${CF_REPO_ROOT}/var"
  local matches='[]'
  local raw_matches=""
  local secret_sinks='[]'
  local artifact_path
  local sink_path
  local path_check_json
  local exists="false"
  local mode=""
  local safe_permissions="false"

  if [[ -d "${artifact_root}" ]]; then
    set +e
    if command -v rg >/dev/null 2>&1; then
      raw_matches="$(
        rg -n -S \
          -g '*.json' \
          -g '*.log' \
          -e 'cfat_[A-Za-z0-9_-]+' \
          -e 'cfk_[A-Za-z0-9_-]+' \
          -e 'Authorization: Bearer ' \
          -e 'X-Auth-Key: ' \
          "${artifact_root}" 2>/dev/null
      )"
    else
      raw_matches="$(
        grep -R -n -E \
          'cfat_[A-Za-z0-9_-]+|cfk_[A-Za-z0-9_-]+|Authorization: Bearer |X-Auth-Key: ' \
          "${artifact_root}" 2>/dev/null
      )"
    fi
    set -e
  fi

  if [[ -n "${raw_matches}" ]]; then
    matches="$(printf '%s\n' "${raw_matches}" | jq -R . | jq -s 'map(select(length > 0)) | .[:50]')"
  fi

  for artifact_path in "${CF_REPO_ROOT}"/var/inventory/auth/token-mint-*.json; do
    [[ -f "${artifact_path}" ]] || continue
    sink_path="$(jq -r '.result.value_out // empty' "${artifact_path}")"
    [[ -n "${sink_path}" ]] || continue
    path_check_json="$(cf_runtime_secret_sink_check_json "${sink_path}")"
    exists="false"
    mode=""
    safe_permissions="false"
    if [[ -f "${sink_path}" ]]; then
      exists="true"
      mode="$(cf_runtime_secret_sink_mode "${sink_path}")"
      if [[ -n "${mode}" && "${mode}" == "600" ]]; then
        safe_permissions="true"
      fi
    fi
    secret_sinks="$(
      jq \
        --arg artifact_path "${artifact_path}" \
        --arg sink_path "${sink_path}" \
        --arg mode "${mode}" \
        --argjson exists "${exists}" \
        --argjson safe_permissions "${safe_permissions}" \
        --argjson path_check "${path_check_json}" \
        '
          . + [{
            artifact_path: $artifact_path,
            sink_path: $sink_path,
            exists: $exists,
            mode: (if $mode == "" then null else $mode end),
            safe_permissions: $safe_permissions,
            path_check: $path_check
          }]
        ' \
        <<< "${secret_sinks}"
    )"
  done

  jq -n \
    --arg artifact_root "${artifact_root}" \
    --argjson matches "${matches}" \
    --argjson secret_sinks "${secret_sinks}" \
    '
      {
        artifact_root: $artifact_root,
        leak_count: ($matches | length),
        sample_matches: $matches,
        secret_sinks: $secret_sinks,
        secret_sink_count: ($secret_sinks | length),
        unsafe_secret_sink_count: (
          $secret_sinks
          | map(
              select(
                .exists == true
                and (
                  (.path_check.ok != true)
                  or (.safe_permissions != true)
                )
              )
            )
          | length
        )
      }
    '
}

cfctl_build_apply_command() {
  local surface="$1"
  local operation="$2"
  local extra_tail="${3:-}"
  local args_shell

  args_shell="$(cfctl_current_args_shell)"
  printf 'cfctl apply %q %q%s%s\n' "${surface}" "${operation}" "${args_shell}" "${extra_tail}"
}

cfctl_build_verb_command() {
  local verb="$1"
  local surface="$2"
  local operation="${3:-}"
  local extra_tail="${4:-}"
  local args_shell

  args_shell="$(cfctl_current_args_shell)"
  case "${verb}" in
    classify|guide|can)
      printf 'cfctl %q %q %q%s%s\n' "${verb}" "${surface}" "${operation}" "${args_shell}" "${extra_tail}"
      ;;
    explain)
      printf 'cfctl explain %q%s%s\n' "${surface}" "${args_shell}" "${extra_tail}"
      ;;
    list|get|verify|snapshot|diff)
      printf 'cfctl %q %q%s%s\n' "${verb}" "${surface}" "${args_shell}" "${extra_tail}"
      ;;
    *)
      printf 'cfctl %q%s%s\n' "${verb}" "${args_shell}" "${extra_tail}"
      ;;
  esac
}

cfctl_build_selector_verb_command() {
  local verb="$1"
  local surface="$2"
  local extra_tail="${3:-}"
  local args_shell

  args_shell="$(cfctl_current_selector_args_shell)"
  printf 'cfctl %q %q%s%s\n' "${verb}" "${surface}" "${args_shell}" "${extra_tail}"
}

cfctl_command_with_lane_prefix() {
  local lane="${1:-}"
  local command_string="${2:-}"

  if [[ -n "${lane}" && "${lane}" != "${CF_ACTIVE_TOKEN_LANE:-}" ]]; then
    printf 'CF_TOKEN_LANE=%s %s\n' "${lane}" "${command_string}"
    return
  fi

  printf '%s\n' "${command_string}"
}

cfctl_tool_wrapper_permission_json() {
  local tool="$1"
  jq -n \
    --arg tool "${tool}" \
    '
      {
        state: "not_applicable",
        basis: "tool_wrapper",
        errors: [],
        request: null,
        status_code: null,
        permission_family: ($tool + " wrapper")
      }
    '
}

cfctl_tool_wrapper_request_json() {
  local tool="$1"
  local classification_json="$2"

  jq -n \
    --arg tool "${tool}" \
    --arg backend "$(cfctl_tool_wrapper_backend "${tool}")" \
    --arg script "$(cfctl_tool_wrapper_script_relpath "${tool}")" \
    --argjson classification "${classification_json}" \
    '
      {
        tool: $tool,
        backend: $backend,
        script: $script,
        mode: ($classification.mode // "preview_required"),
        effective_args: ($classification.effective_args // []),
        defaulted: ($classification.defaulted // false)
      }
    '
}

cfctl_tool_wrapper_trust_json() {
  local tool="$1"
  local request_json="$2"
  local preview_ttl_seconds
  local preview_expires_at="null"
  local request_fingerprint

  preview_ttl_seconds="$(jq -r '.policy.preview_ttl_seconds // 900' "$(cf_runtime_catalog_path)")"
  request_fingerprint="$(cf_hash_json "${request_json}")"

  if [[ "${preview_ttl_seconds}" != "0" ]]; then
    preview_expires_at="$(jq -Rn --arg ts "$(cf_seconds_from_now_iso8601 "${preview_ttl_seconds}")" '$ts')"
  fi

  jq -n \
    --arg tool "${tool}" \
    --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg policy_version "$(jq -r '.version // 0' "$(cf_runtime_catalog_path)")" \
    --arg request_fingerprint "${request_fingerprint}" \
    --argjson preview_expires_at "${preview_expires_at}" \
    --argjson request "${request_json}" \
    '
      {
        tool: $tool,
        lane: $lane,
        policy_version: $policy_version,
        request_fingerprint: $request_fingerprint,
        preview_expires_at: $preview_expires_at,
        request: $request
      }
    '
}

cfctl_find_tool_wrapper_receipt_path() {
  local tool="$1"
  local ack_plan="$2"
  local runtime_dir="${CF_REPO_ROOT}/var/inventory/runtime"
  local candidate

  if [[ ! -d "${runtime_dir}" ]]; then
    return 1
  fi

  for candidate in "${runtime_dir}"/*.json; do
    [[ -f "${candidate}" ]] || continue
    if jq -e \
      --arg tool "${tool}" \
      --arg ack_plan "${ack_plan}" \
      '
        (.operation_id // "") == $ack_plan
        and .action == $tool
        and .surface == $tool
        and (.summary.plan_mode // false) == true
      ' \
      "${candidate}" >/dev/null 2>&1; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  return 1
}

cfctl_validate_tool_wrapper_receipt() {
  local receipt_path="$1"
  local expected_trust_json="$2"
  local receipt_trust_json
  local preview_expires_at
  local preview_expires_epoch

  receipt_trust_json="$(jq -c '.trust // null' "${receipt_path}")"
  if [[ "${receipt_trust_json}" == "null" ]]; then
    CFCTL_PLAN_RECEIPT_ERROR_CODE="preview_version_mismatch"
    CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview receipt is missing trust metadata"
    return 1
  fi

  if [[ "$(jq -r '.tool // ""' <<< "${expected_trust_json}")" != "$(jq -r '.tool // ""' <<< "${receipt_trust_json}")" ]]; then
    CFCTL_PLAN_RECEIPT_ERROR_CODE="preview_version_mismatch"
    CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview receipt no longer matches this tool"
    return 1
  fi

  if [[ "$(jq -r '.policy_version // ""' <<< "${expected_trust_json}")" != "$(jq -r '.policy_version // ""' <<< "${receipt_trust_json}")" ]]; then
    CFCTL_PLAN_RECEIPT_ERROR_CODE="preview_version_mismatch"
    CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview receipt was created under a different runtime policy version"
    return 1
  fi

  if [[ "$(jq -r '.lane // ""' <<< "${expected_trust_json}")" != "$(jq -r '.lane // ""' <<< "${receipt_trust_json}")" ]]; then
    CFCTL_PLAN_RECEIPT_ERROR_CODE="preview_lane_mismatch"
    CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview receipt lane no longer matches the current lane"
    return 1
  fi

  if [[ "$(jq -r '.request_fingerprint // ""' <<< "${expected_trust_json}")" != "$(jq -r '.request_fingerprint // ""' <<< "${receipt_trust_json}")" ]]; then
    CFCTL_PLAN_RECEIPT_ERROR_CODE="preview_payload_mismatch"
    CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview receipt request no longer matches the current wrapped command"
    return 1
  fi

  preview_expires_at="$(jq -r '.preview_expires_at // empty' <<< "${receipt_trust_json}")"
  if [[ -n "${preview_expires_at}" ]]; then
    preview_expires_epoch="$(cf_iso8601_to_epoch "${preview_expires_at}" 2>/dev/null || true)"
    if [[ -n "${preview_expires_epoch}" ]] && (( preview_expires_epoch < $(cf_now_epoch) )); then
      CFCTL_PLAN_RECEIPT_ERROR_CODE="preview_expired"
      CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview receipt has expired"
      return 1
    fi
  fi

  CFCTL_PLAN_RECEIPT_TRUST_JSON="${receipt_trust_json}"
  return 0
}

cfctl_run_tool_wrapper() {
  local tool="$1"
  local classification_json="$2"
  local tool_meta_json
  local script_relpath
  local script_path
  local log_category
  local log_dir
  local log_path
  local args_shell
  local output_tail_json
  local status
  local -a effective_args=()

  tool_meta_json="$(cfctl_tool_wrapper_meta_json "${tool}")"
  script_relpath="$(jq -r '.script // empty' <<< "${tool_meta_json}")"
  log_category="$(jq -r '.log_category // empty' <<< "${tool_meta_json}")"
  script_path="${CF_REPO_ROOT}/${script_relpath}"

  if [[ ! -f "${script_path}" ]]; then
    echo "Wrapped tool script not found: ${script_relpath}" >&2
    return 127
  fi

  while IFS= read -r arg; do
    effective_args+=("${arg}")
  done < <(jq -r '.effective_args[]?' <<< "${classification_json}")

  log_dir="$(cf_log_dir "${log_category}")"
  log_path="${log_dir}/${tool}-${CFCTL_OPERATION_ID:-$(cf_runtime_operation_id)}.log"
  : > "${log_path}"

  set +e
  env CF_RUNTIME_CALLER=cfctl CFCTL_OPERATION_ID="${CFCTL_OPERATION_ID:-}" "${script_path}" "${effective_args[@]}" >"${log_path}" 2>&1
  status=$?
  set -e

  args_shell="$(cfctl_shell_join_args "${effective_args[@]}")"
  output_tail_json="$(
    tail -n 40 "${log_path}" 2>/dev/null | jq -Rsc 'split("\n") | map(select(length > 0))'
  )"

  CFCTL_WRAPPER_STATUS="${status}"
  CFCTL_WRAPPER_LOG_PATH="${log_path}"
  CFCTL_WRAPPER_RESULT_JSON="$(
    jq -n \
      --arg tool "${tool}" \
      --arg script "${script_relpath}" \
      --arg command "$(if [[ -n "${args_shell}" ]]; then printf 'cfctl %s %s' "${tool}" "${args_shell}"; else printf 'cfctl %s' "${tool}"; fi)" \
      --argjson classification "${classification_json}" \
      --argjson exit_code "${status}" \
      --arg log_path "${log_path}" \
      --argjson output_tail "${output_tail_json}" \
      '
        {
          tool: $tool,
          script: $script,
          command: $command,
          classification: $classification,
          exit_code: $exit_code,
          log_path: $log_path,
          output_tail: $output_tail
        }
      '
  )"
}

cfctl_recommended_lane_from_comparison() {
  local comparison_json="$1"
  local current_lane="${CF_ACTIVE_TOKEN_LANE:-}"
  local candidate

  while IFS= read -r candidate; do
    [[ -n "${candidate}" ]] || continue
    if [[ "${candidate}" != "${current_lane}" ]]; then
      printf '%s\n' "${candidate}"
      return
    fi
  done < <(jq -r '.summary.allowed_lanes[]? // empty' <<< "${comparison_json}")

  jq -r '.summary.allowed_lanes[0] // empty' <<< "${comparison_json}"
}

cfctl_surface_mode() {
  local surface="$1"

  if [[ "$(jq -r --arg surface "${surface}" '.surfaces[$surface].actions.apply.supported // false' "${CFCTL_REGISTRY_PATH}")" == "true" ]]; then
    printf 'fully_operable\n'
    return
  fi

  printf 'read_only\n'
}

cfctl_surface_supported_verbs_json() {
  local surface="$1"

  jq -c \
    --arg surface "${surface}" \
    --argjson state_meta "$(cfctl_surface_state_meta "${surface}")" \
    '
      (.surfaces[$surface].actions // {})
      | to_entries
      | map(select(.value.supported == true))
      | map(.key)
      | . + (
          if ($state_meta.supported // false) then
            ["diff"]
          else
            []
          end
        )
      | . + (
          if ($state_meta.sync_supported // false) then
            ["sync"]
          else
            []
          end
        )
      | unique
      | sort
    ' \
    "${CFCTL_REGISTRY_PATH}"
}

cfctl_surface_supported_apply_operations_json() {
  local surface="$1"

  jq -c \
    --arg surface "${surface}" \
    '.surfaces[$surface].actions.apply.operations // {} | keys | sort' \
    "${CFCTL_REGISTRY_PATH}"
}

cfctl_surface_write_risks_json() {
  local surface="$1"

  jq -c \
    --arg surface "${surface}" \
    '
      (
        .surfaces[$surface].actions.apply.operations // {}
        | to_entries
        | map(.value.risk // "write")
      )
      | unique
      | sort
    ' \
    "${CFCTL_REGISTRY_PATH}"
}

cfctl_preview_rows_json() {
  local rows='[]'
  local file
  local expired="false"
  local preview_expires_at=""
  local preview_expires_epoch=""
  local trust_complete="false"

  for file in "${CF_REPO_ROOT}"/var/inventory/runtime/*.json "${CF_REPO_ROOT}"/var/inventory/auth/token-mint-*.json; do
    [[ -f "${file}" ]] || continue
    if ! jq -e '
      (.action == "apply" and (.summary.plan_mode // false) == true)
      or (.action == "token.mint" and (.planned // false) == true)
    ' "${file}" >/dev/null 2>&1; then
      continue
    fi

    preview_expires_at="$(jq -r '.trust.preview_expires_at // empty' "${file}")"
    expired="false"
    if [[ -n "${preview_expires_at}" ]]; then
      preview_expires_epoch="$(cf_iso8601_to_epoch "${preview_expires_at}" 2>/dev/null || true)"
      if [[ -z "${preview_expires_epoch}" || "${preview_expires_epoch}" -le "$(cf_now_epoch)" ]]; then
        expired="true"
      fi
    fi
    trust_complete="$(
      jq -e '
        .trust != null
        and (.trust.policy_fingerprint // "") != ""
        and (.trust.request_fingerprint // "") != ""
        and (.trust.target_fingerprint // "") != ""
      ' "${file}" >/dev/null 2>&1 && echo true || echo false
    )"

    rows="$(
      jq \
        --arg artifact_path "${file}" \
        --argjson artifact "$(cat "${file}")" \
        --argjson expired "${expired}" \
        --argjson trust_complete "${trust_complete}" \
        '
          . + [{
            artifact_path: $artifact_path,
            action: ($artifact.action // null),
            surface: (
              if ($artifact.action // "") == "token.mint" then
                "token"
              else
                ($artifact.surface // null)
              end
            ),
            operation: (
              if ($artifact.action // "") == "token.mint" then
                "mint"
              else
                ($artifact.operation // null)
              end
            ),
            operation_id: ($artifact.operation_id // null),
            generated_at: ($artifact.generated_at // null),
            lane: ($artifact.auth.lane // $artifact.trust.lane // null),
            preview_expires_at: ($artifact.trust.preview_expires_at // null),
            lock_mode: ($artifact.trust.lock_mode // null),
            lock_key: ($artifact.trust.lock_key // null),
            trust_complete: $trust_complete,
            expired: $expired
          }]
        ' \
        <<< "${rows}"
    )"
  done

  jq -n \
    --argjson previews "${rows}" \
    '
      {
        preview_count: ($previews | length),
        active_count: ($previews | map(select(.expired != true and .trust_complete == true)) | length),
        actionable_count: ($previews | map(select(.expired != true and .trust_complete == true)) | length),
        expired_count: ($previews | map(select(.expired == true)) | length),
        legacy_count: ($previews | map(select(.trust_complete != true)) | length),
        inactive_legacy_count: ($previews | map(select(.expired != true and .trust_complete != true)) | length),
        previews: ($previews | sort_by(.generated_at // "") | reverse)
      }
    '
}

cfctl_preview_purge_expired_json() {
  local previews_json
  local results='[]'
  local path

  previews_json="$(cfctl_preview_rows_json)"
  while IFS= read -r path; do
    [[ -n "${path}" ]] || continue
    if [[ -f "${path}" ]]; then
      rm -f "${path}"
      results="$(jq --arg path "${path}" '. + [{artifact_path: $path, removed: true}]' <<< "${results}")"
    fi
  done < <(jq -r '.previews[] | select(.expired == true) | .artifact_path' <<< "${previews_json}")

  jq -n \
    --argjson results "${results}" \
    '
      {
        purged_count: ($results | length),
        results: $results
      }
    '
}

cfctl_lock_rows_json() {
  local lock_health_json

  lock_health_json="$(cf_runtime_lock_health_json)"
  jq -n \
    --argjson lock_health "${lock_health_json}" \
    '
      {
        lock_count: ($lock_health.lock_count // 0),
        stale_lock_count: ($lock_health.stale_lock_count // 0),
        orphaned_lock_count: ($lock_health.orphaned_lock_count // 0),
        locks: (
          ($lock_health.locks // [])
          | map({
              lock_key: (.metadata.lock_key // null),
              lock_path: .lock_path,
              operation_id: (.metadata.operation_id // null),
              surface: (.metadata.summary.surface // null),
              operation: (.metadata.summary.operation // null),
              lock_mode: (.metadata.lock_mode // null),
              issued_at: (.metadata.issued_at // null),
              expires_at: (.metadata.expires_at // null),
              stale: (.stale // false),
              orphaned: (.orphaned // false)
            })
          | sort_by(.issued_at // "")
          | reverse
        )
      }
    '
}

cfctl_doctor_repair_hints_json() {
  local preview_health_json="$1"
  local lock_health_json="$2"
  local bypass_health_json="$3"
  local secret_scan_json="$4"
  local registry_integrity_json="$5"
  local hints='[]'

  if [[ "$(jq '(.expired_preview_count // 0) > 0' <<< "${preview_health_json}")" == "true" ]]; then
    hints="$(jq '. + ["cfctl previews purge-expired"]' <<< "${hints}")"
  fi

  if [[ "$(jq '(.stale_lock_count // 0) > 0' <<< "${lock_health_json}")" == "true" ]]; then
    hints="$(jq '. + ["cfctl locks clear-stale"]' <<< "${hints}")"
  fi

  if [[ "$(jq '(.authorization_health.expired_count // 0) > 0' <<< "${bypass_health_json}")" == "true" ]]; then
    hints="$(jq '. + ["cfctl admin authorizations"]' <<< "${hints}")"
  fi

  if [[ "$(jq '(.legacy_env_active == true) and (.legacy_env_allowed != true)' <<< "${bypass_health_json}")" == "true" ]]; then
    hints="$(jq --arg env_name "$(jq -r '.legacy_env_name' <<< "${bypass_health_json}")" '. + [("unset " + $env_name)]' <<< "${hints}")"
  fi

  if [[ "$(jq '(.leak_count // 0) > 0' <<< "${secret_scan_json}")" == "true" ]]; then
    hints="$(jq '. + ["rg -n -S '\''cfat_|cfk_|Authorization: Bearer |X-Auth-Key: '\'' var"]' <<< "${hints}")"
  fi

  if [[ "$(jq '(.unsafe_secret_sink_count // 0) > 0' <<< "${secret_scan_json}")" == "true" ]]; then
    hints="$(jq '. + ["Use an absolute non-repo secret sink such as /tmp/cloudflare-token.secret and ensure mode 600"]' <<< "${hints}")"
  fi

  if [[ "$(jq '(.missing_count // 0) > 0' <<< "${registry_integrity_json}")" == "true" ]]; then
    hints="$(jq '. + ["Fix missing mutable-operation policy fields in catalog/runtime.json or catalog/surfaces.json"]' <<< "${hints}")"
  fi

  printf '%s\n' "${hints}"
}

cfctl_safe_next_steps_json() {
  local overall_status="${1:-healthy}"
  local steps='["cfctl surfaces","cfctl explain <surface>","cfctl classify <surface> <operation>"]'

  if [[ "${overall_status}" != "healthy" ]]; then
    steps='["cfctl doctor --repair-hints","cfctl previews","cfctl locks"]'
  fi

  printf '%s\n' "${steps}"
}

cfctl_failure_guidance_json() {
  local action="$1"
  local surface="$2"
  local backend="$3"
  local permission_json="$4"
  local error_code="$5"
  local error_message="$6"
  local operation="${7:-}"
  local recommendation_command=""
  local recommended_lane=""
  local next_step=""
  local comparison_json="{}"
  local base_command=""
  local requirement_json="{}"

  if [[ "${surface}" != "runtime" && "${surface}" != "token" ]] && cfctl_has_surface "${surface}"; then
    comparison_json="$(cfctl_compare_permission_all_lanes "${surface}" "${action}" "${operation}")"
    recommended_lane="$(cfctl_recommended_lane_from_comparison "${comparison_json}")"
  fi

  case "${error_code}" in
    permission_denied|lane_not_allowed)
      if [[ "${action}" == "apply" && -n "${operation}" ]]; then
        base_command="$(cfctl_build_apply_command "${surface}" "${operation}" " --plan")"
      elif [[ "${action}" == "classify" || "${action}" == "guide" || "${action}" == "can" ]] && [[ -n "${operation}" ]]; then
        base_command="$(cfctl_build_verb_command "${action}" "${surface}" "${operation}")"
      else
        base_command="$(cfctl_build_verb_command "${action}" "${surface}" "${operation}")"
      fi
      if [[ -n "${recommended_lane}" ]]; then
        recommendation_command="$(cfctl_command_with_lane_prefix "${recommended_lane}" "${base_command}")"
        next_step="Retry on the recommended lane."
      else
        recommendation_command="${base_command}"
        next_step="Current credentials do not cover this surface; inspect lanes and token scope."
      fi
      ;;
    preview_required)
      recommendation_command="$(cfctl_command_with_lane_prefix "${recommended_lane}" "$(cfctl_build_apply_command "${surface}" "${operation}" " --plan")")"
      next_step="Run the preview first and review the emitted operation_id."
      ;;
    preview_receipt_missing)
      recommendation_command="cfctl previews"
      next_step="List current preview receipts, then rerun the preview if the expected operation_id is absent."
      ;;
    preview_payload_mismatch)
      recommendation_command="$(cfctl_command_with_lane_prefix "${recommended_lane}" "$(cfctl_build_apply_command "${surface}" "${operation}" " --plan")")"
      next_step="Selectors, payload, lane, or runtime policy changed. Mint a fresh preview and ack that new operation_id."
      ;;
    preview_lane_mismatch)
      recommendation_command="$(cfctl_command_with_lane_prefix "${recommended_lane}" "$(cfctl_build_apply_command "${surface}" "${operation}" " --plan")")"
      next_step="Re-run the preview on the same lane you intend to use for the real apply."
      ;;
    preview_version_mismatch|preview_expired)
      recommendation_command="$(cfctl_command_with_lane_prefix "${recommended_lane}" "$(cfctl_build_apply_command "${surface}" "${operation}" " --plan")")"
      next_step="The reviewed preview is no longer valid. Generate a fresh preview and use its operation_id."
      ;;
    lock_unavailable)
      recommendation_command="cfctl locks"
      next_step="Inspect active locks and clear only stale ones."
      ;;
    unsafe_secret_sink)
      recommendation_command="cfctl token mint ... --value-out /tmp/cloudflare-token.secret"
      next_step="Use an absolute non-repo path with mode 600. Repo paths, var/, and symlinks are rejected."
      ;;
    invalid_arguments)
      if [[ "${surface}" != "runtime" && "${surface}" != "token" ]] && cfctl_has_surface "${surface}"; then
        requirement_json="$(cfctl_requirement_check_json "${surface}" "${action}" "${operation}")"
        next_step="Add the missing selectors or choose a valid selector set."
        recommendation_command="$(cfctl_build_verb_command "explain" "${surface}")"
      fi
      ;;
    *)
      ;;
  esac

  jq -n \
    --arg next_step "${next_step}" \
    --arg recommended_command "${recommendation_command}" \
    --arg recommended_lane "${recommended_lane}" \
    '
      {
        next_step: (if $next_step == "" then null else $next_step end),
        recommended_command: (if $recommended_command == "" then null else $recommended_command end),
        recommended_lane: (if $recommended_lane == "" then null else $recommended_lane end)
      }
    '
}

cfctl_registry_integrity_json() {
  local reports='[]'
  local surface
  local operation
  local policy_json

  while IFS=$'\t' read -r surface operation; do
    policy_json="$(cfctl_operation_policy_json "${surface}" "apply" "${operation}")"
    reports="$(
      jq \
        --arg surface "${surface}" \
        --arg operation "${operation}" \
        --argjson policy "${policy_json}" \
        '
          . + [{
            surface: $surface,
            operation: $operation,
            policy: $policy,
            complete: (
              ($policy.risk // null) != null
              and ($policy.preview_required // null) != null
              and ($policy.allowed_lanes | type == "array" and ($policy.allowed_lanes | length) > 0)
              and ($policy.verification_required // null) != null
              and ($policy.secret_policy // null) != null
              and ($policy.lock_strategy // null) != null
              and ($policy.preview_ttl_seconds // null) != null
              and ($policy.public_example // null) != null
              and ($policy.troubleshooting_hint // null) != null
            )
          }]
        ' \
        <<< "${reports}"
    )"
  done < <(
    jq -r '
      .surfaces
      | to_entries[]
      | select(.value.actions.apply.supported == true)
      | .key as $surface
      | (.value.actions.apply.operations | keys[])
      | [$surface, .]
      | @tsv
    ' "${CFCTL_REGISTRY_PATH}"
  )

  while IFS= read -r surface; do
    policy_json="$(cfctl_operation_policy_json "${surface}" "apply" "sync")"
    reports="$(
      jq \
        --arg surface "${surface}" \
        --argjson policy "${policy_json}" \
        '
          . + [{
            surface: $surface,
            operation: "sync",
            policy: $policy,
            complete: (
              ($policy.risk // null) != null
              and ($policy.preview_required // null) != null
              and ($policy.allowed_lanes | type == "array" and ($policy.allowed_lanes | length) > 0)
              and ($policy.verification_required // null) != null
              and ($policy.secret_policy // null) != null
              and ($policy.lock_strategy // null) != null
              and ($policy.preview_ttl_seconds // null) != null
              and ($policy.public_example // null) != null
              and ($policy.troubleshooting_hint // null) != null
            )
          }]
        ' \
        <<< "${reports}"
    )"
  done < <(
    jq -r '
      .desired_state
      | to_entries[]
      | select(.value.sync_supported == true)
      | .key
    ' "$(cf_runtime_catalog_path)"
  )

  policy_json="$(cfctl_operation_policy_json "token" "apply" "mint")"
  reports="$(
    jq \
      --argjson policy "${policy_json}" \
      '
        . + [{
          surface: "token",
          operation: "mint",
          policy: $policy,
          complete: (
            ($policy.risk // null) != null
            and ($policy.preview_required // null) != null
            and ($policy.allowed_lanes | type == "array" and ($policy.allowed_lanes | length) > 0)
            and ($policy.verification_required // null) != null
            and ($policy.secret_policy // null) != null
            and ($policy.lock_strategy // null) != null
            and ($policy.preview_ttl_seconds // null) != null
            and ($policy.public_example // null) != null
            and ($policy.troubleshooting_hint // null) != null
          )
        }]
      ' \
      <<< "${reports}"
  )"

  jq -n \
    --argjson checks "${reports}" \
    '
      {
        checks: $checks,
        missing_count: ($checks | map(select(.complete != true)) | length)
      }
    '
}

cfctl_preview_receipt_health_json() {
  local reports='[]'
  local file
  local preview_expires_at
  local expired

  for file in "${CF_REPO_ROOT}"/var/inventory/runtime/*.json "${CF_REPO_ROOT}"/var/inventory/auth/token-mint-*.json; do
    [[ -f "${file}" ]] || continue
    if ! jq -e '
      (.action == "apply" and (.summary.plan_mode // false) == true)
      or (.action == "token.mint" and (.planned // false) == true)
    ' "${file}" >/dev/null 2>&1; then
      continue
    fi

    preview_expires_at="$(jq -r '.trust.preview_expires_at // empty' "${file}")"
    expired="false"
    if [[ -n "${preview_expires_at}" ]]; then
      if [[ "$(cf_iso8601_to_epoch "${preview_expires_at}" 2>/dev/null || echo 0)" -le "$(cf_now_epoch)" ]]; then
        expired="true"
      fi
    fi

    reports="$(
      jq \
        --arg path "${file}" \
        --arg preview_expires_at "${preview_expires_at}" \
        --argjson expired "${expired}" \
        --argjson has_trust "$(jq '.trust != null' "${file}")" \
        '. + [{
          path: $path,
          has_trust: $has_trust,
          preview_expires_at: (if $preview_expires_at == "" then null else $preview_expires_at end),
          expired: $expired
        }]' \
        <<< "${reports}"
    )"
  done

  jq -n \
    --argjson previews "${reports}" \
    '
      {
        preview_count: ($previews | length),
        legacy_preview_count: ($previews | map(select(.has_trust != true)) | length),
        expired_preview_count: ($previews | map(select(.expired == true)) | length),
        previews: $previews
      }
    '
}

cfctl_bypass_health_json() {
  local legacy_env_name
  local legacy_env_active="false"
  local authorization_health

  legacy_env_name="$(cf_runtime_legacy_bypass_env_name)"
  if [[ "${!legacy_env_name:-}" == "1" ]]; then
    legacy_env_active="true"
  fi
  authorization_health="$(cf_backend_authorization_health_json)"

  jq -n \
    --arg legacy_env_name "${legacy_env_name}" \
    --argjson legacy_env_allowed "$(if cf_runtime_legacy_bypass_allowed; then echo true; else echo false; fi)" \
    --argjson legacy_env_active "${legacy_env_active}" \
    --argjson authorization_health "${authorization_health}" \
    '
      {
        legacy_env_name: $legacy_env_name,
        legacy_env_allowed: $legacy_env_allowed,
        legacy_env_active: $legacy_env_active,
        authorization_health: $authorization_health
      }
    '
}

cfctl_handle_doctor() {
  local lanes_json
  local guard_report_json
  local secret_scan_json
  local runtime_json
  local registry_integrity_json
  local preview_health_json
  local lock_health_json
  local bypass_health_json
  local repair_hints_json
  local safe_next_steps_json
  local result_json
  local ok="true"
  local overall_status="healthy"

  lanes_json="$(cfctl_collect_lane_health_json)"
  guard_report_json="$(cfctl_backend_guard_report_json)"
  secret_scan_json="$(cfctl_secret_scan_json)"
  runtime_json="$(cfctl_runtime_catalog_json)"
  registry_integrity_json="$(cfctl_registry_integrity_json)"
  preview_health_json="$(cfctl_preview_receipt_health_json)"
  lock_health_json="$(cf_runtime_lock_health_json)"
  bypass_health_json="$(cfctl_bypass_health_json)"

  if [[ "$(jq '(.summary.healthy_lane_count // 0) > 0' <<< "${lanes_json}")" != "true" ]]; then
    ok="false"
    overall_status="unsafe"
  fi

  if [[ "$(jq 'map(select(.guarded != true)) | length == 0' <<< "${guard_report_json}")" != "true" ]]; then
    ok="false"
    overall_status="unsafe"
  fi

  if [[ "$(jq '(.leak_count // 0) == 0' <<< "${secret_scan_json}")" != "true" ]]; then
    ok="false"
    overall_status="unsafe"
  fi

  if [[ "$(jq '(.unsafe_secret_sink_count // 0) == 0' <<< "${secret_scan_json}")" != "true" ]]; then
    ok="false"
    overall_status="unsafe"
  fi

  if [[ "$(jq '(.missing_count // 0) == 0' <<< "${registry_integrity_json}")" != "true" ]]; then
    ok="false"
    overall_status="unsafe"
  fi

  if [[ "$(jq '(.legacy_env_active == true) and (.legacy_env_allowed != true)' <<< "${bypass_health_json}")" == "true" ]]; then
    ok="false"
    overall_status="unsafe"
  fi

  if [[ "${overall_status}" != "unsafe" && "$(jq '(.expired_preview_count // 0) > 0' <<< "${preview_health_json}")" == "true" ]]; then
    overall_status="degraded"
  fi

  if [[ "${overall_status}" != "unsafe" && "$(jq '(.stale_lock_count // 0) > 0' <<< "${lock_health_json}")" == "true" ]]; then
    overall_status="degraded"
  fi

  if [[ "${overall_status}" != "unsafe" && "$(jq '(.authorization_health.expired_count // 0) > 0' <<< "${bypass_health_json}")" == "true" ]]; then
    overall_status="degraded"
  fi

  repair_hints_json="$(cfctl_doctor_repair_hints_json "${preview_health_json}" "${lock_health_json}" "${bypass_health_json}" "${secret_scan_json}" "${registry_integrity_json}")"
  safe_next_steps_json="$(cfctl_safe_next_steps_json "${overall_status}")"

  if [[ "${CFCTL_STRICT}" == "1" && "${overall_status}" != "healthy" ]]; then
    ok="false"
  fi

  result_json="$(
    jq -n \
      --argjson runtime "${runtime_json}" \
      --argjson lanes "${lanes_json}" \
      --argjson backend_guards "${guard_report_json}" \
      --argjson secret_scan "${secret_scan_json}" \
      --argjson registry_integrity "${registry_integrity_json}" \
      --argjson preview_receipts "${preview_health_json}" \
      --argjson lock_health "${lock_health_json}" \
      --argjson bypass_health "${bypass_health_json}" \
      --argjson repair_hints "${repair_hints_json}" \
      --argjson safe_next_steps "${safe_next_steps_json}" \
      --argjson strict_mode "$([[ "${CFCTL_STRICT}" == "1" ]] && echo true || echo false)" \
      --argjson include_repair_hints "$([[ "${CFCTL_REPAIR_HINTS}" == "1" ]] && echo true || echo false)" \
      --arg overall_status "${overall_status}" \
      '
        {
          status: $overall_status,
          strict_mode: $strict_mode,
          runtime: {
            preferred_entrypoint: ($runtime.preferred_entrypoint // null),
            public_verbs: ($runtime.public_verbs // []),
            landing_flow: ($runtime.landing_flow // []),
            policy: ($runtime.policy // {})
          },
          lanes: $lanes,
          backend_guards: {
            scripts: $backend_guards,
            missing: ($backend_guards | map(select(.guarded != true)))
          },
          registry_integrity: $registry_integrity,
          preview_receipts: $preview_receipts,
          lock_health: $lock_health,
          bypass_health: $bypass_health,
          secret_scan: $secret_scan,
          safe_next_steps: $safe_next_steps,
          repair_hints: (if $include_repair_hints == true then $repair_hints else [] end),
          repair_hint_count: ($repair_hints | length)
        }
      '
  )"

  cfctl_emit_result \
    "${ok}" \
    "doctor" \
    "runtime" \
    "runtime" \
    "true" \
    '{"state":"not_applicable","basis":"runtime_health","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
    '{"state":"not_applicable"}' \
    "$(jq '{status: .status, strict_mode: .strict_mode, healthy_lanes: .lanes.summary.healthy_lanes, missing_backend_guards: (.backend_guards.missing | length), registry_policy_gaps: (.registry_integrity.missing_count // 0), secret_leak_count: (.secret_scan.leak_count // 0), unsafe_secret_sink_count: (.secret_scan.unsafe_secret_sink_count // 0), stale_lock_count: (.lock_health.stale_lock_count // 0), orphaned_lock_count: (.lock_health.orphaned_lock_count // 0), expired_preview_count: (.preview_receipts.expired_preview_count // 0), legacy_preview_count: (.preview_receipts.legacy_preview_count // 0), authorization_count: (.bypass_health.authorization_health.authorization_count // 0), expired_authorization_count: (.bypass_health.authorization_health.expired_count // 0), legacy_bypass_active: (.bypass_health.legacy_env_active // false), repair_hint_count: (.repair_hint_count // 0), safe_next_steps: (.safe_next_steps // [])}' <<< "${result_json}")" \
    "${result_json}" \
    "" \
    "$([[ "${ok}" == "true" ]] && printf '' || printf 'runtime_health_failed')" \
    "$([[ "${ok}" == "true" ]] && printf '' || printf 'Doctor found one or more trust blockers or degraded strict-mode conditions')"
}

cfctl_handle_previews() {
  local subcommand="${1:-list}"
  local previews_json
  local purge_json

  case "${subcommand}" in
    list|"")
      previews_json="$(cfctl_preview_rows_json)"
      cfctl_emit_result \
        "true" \
        "previews" \
        "runtime" \
        "runtime" \
        "true" \
        '{"state":"not_applicable","basis":"preview_inventory","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
        '{"state":"not_applicable"}' \
        "$(jq '{preview_count: .preview_count, active_count: .active_count, actionable_count: .actionable_count, expired_count: .expired_count, legacy_count: .legacy_count, inactive_legacy_count: .inactive_legacy_count}' <<< "${previews_json}")" \
        "${previews_json}" \
        ""
      ;;
    purge-expired)
      purge_json="$(cfctl_preview_purge_expired_json)"
      cfctl_emit_result \
        "true" \
        "previews" \
        "runtime" \
        "runtime" \
        "true" \
        '{"state":"not_applicable","basis":"preview_cleanup","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
        '{"state":"not_applicable"}' \
        "$(jq '{purged_count: .purged_count}' <<< "${purge_json}")" \
        "${purge_json}" \
        ""
      ;;
    -h|--help|help)
      cat <<'EOF'
Usage:
  cfctl previews
  cfctl previews purge-expired
EOF
      ;;
    *)
      echo "Unknown previews subcommand: ${subcommand}" >&2
      exit 1
      ;;
  esac
}

cfctl_handle_locks_view() {
  local subcommand="${1:-list}"
  local locks_json
  local clear_json

  case "${subcommand}" in
    list|"")
      locks_json="$(cfctl_lock_rows_json)"
      cfctl_emit_result \
        "true" \
        "locks" \
        "runtime" \
        "runtime" \
        "true" \
        '{"state":"not_applicable","basis":"lock_inventory","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
        '{"state":"not_applicable"}' \
        "$(jq '{lock_count: .lock_count, stale_lock_count: .stale_lock_count, orphaned_lock_count: .orphaned_lock_count}' <<< "${locks_json}")" \
        "${locks_json}" \
        ""
      ;;
    clear-stale)
      clear_json="$(cf_runtime_lock_clear_stale_json)"
      cfctl_emit_result \
        "true" \
        "locks" \
        "runtime" \
        "runtime" \
        "true" \
        '{"state":"not_applicable","basis":"lock_cleanup","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
        '{"state":"not_applicable"}' \
        "$(jq '{cleared_count: .cleared_count, inspected_count: .inspected_count}' <<< "${clear_json}")" \
        "${clear_json}" \
        ""
      ;;
    -h|--help|help)
      cat <<'EOF'
Usage:
  cfctl locks
  cfctl locks clear-stale
EOF
      ;;
    *)
      echo "Unknown locks subcommand: ${subcommand}" >&2
      exit 1
      ;;
  esac
}

cfctl_handle_classify() {
  local surface="$1"
  local requested_operation="$2"
  local policy_json
  local comparison_json
  local permission_json
  local selector_requirements_json
  local recommended_lane
  local lane_hint_json
  local public_example
  local troubleshooting_hint
  local result_json
  local target_action="apply"
  local operation="${requested_operation}"

  if [[ "${surface}" == "token" && "${requested_operation}" == "mint" ]]; then
    policy_json="$(cfctl_operation_policy_json "token" "apply" "mint")"
    public_example="$(jq -r '.public_example // "cfctl token mint --name <token-name> --permission \"<Permission>\" --ttl-hours 24 --plan"' <<< "${policy_json}")"
    troubleshooting_hint="$(jq -r '.troubleshooting_hint // "Use --value-out <absolute path> for real token delivery. Stdout reveal is policy-gated."' <<< "${policy_json}")"
    result_json="$(
      jq -n \
      --argjson policy "${policy_json}" \
      --arg public_example "${public_example}" \
      --arg troubleshooting_hint "${troubleshooting_hint}" \
        '
          {
            surface: "token",
            action: "token",
            operation: "mint",
            policy: $policy,
            lane_comparison: null,
            current_permission_probe: null,
            selector_readiness: {ready: true, missing_required: [], any_satisfied: true},
            lane_hint: {current_lane: null, recommended_lane: null, retry_on_recommended_lane: false},
            public_example: $public_example,
            troubleshooting_hint: $troubleshooting_hint
          }
        '
    )"
    cfctl_emit_result \
      "true" \
      "classify" \
      "token" \
      "registry" \
      "true" \
      '{"state":"not_applicable","basis":"token_policy","errors":[],"request":null,"status_code":null,"permission_family":"Account API Tokens"}' \
      '{"state":"not_applicable"}' \
      "$(jq '.policy' <<< "${result_json}")" \
      "${result_json}" \
      "" \
      "" \
      "" \
      "mint"
    return
  fi

  cfctl_require_surface "${surface}"

  if cfctl_action_supported "${surface}" "${requested_operation}"; then
    target_action="${requested_operation}"
    operation=""
  elif cfctl_action_supported "${surface}" "apply" "${requested_operation}"; then
    target_action="apply"
    operation="${requested_operation}"
  elif [[ "${requested_operation}" == "sync" ]] && cfctl_surface_sync_supported "${surface}"; then
    target_action="apply"
    operation="sync"
  else
    cfctl_emit_failure "classify" "${surface}" "registry" '{"state":"unknown","basis":"unsupported_operation","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_operation" "Unsupported operation ${requested_operation} for ${surface}" "${requested_operation}"
    exit 1
  fi

  if [[ "${target_action}" == "apply" ]]; then
    policy_json="$(cfctl_operation_policy_json "${surface}" "apply" "${operation}")"
  else
    policy_json="$(cfctl_operation_policy_json "${surface}" "${target_action}" "")"
  fi

  selector_requirements_json="$(cfctl_requirement_check_json "${surface}" "${target_action}" "${operation}")"
  comparison_json="$(cfctl_compare_permission_all_lanes "${surface}" "${target_action}" "${operation}")"
  permission_json="$(jq -c --arg lane "${CF_ACTIVE_TOKEN_LANE:-}" '(.lanes | map(select(.lane == $lane)) | .[0].permission) // {state:"unknown", basis:"lane_unavailable", errors: [], request: null, status_code: null, permission_family: "Cloudflare API"}' <<< "${comparison_json}")"
  recommended_lane="$(cfctl_recommended_lane_from_comparison "${comparison_json}")"
  public_example="$(jq -r '.public_example // empty' <<< "${policy_json}")"
  if [[ -z "${public_example}" || "${public_example}" == "null" ]]; then
    if [[ "${target_action}" == "apply" ]]; then
      public_example="$(cfctl_build_apply_command "${surface}" "${operation}" " --plan")"
    else
      public_example="$(cfctl_build_verb_command "${target_action}" "${surface}" "${operation}")"
    fi
  fi
  troubleshooting_hint="$(jq -r '.troubleshooting_hint // empty' <<< "${policy_json}")"
  lane_hint_json="$(
    jq -n \
      --arg current_lane "${CF_ACTIVE_TOKEN_LANE:-}" \
      --arg recommended_lane "${recommended_lane}" \
      --argjson permission "${permission_json}" \
      '
        {
          current_lane: (if $current_lane == "" then null else $current_lane end),
          recommended_lane: (if $recommended_lane == "" then null else $recommended_lane end),
          retry_on_recommended_lane: (
            ($recommended_lane != "")
            and ($recommended_lane != $current_lane)
            and ($permission.state // "") != "allowed"
          )
        }
      '
  )"
  result_json="$(
    jq -n \
      --arg surface "${surface}" \
      --arg action "${target_action}" \
      --arg requested_operation "${requested_operation}" \
      --argjson target "$(cfctl_target_json)" \
      --argjson policy "${policy_json}" \
      --argjson lane_comparison "${comparison_json}" \
      --argjson current_permission_probe "${permission_json}" \
      --argjson selector_readiness "${selector_requirements_json}" \
      --argjson lane_hint "${lane_hint_json}" \
      --arg public_example "${public_example}" \
      --arg troubleshooting_hint "${troubleshooting_hint}" \
      '
        {
          surface: $surface,
          action: $action,
          requested_operation: $requested_operation,
          target: $target,
          policy: $policy,
          lane_comparison: $lane_comparison,
          current_permission_probe: $current_permission_probe,
          selector_readiness: $selector_readiness,
          lane_hint: $lane_hint,
          public_example: $public_example,
          troubleshooting_hint: (if $troubleshooting_hint == "" then null else $troubleshooting_hint end),
          likely_failure_class: (
            if $selector_readiness.ready != true then
              "invalid_arguments"
            elif ($current_permission_probe.state // "") == "denied" then
              "permission_denied"
            elif ($policy.preview_required // false) == true then
              "preview_required"
            else
              null
            end
          )
        }
      '
  )"

  cfctl_emit_result \
    "true" \
    "classify" \
    "${surface}" \
    "registry" \
    "true" \
    "${permission_json}" \
    '{"state":"not_applicable"}' \
    "$(jq '{risk: .policy.risk, preview_required: .policy.preview_required, confirmation: .policy.confirmation, lock_strategy: .policy.lock_strategy, secret_policy: .policy.secret_policy, allowed_lanes: (.lane_comparison.summary.allowed_lanes // []), selector_ready: .selector_readiness.ready, recommended_lane: .lane_hint.recommended_lane, likely_failure_class: .likely_failure_class}' <<< "${result_json}")" \
    "${result_json}" \
    "" \
    "" \
    "" \
    "${requested_operation}"
}

cfctl_handle_guide() {
  local surface="$1"
  local requested_operation="$2"
  local args_shell
  local guide_json
  local policy_json
  local preview_command
  local apply_command
  local verify_command=""
  local discovery_command=""
  local lane_comparison
  local current_lane
  local recommended_lane
  local command_prefix=""
  local troubleshooting_hint=""
  local public_example=""

  args_shell="$(cfctl_current_args_shell)"

  if [[ "${surface}" == "token" && "${requested_operation}" == "mint" ]]; then
    local token_policy_json
    token_policy_json="$(cfctl_operation_policy_json "token" "apply" "mint")"
    preview_command="cfctl token mint${args_shell} --plan"
    apply_command="cfctl token mint${args_shell} --ack-plan <operation-id> --value-out <secure-path>"
    troubleshooting_hint="$(jq -r '.troubleshooting_hint // "Use an absolute non-repo path for --value-out. Repo paths, var/, and symlinks are rejected."' <<< "${token_policy_json}")"
    guide_json="$(
      jq -n \
        --arg preview_command "${preview_command}" \
        --arg apply_command "${apply_command}" \
        --argjson policy "${token_policy_json}" \
        --arg troubleshooting_hint "${troubleshooting_hint}" \
        --argjson reveal_allowed "$(if cf_runtime_token_reveal_allowed; then echo true; else echo false; fi)" \
        '
          {
            surface: "token",
            operation: "mint",
            policy: $policy,
            steps: [
              "Run permission-group discovery first if needed.",
              "Run the preview command and inspect the request body.",
              "For a real mint, use --value-out <secure-path>.",
              (
                if $reveal_allowed == true then
                  "Use --reveal-token-once only when you intentionally need a one-time stdout reveal."
                else
                  "Stdout reveal is disabled by runtime policy. Use --value-out <secure-path>."
                end
              )
            ],
            troubleshooting_hint: $troubleshooting_hint,
            commands: {
              discovery: "cfctl token permission-groups --name \"<filter>\"",
              preview: $preview_command,
              apply: $apply_command
            }
          }
        '
    )"
    cfctl_emit_result \
      "true" \
      "guide" \
      "token" \
      "registry" \
      "true" \
      '{"state":"not_applicable","basis":"token_policy","errors":[],"request":null,"status_code":null,"permission_family":"Account API Tokens"}' \
      '{"state":"not_applicable"}' \
      "$(jq '.commands' <<< "${guide_json}")" \
      "${guide_json}" \
      "" \
      "" \
      "" \
      "mint"
    return
  fi

  cfctl_require_surface "${surface}"
  if [[ "${requested_operation}" == "sync" ]]; then
    if ! cfctl_surface_sync_supported "${surface}"; then
      cfctl_emit_failure "guide" "${surface}" "registry" '{"state":"unknown","basis":"sync_unsupported","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_operation" "Desired-state sync is not supported for ${surface}" "${requested_operation}"
      exit 1
    fi
  elif ! cfctl_action_supported "${surface}" "apply" "${requested_operation}"; then
    cfctl_emit_failure "guide" "${surface}" "registry" '{"state":"unknown","basis":"unsupported_operation","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_operation" "Unsupported operation ${requested_operation} for ${surface}" "${requested_operation}"
    exit 1
  fi
  lane_comparison="$(cfctl_compare_permission_all_lanes "${surface}" "apply" "${requested_operation}")"
  current_lane="${CF_ACTIVE_TOKEN_LANE:-}"
  recommended_lane="$(jq -r '.summary.allowed_lanes[0] // empty' <<< "${lane_comparison}")"
  if [[ -n "${recommended_lane}" && "${recommended_lane}" != "${current_lane}" ]]; then
    command_prefix="CF_TOKEN_LANE=${recommended_lane} "
  fi
  policy_json="$(cfctl_operation_policy_json "${surface}" "apply" "${requested_operation}")"

  preview_command="${command_prefix}$(cfctl_build_apply_command "${surface}" "${requested_operation}" " --plan")"
  apply_command="${command_prefix}$(cfctl_build_apply_command "${surface}" "${requested_operation}" " --ack-plan <operation-id>")"
  discovery_command="$(cfctl_surface_discovery_command "${surface}" "${recommended_lane}")"
  verify_command="$(cfctl_surface_verify_command "${surface}" "${recommended_lane}")"
  if [[ -n "$(cfctl_required_confirmation "${surface}" "${requested_operation}")" ]]; then
    apply_command="$(printf '%s --confirm %q' "${apply_command}" "$(cfctl_required_confirmation "${surface}" "${requested_operation}")")"
  fi
  public_example="$(jq -r '.public_example // empty' <<< "${policy_json}")"
  if [[ -z "${public_example}" || "${public_example}" == "null" ]]; then
    public_example="${preview_command}"
  fi
  troubleshooting_hint="$(jq -r '.troubleshooting_hint // empty' <<< "${policy_json}")"

  guide_json="$(
    jq -n \
      --arg surface "${surface}" \
      --arg operation "${requested_operation}" \
      --arg discovery_command "${discovery_command}" \
      --arg preview_command "${preview_command}" \
      --arg apply_command "${apply_command}" \
      --arg verify_command "${verify_command}" \
      --arg current_lane "${current_lane}" \
      --arg recommended_lane "${recommended_lane}" \
      --arg public_example "${public_example}" \
      --arg troubleshooting_hint "${troubleshooting_hint}" \
      --arg module "$(cfctl_surface_module_name "${surface}")" \
      --arg standards_ref "$(cfctl_surface_standards_ref "${surface}")" \
      --argjson docs_topics "$(cfctl_surface_docs_topics_json "${surface}")" \
      --argjson policy "${policy_json}" \
      '
        {
          surface: $surface,
          operation: $operation,
          module: (if $module == "" then null else $module end),
          standards_ref: (if $standards_ref == "" then null else $standards_ref end),
          docs_topics: $docs_topics,
          policy: $policy,
          lane_hint: {
            current_lane: (if $current_lane == "" then null else $current_lane end),
            recommended_lane: (if $recommended_lane == "" then null else $recommended_lane end)
          },
          steps: [
            "Run the discovery command first if you still need to confirm the target.",
            "Run the preview command first.",
            "Inspect the preview artifact and capture its operation_id.",
            "Run the apply command with --ack-plan <operation-id> after review.",
            (
              if $verify_command == "" then
                "Use list/get commands to confirm the new state."
              else
                "Run the verification command after the mutation completes."
              end
            )
          ],
          public_example: $public_example,
          troubleshooting_hint: (if $troubleshooting_hint == "" then null else $troubleshooting_hint end),
          commands: {
            discovery: $discovery_command,
            preview: $preview_command,
            apply: $apply_command,
            verify: (if $verify_command == "" then null else $verify_command end)
          }
        }
      '
  )"

  cfctl_emit_result \
    "true" \
    "guide" \
    "${surface}" \
    "registry" \
    "true" \
    '{"state":"not_applicable","basis":"guide","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
    '{"state":"not_applicable"}' \
    "$(jq '.commands' <<< "${guide_json}")" \
    "${guide_json}" \
    "" \
    "" \
    "" \
    "${requested_operation}"
}

cfctl_handle_list_surfaces() {
  local result_json
  local surfaces_json='[]'
  local surface
  local lane_fit_json
  local lane_requirements_json
  local read_supported="false"
  local write_supported="false"
  local supported_verbs_json
  local apply_operations_json
  local write_risks_json
  local mode

  while IFS= read -r surface; do
    supported_verbs_json="$(cfctl_surface_supported_verbs_json "${surface}")"
    apply_operations_json="$(cfctl_surface_supported_apply_operations_json "${surface}")"
    write_risks_json="$(cfctl_surface_write_risks_json "${surface}")"
    lane_requirements_json="$(cfctl_requirement_check_json "${surface}" "list")"
    lane_fit_json="$(cfctl_compare_permission_all_lanes "${surface}" "list")"
    read_supported="$(
      jq -e 'index("list") != null or index("get") != null or index("verify") != null' <<< "${supported_verbs_json}" >/dev/null 2>&1 && echo true || echo false
    )"
    write_supported="$(
      [[ "$(jq 'length > 0' <<< "${apply_operations_json}")" == "true" ]] && echo true || echo false
    )"
    mode="$(cfctl_surface_mode "${surface}")"
    surfaces_json="$(
      jq \
        --arg surface "${surface}" \
        --arg mode "${mode}" \
        --argjson meta "$(cfctl_surface_meta "${surface}")" \
        --argjson supported_verbs "${supported_verbs_json}" \
        --argjson apply_operations "${apply_operations_json}" \
        --argjson write_risks "${write_risks_json}" \
        --argjson desired_state "$(cfctl_surface_state_meta "${surface}")" \
        --arg module "$(cfctl_surface_module_name "${surface}")" \
        --arg standards_ref "$(cfctl_surface_standards_ref "${surface}")" \
        --argjson docs_topics "$(cfctl_surface_docs_topics_json "${surface}")" \
        --argjson lane_requirements "${lane_requirements_json}" \
        --argjson lane_fit "${lane_fit_json}" \
        --argjson read_supported "${read_supported}" \
        --argjson write_supported "${write_supported}" \
        '
          . + [{
            surface: $surface,
            description: ($meta.description // null),
            backend: ($meta.backend // null),
            module: (if $module == "" then null else $module end),
            standards_ref: (if $standards_ref == "" then null else $standards_ref end),
            docs_topics: $docs_topics,
            mode: $mode,
            selectors: ($meta.selectors // []),
            supported_verbs: $supported_verbs,
            read_supported: $read_supported,
            write_supported: $write_supported,
            apply_operations: $apply_operations,
            write_risk_classes: $write_risks,
            desired_state_supported: ($desired_state.supported // false),
            sync_supported: ($desired_state.sync_supported // false),
            default_lane_fit: {
              current_lane: ($lane_fit.active_lane // null),
              status: (
                if ($lane_requirements.error // null) != null then
                  "unsupported"
                elif ($lane_requirements.ready // false) != true then
                  "selector_dependent"
                elif (
                  (($lane_fit.summary.allowed_lanes // []) | length) > 0
                  or (($lane_fit.summary.denied_lanes // []) | length) > 0
                ) then
                  "resolved"
                else
                  "unknown"
                end
              ),
              selector_ready: ($lane_requirements.ready // false),
              required_selectors: ($lane_requirements.required_selectors // []),
              selectors_any_of: ($lane_requirements.selectors_any_of // []),
              missing_required: ($lane_requirements.missing_required // []),
              allowed_lanes: (
                if ($lane_requirements.ready // false) == true then
                  ($lane_fit.summary.allowed_lanes // [])
                else
                  []
                end
              ),
              denied_lanes: (
                if ($lane_requirements.ready // false) == true then
                  ($lane_fit.summary.denied_lanes // [])
                else
                  []
                end
              ),
              unknown_lanes: ($lane_fit.summary.unknown_lanes // []),
              recommended_lane: (
                if (
                  ($lane_requirements.ready // false) != true
                  or (($lane_fit.summary.allowed_lanes // []) | length) == 0
                ) then
                  null
                else
                  ($lane_fit.summary.allowed_lanes[0] // null)
                end
              )
            }
          }]
        ' \
        <<< "${surfaces_json}"
    )"
  done < <(jq -r '.surfaces | keys[]' "${CFCTL_REGISTRY_PATH}" | sort)

  result_json="$(
    jq -n \
      --argjson registry "$(cfctl_registry_json)" \
      --argjson runtime "$(cfctl_runtime_catalog_json)" \
      --argjson surfaces "${surfaces_json}" \
      '
        {
          registry_version: ($registry.version // null),
          runtime_version: ($runtime.version // null),
          public_verbs: ($runtime.public_verbs // []),
          landing_flow: ($runtime.landing_flow // []),
          policy: ($runtime.policy // {}),
          surfaces: ($surfaces | sort_by(.surface))
        }
      '
  )"

  cfctl_emit_result \
    "true" \
    "list" \
    "surfaces" \
    "registry" \
    "true" \
    '{"state":"not_applicable","basis":"registry","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
    '{"state":"not_applicable"}' \
    "$(jq -n --argjson result "${result_json}" '{count: ($result.surfaces | length), public_verbs: $result.public_verbs, landing_flow: $result.landing_flow, writable_surface_count: ($result.surfaces | map(select(.write_supported == true)) | length), desired_state_surface_count: ($result.surfaces | map(select(.desired_state_supported == true)) | length)}')" \
    "${result_json}" \
    ""
}

cfctl_handle_standards() {
  local surface="${1:-}"
  local result_json
  local runtime_json='null'
  local summary_json

  if [[ -z "${surface}" ]]; then
    result_json="$(
      jq -n \
        --argjson standards "$(cfctl_standards_json)" \
        '
          {
            version: ($standards.version // null),
            title: ($standards.title // null),
            intent: ($standards.intent // null),
            default_change_path: ($standards.default_change_path // []),
            universal: ($standards.universal // []),
            surfaces: (
              ($standards.surfaces // {})
              | to_entries
              | map({
                  surface: .key,
                  stance: (.value.stance // null),
                  standard_count: ((.value.standards // []) | length),
                  required_count: ((.value.standards // []) | map(select(.level == "required")) | length),
                  recommended_count: ((.value.standards // []) | map(select(.level == "recommended")) | length),
                  evidence: (.value.evidence // [])
                })
              | sort_by(.surface)
            )
          }
        '
    )"

    cfctl_emit_result \
      "true" \
      "standards" \
      "all" \
      "catalog" \
      "true" \
      '{"state":"not_applicable","basis":"catalog","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
      '{"state":"not_applicable"}' \
      "$(jq '{surface_count: (.surfaces | length), universal_standard_count: (.universal | length), default_change_path: .default_change_path}' <<< "${result_json}")" \
      "${result_json}" \
      ""
    return
  fi

  if ! cfctl_has_standards_surface "${surface}"; then
    cfctl_emit_failure "standards" "${surface}" "catalog" '{"state":"unknown","basis":"missing_surface_standard","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_surface" "No standards registered for ${surface}"
    exit 1
  fi

  if cfctl_has_surface "${surface}"; then
    runtime_json="$(
      jq -n \
        --argjson surface_meta "$(cfctl_surface_meta "${surface}")" \
        --argjson state_meta "$(cfctl_surface_state_meta "${surface}")" \
        --argjson supported_verbs "$(cfctl_surface_supported_verbs_json "${surface}")" \
        --argjson apply_operations "$(cfctl_surface_supported_apply_operations_json "${surface}")" \
        --argjson write_risks "$(cfctl_surface_write_risks_json "${surface}")" \
        '
          {
            description: ($surface_meta.description // null),
            backend: ($surface_meta.backend // null),
            selectors: ($surface_meta.selectors // []),
            supported_verbs: $supported_verbs,
            apply_operations: $apply_operations,
            write_risk_classes: $write_risks,
            desired_state_supported: ($state_meta.supported // false),
            sync_supported: ($state_meta.sync_supported // false)
          }
        '
    )"
  fi

  result_json="$(
    jq -n \
      --arg surface "${surface}" \
      --argjson standards "$(cfctl_standards_json)" \
      --argjson runtime "${runtime_json}" \
      '
        {
          version: ($standards.version // null),
          title: ($standards.title // null),
          surface: $surface,
          intent: ($standards.intent // null),
          default_change_path: ($standards.default_change_path // []),
          universal: ($standards.universal // []),
          standard: ($standards.surfaces[$surface] // {}),
          runtime: $runtime,
          standards_only: ($runtime == null)
        }
      '
  )"

  summary_json="$(
    jq '
      {
        surface: .surface,
        standard_count: (.standard.standards | length),
        required_count: (.standard.standards | map(select(.level == "required")) | length),
        standards_only: .standards_only,
        desired_state_supported: (.runtime.desired_state_supported // false),
        apply_operation_count: ((.runtime.apply_operations // []) | length),
        audit_feature_count: ((.standard.audit_features // []) | length)
      }
    ' <<< "${result_json}"
  )"

  cfctl_emit_result \
    "true" \
    "standards" \
    "${surface}" \
    "catalog" \
    "true" \
    '{"state":"not_applicable","basis":"catalog","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
    '{"state":"not_applicable"}' \
    "${summary_json}" \
    "${result_json}" \
    ""
}

cfctl_handle_docs() {
  local topic="${1:-}"
  local result_json
  local summary_json
  local now_iso

  now_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  if [[ -z "${topic}" ]]; then
    result_json="$(
      jq -n \
        --arg now_iso "${now_iso}" \
        --argjson bank "$(cfctl_doc_bank_json)" \
        '
          {
            version: ($bank.version // null),
            title: ($bank.title // null),
            checked_on: ($bank.checked_on // null),
            intent: ($bank.intent // null),
            source_policy: ($bank.source_policy // {}),
            refresh_policy: ($bank.refresh_policy // {}),
            freshness: (
              (($bank.checked_on // null) + "T00:00:00Z") as $checked_iso
              | ($bank.refresh_policy.refresh_interval_days // 30) as $interval
              | {
                  checked_on: ($bank.checked_on // null),
                  refresh_interval_days: $interval,
                  age_days: (((($now_iso | fromdateiso8601) - ($checked_iso | fromdateiso8601)) / 86400) | floor),
                  refresh_due: (((($now_iso | fromdateiso8601) - ($checked_iso | fromdateiso8601)) / 86400) | floor) > $interval
                }
            ),
            docs_access: ($bank.docs_access // {}),
            foundation: (
              ($bank.foundation // [])
              | map({
                  id,
                  title,
                  area: (.area // null),
                  status: (.status // null),
                  summary,
                  why_it_matters_here,
                  source_count: ((.sources // []) | length)
                })
            ),
            watch: (
              ($bank.watch // [])
              | map({
                  id,
                  title,
                  area: (.area // null),
                  status: (.status // null),
                  source_date: (.source_date // null),
                  summary,
                  why_it_matters_here,
                  source_count: ((.sources // []) | length)
                })
            ),
            excluded_noise: ($bank.excluded_noise // [])
          }
        '
    )"

    summary_json="$(
      jq '
        {
          checked_on: .checked_on,
          freshness: .freshness,
          foundation_count: (.foundation | length),
          watch_count: (.watch | length),
          watch_statuses: (
            (.watch | group_by(.status) | map({status: .[0].status, count: length}))
          )
        }
      ' <<< "${result_json}"
    )"

    cfctl_emit_result \
      "true" \
      "docs" \
      "all" \
      "catalog" \
      "true" \
      '{"state":"not_applicable","basis":"catalog","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
      '{"state":"not_applicable"}' \
      "${summary_json}" \
      "${result_json}" \
      ""
    return
  fi

  if ! cfctl_has_doc_bank_topic "${topic}"; then
    cfctl_emit_failure "docs" "${topic}" "catalog" '{"state":"unknown","basis":"missing_docs_topic","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "invalid_arguments" "No Cloudflare docs bank topic registered for ${topic}"
    exit 1
  fi

  if [[ "${topic}" == "foundation" || "${topic}" == "watch" ]]; then
    result_json="$(
      jq -n \
        --arg topic "${topic}" \
        --arg now_iso "${now_iso}" \
        --argjson bank "$(cfctl_doc_bank_json)" \
        '
          {
            version: ($bank.version // null),
            title: ($bank.title // null),
            checked_on: ($bank.checked_on // null),
            topic: $topic,
            intent: ($bank.intent // null),
            source_policy: ($bank.source_policy // {}),
            refresh_policy: ($bank.refresh_policy // {}),
            freshness: (
              (($bank.checked_on // null) + "T00:00:00Z") as $checked_iso
              | ($bank.refresh_policy.refresh_interval_days // 30) as $interval
              | {
                  checked_on: ($bank.checked_on // null),
                  refresh_interval_days: $interval,
                  age_days: (((($now_iso | fromdateiso8601) - ($checked_iso | fromdateiso8601)) / 86400) | floor),
                  refresh_due: (((($now_iso | fromdateiso8601) - ($checked_iso | fromdateiso8601)) / 86400) | floor) > $interval
                }
            ),
            items: (
              if $topic == "foundation" then
                ($bank.foundation // [])
              else
                ($bank.watch // [])
              end
            )
          }
        '
    )"

    summary_json="$(
      jq '
        {
          topic: .topic,
          checked_on: .checked_on,
          freshness: .freshness,
          item_count: (.items | length),
          status_counts: (
            (.items | group_by(.status) | map({status: .[0].status, count: length}))
          )
        }
      ' <<< "${result_json}"
    )"

    cfctl_emit_result \
      "true" \
      "docs" \
      "${topic}" \
      "catalog" \
      "true" \
      '{"state":"not_applicable","basis":"catalog","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
      '{"state":"not_applicable"}' \
      "${summary_json}" \
      "${result_json}" \
      ""
    return
  fi

  result_json="$(
    jq -n \
      --arg topic "${topic}" \
      --arg now_iso "${now_iso}" \
      --argjson bank "$(cfctl_doc_bank_json)" \
      '
        (($bank.foundation // []) | map(select(.id == $topic)) | .[0]) as $foundation_entry
        | (($bank.watch // []) | map(select(.id == $topic)) | .[0]) as $watch_entry
        | if $foundation_entry != null then
            {
              version: ($bank.version // null),
              title: ($bank.title // null),
              checked_on: ($bank.checked_on // null),
              freshness: (
                (($bank.checked_on // null) + "T00:00:00Z") as $checked_iso
                | ($bank.refresh_policy.refresh_interval_days // 30) as $interval
                | {
                    checked_on: ($bank.checked_on // null),
                    refresh_interval_days: $interval,
                    age_days: (((($now_iso | fromdateiso8601) - ($checked_iso | fromdateiso8601)) / 86400) | floor),
                    refresh_due: (((($now_iso | fromdateiso8601) - ($checked_iso | fromdateiso8601)) / 86400) | floor) > $interval
                  }
              ),
              topic: $topic,
              kind: "foundation",
              entry: $foundation_entry
            }
          else
            {
              version: ($bank.version // null),
              title: ($bank.title // null),
              checked_on: ($bank.checked_on // null),
              freshness: (
                (($bank.checked_on // null) + "T00:00:00Z") as $checked_iso
                | ($bank.refresh_policy.refresh_interval_days // 30) as $interval
                | {
                    checked_on: ($bank.checked_on // null),
                    refresh_interval_days: $interval,
                    age_days: (((($now_iso | fromdateiso8601) - ($checked_iso | fromdateiso8601)) / 86400) | floor),
                    refresh_due: (((($now_iso | fromdateiso8601) - ($checked_iso | fromdateiso8601)) / 86400) | floor) > $interval
                  }
              ),
              topic: $topic,
              kind: "watch",
              entry: $watch_entry
            }
          end
      '
  )"

  summary_json="$(
    jq '
      {
        topic: .topic,
        kind: .kind,
        checked_on: .checked_on,
        freshness: .freshness,
        title: .entry.title,
        status: (.entry.status // null),
        source_date: (.entry.source_date // null),
        source_count: ((.entry.sources // []) | length)
      }
    ' <<< "${result_json}"
  )"

  cfctl_emit_result \
    "true" \
    "docs" \
    "${topic}" \
    "catalog" \
    "true" \
    '{"state":"not_applicable","basis":"catalog","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
    '{"state":"not_applicable"}' \
    "${summary_json}" \
    "${result_json}" \
    ""
}

cfctl_handle_standards_audit() {
  local requested_root="${1:-}"
  local audit_root="${requested_root}"
  local resolved_root=""
  local result_json
  local summary_json

  if [[ -z "${audit_root}" ]]; then
    audit_root="$(cfctl_standards_audit_default_root)"
  fi

  resolved_root="$(cf_realpath_best_effort "${audit_root}" 2>/dev/null || true)"
  if [[ -z "${resolved_root}" ]] || [[ ! -d "${resolved_root}" ]]; then
    cfctl_emit_failure "standards" "audit" "catalog" '{"state":"not_applicable","basis":"standards_audit","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "invalid_arguments" "Standards audit root is not a readable directory: ${audit_root}"
    exit 1
  fi

  result_json="$(
    cfctl_workspace_standards_audit_json "${resolved_root}" \
      | jq --arg root "${resolved_root}" '{root: $root} + .'
  )"

  summary_json="$(
    jq '
      {
        root: .root,
        config_file_count: .config_file_count,
        covered_feature_count: .coverage.covered_feature_count,
        uncovered_feature_count: .coverage.uncovered_feature_count,
        compatibility_date_aging_count: (.compatibility_date_freshness.aging_count // 0),
        compatibility_date_stale_count: (.compatibility_date_freshness.stale_count // 0),
        warning_count: .findings_summary.warning_count,
        note_count: .findings_summary.note_count
      }
    ' <<< "${result_json}"
  )"

  cfctl_emit_result \
    "true" \
    "standards" \
    "audit" \
    "catalog" \
    "true" \
    '{"state":"not_applicable","basis":"catalog","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
    '{"state":"not_applicable"}' \
    "${summary_json}" \
    "${result_json}" \
    ""
}

cfctl_collect_filtered_items_or_fail() {
  local action="$1"
  local surface="$2"
  local operation="${3:-}"

  cfctl_collect_surface_items "${surface}"
  if [[ -n "${CFCTL_COLLECT_ERROR_CODE}" ]]; then
    cfctl_emit_result \
      "false" \
      "${action}" \
      "${surface}" \
      "${CFCTL_COLLECT_BACKEND:-unknown}" \
      "false" \
      "${CFCTL_PERMISSION_JSON}" \
      '{"state":"not_applicable"}' \
      "$(jq -n --arg message "${CFCTL_COLLECT_ERROR_MESSAGE}" '{message: $message}')" \
      "${CFCTL_COLLECT_SOURCE_JSON}" \
      "${CFCTL_COLLECT_BACKEND_ARTIFACT_PATH}" \
      "${CFCTL_COLLECT_ERROR_CODE}" \
      "${CFCTL_COLLECT_ERROR_MESSAGE}" \
      "${operation}"
    exit 1
  fi

  CFCTL_FILTERED_ITEMS_JSON="$(cfctl_filter_surface_items "${surface}" "${CFCTL_COLLECT_ITEMS_JSON}")"
}

cfctl_handle_explain() {
  local surface="${1:-}"
  local result_json
  local mode
  local supported_verbs_json
  local supported_operations_json
  local list_lane_comparison_json
  local operation_rows='[]'
  local operation

  if [[ -z "${surface}" || "${surface}" == "surfaces" ]]; then
    cfctl_handle_list_surfaces
    return
  fi

  cfctl_require_surface "${surface}"
  mode="$(cfctl_surface_mode "${surface}")"
  supported_verbs_json="$(cfctl_surface_supported_verbs_json "${surface}")"
  supported_operations_json="$(cfctl_surface_supported_apply_operations_json "${surface}")"
  list_lane_comparison_json="$(cfctl_compare_permission_all_lanes "${surface}" "list")"
  while IFS= read -r operation; do
    [[ -n "${operation}" ]] || continue
    operation_rows="$(
      jq \
        --arg operation "${operation}" \
        --argjson policy "$(cfctl_operation_policy_json "${surface}" "apply" "${operation}")" \
        --argjson requirements "$(cfctl_requirement_check_json "${surface}" "apply" "${operation}")" \
        --argjson lane_comparison "$(cfctl_compare_permission_all_lanes "${surface}" "apply" "${operation}")" \
        '. + [{
          operation: $operation,
          policy: $policy,
          selector_readiness: $requirements,
          lane_comparison: $lane_comparison
        }]' \
        <<< "${operation_rows}"
    )"
  done < <(jq -r '.[]' <<< "${supported_operations_json}")
  result_json="$(
    jq -n \
      --arg surface "${surface}" \
      --argjson meta "$(cfctl_surface_meta "${surface}")" \
      --argjson target "$(cfctl_target_json)" \
      --argjson permission "$(cfctl_probe_permission "${surface}" "list")" \
      --argjson state_meta "$(cfctl_surface_state_meta "${surface}")" \
      --argjson runtime "$(cfctl_runtime_catalog_json)" \
      --arg module "$(cfctl_surface_module_name "${surface}")" \
      --arg standards_ref "$(cfctl_surface_standards_ref "${surface}")" \
      --argjson docs_topics "$(cfctl_surface_docs_topics_json "${surface}")" \
      --arg inventory_script "$(cfctl_surface_inventory_script_relpath "${surface}")" \
      --arg apply_script "$(cfctl_surface_apply_script_relpath "${surface}")" \
      --arg mode "${mode}" \
      --argjson supported_verbs "${supported_verbs_json}" \
      --argjson supported_operations "${supported_operations_json}" \
      --argjson list_lane_comparison "${list_lane_comparison_json}" \
      --argjson operation_rows "${operation_rows}" \
      '
        {
          surface: $surface,
          mode: $mode,
          target_context: $target,
          current_permission_probe: $permission,
          module: (if $module == "" then null else $module end),
          standards_ref: (if $standards_ref == "" then null else $standards_ref end),
          docs_topics: $docs_topics,
          metadata: $meta,
          desired_state: $state_meta,
          public_verbs: ($runtime.public_verbs // []),
          selectors: ($meta.selectors // []),
          supported_verbs: $supported_verbs,
          supported_operations: $supported_operations,
          verification_behavior: {
            verify_supported: (($supported_verbs | index("verify")) != null),
            readback_backend: ($meta.inventory_script // null)
          },
          implementation: {
            inventory_script: (if $inventory_script == "" then null else $inventory_script end),
            apply_script: (if $apply_script == "" then null else $apply_script end)
          },
          lane_caveats: {
            list_lane_comparison: $list_lane_comparison,
            recommended_lane: ($list_lane_comparison.summary.allowed_lanes[0] // null)
          },
          operation_policies: $operation_rows,
          backend_policy: ($runtime.policy.backend_scripts // null),
          examples: ($meta.examples // [])
        }
      '
  )"

  cfctl_emit_result \
    "true" \
    "explain" \
    "${surface}" \
    "registry" \
    "true" \
    "$(jq '.current_permission_probe' <<< "${result_json}")" \
    '{"state":"not_applicable"}' \
    "$(jq '{surface: .surface, mode: .mode, supported_verbs: .supported_verbs, supported_operations: .supported_operations, recommended_lane: .lane_caveats.recommended_lane, desired_state: .desired_state}' <<< "${result_json}")" \
    "${result_json}" \
    ""
}

cfctl_handle_can() {
  local surface="$1"
  local requested_operation="$2"
  local target_action=""
  local apply_operation=""
  local permission_json
  local comparison_json
  local current_lane

  cfctl_require_surface "${surface}"

  if cfctl_action_supported "${surface}" "${requested_operation}"; then
    target_action="${requested_operation}"
  elif cfctl_action_supported "${surface}" "apply" "${requested_operation}"; then
    target_action="apply"
    apply_operation="${requested_operation}"
  elif [[ "${requested_operation}" == "sync" ]] && cfctl_surface_sync_supported "${surface}"; then
    target_action="apply"
    apply_operation="sync"
  else
    cfctl_emit_failure "can" "${surface}" "registry" '{"state":"unknown","basis":"unsupported_operation","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_operation" "Unsupported operation ${requested_operation} for ${surface}" "${requested_operation}"
    exit 1
  fi

  if [[ "${CFCTL_ALL_LANES}" == "1" ]]; then
    comparison_json="$(cfctl_compare_permission_all_lanes "${surface}" "${target_action}" "${apply_operation}")"
    current_lane="${CF_ACTIVE_TOKEN_LANE:-}"
    permission_json="$(jq -c --arg lane "${current_lane}" '(.lanes | map(select(.lane == $lane)) | .[0].permission) // {state:"unknown", basis:"lane_unavailable", errors: [], request: null, status_code: null, permission_family: "Cloudflare API"}' <<< "${comparison_json}")"

    cfctl_emit_result \
      "true" \
      "can" \
      "${surface}" \
      "permission_probe" \
      "true" \
      "${permission_json}" \
      '{"state":"not_applicable"}' \
      "$(jq -n --arg operation "${requested_operation}" --argjson comparison "${comparison_json}" '{operation: $operation, allowed_lanes: ($comparison.summary.allowed_lanes // []), denied_lanes: ($comparison.summary.denied_lanes // [])}')" \
      "${comparison_json}" \
      "" \
      "" \
      "" \
      "${requested_operation}"
    return
  fi

  permission_json="$(cfctl_probe_permission "${surface}" "${target_action}" "${apply_operation}")"
  cfctl_emit_result \
    "true" \
    "can" \
    "${surface}" \
    "permission_probe" \
    "true" \
    "${permission_json}" \
    '{"state":"not_applicable"}' \
    "$(jq -n --arg operation "${requested_operation}" '{operation: $operation}')" \
    "$(jq -n --arg operation "${requested_operation}" '{operation: $operation}')" \
    "" \
    "" \
    "" \
    "${requested_operation}"
}

cfctl_handle_list_like() {
  local action="$1"
  local surface="$2"

  if [[ "${surface}" == "surfaces" ]]; then
    cfctl_handle_list_surfaces
    return
  fi

  cfctl_require_surface "${surface}"
  if ! cfctl_action_supported "${surface}" "list"; then
    cfctl_emit_failure "${action}" "${surface}" "registry" '{"state":"unknown","basis":"unsupported_operation","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_operation" "${action} is not supported for ${surface}"
    exit 1
  fi

  if ! cfctl_validate_requirements "${surface}" "list"; then
    cfctl_emit_failure "${action}" "${surface}" "registry" '{"state":"unknown","basis":"invalid_arguments","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "invalid_arguments" "Invalid selectors for ${surface} ${action}"
    exit 1
  fi

  cfctl_action_permission_gate "${surface}" "list"
  cfctl_collect_filtered_items_or_fail "${action}" "${surface}"

  cfctl_emit_result \
    "true" \
    "${action}" \
    "${surface}" \
    "${CFCTL_COLLECT_BACKEND}" \
    "true" \
    "${CFCTL_PERMISSION_JSON}" \
    '{"state":"not_applicable"}' \
    "$(cfctl_summary_for_items "${surface}" "${CFCTL_FILTERED_ITEMS_JSON}")" \
    "${CFCTL_FILTERED_ITEMS_JSON}" \
    "${CFCTL_COLLECT_BACKEND_ARTIFACT_PATH}"
}

cfctl_handle_get_like() {
  local action="$1"
  local surface="$2"

  cfctl_require_surface "${surface}"
  if ! cfctl_action_supported "${surface}" "${action}"; then
    cfctl_emit_failure "${action}" "${surface}" "registry" '{"state":"unknown","basis":"unsupported_operation","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_operation" "${action} is not supported for ${surface}"
    exit 1
  fi

  if ! cfctl_validate_requirements "${surface}" "${action}"; then
    cfctl_emit_failure "${action}" "${surface}" "registry" '{"state":"unknown","basis":"invalid_arguments","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "invalid_arguments" "Invalid selectors for ${surface} ${action}"
    exit 1
  fi

  cfctl_action_permission_gate "${surface}" "${action}"
  cfctl_collect_filtered_items_or_fail "${action}" "${surface}"

  local match_count
  match_count="$(jq 'length' <<< "${CFCTL_FILTERED_ITEMS_JSON}")"
  if [[ "${match_count}" == "0" ]]; then
    cfctl_emit_result \
      "false" \
      "${action}" \
      "${surface}" \
      "${CFCTL_COLLECT_BACKEND}" \
      "false" \
      "${CFCTL_PERMISSION_JSON}" \
      '{"state":"not_applicable"}' \
      "$(jq -n --arg message "No matching resource found" '{message: $message}')" \
      "${CFCTL_FILTERED_ITEMS_JSON}" \
      "${CFCTL_COLLECT_BACKEND_ARTIFACT_PATH}" \
      "target_not_found" \
      "No matching resource found"
    exit 1
  fi

  if [[ "${match_count}" != "1" ]]; then
    cfctl_emit_result \
      "false" \
      "${action}" \
      "${surface}" \
      "${CFCTL_COLLECT_BACKEND}" \
      "false" \
      "${CFCTL_PERMISSION_JSON}" \
      '{"state":"not_applicable"}' \
      "$(jq -n --argjson count "${match_count}" '{count: $count}')" \
      "${CFCTL_FILTERED_ITEMS_JSON}" \
      "${CFCTL_COLLECT_BACKEND_ARTIFACT_PATH}" \
      "target_ambiguous" \
      "Multiple resources matched the selectors"
    exit 1
  fi

  local item_json
  local verification_state="not_applicable"
  item_json="$(jq '.[0]' <<< "${CFCTL_FILTERED_ITEMS_JSON}")"
  if [[ "${action}" == "verify" ]]; then
    verification_state="verified"
  fi

  cfctl_emit_result \
    "true" \
    "${action}" \
    "${surface}" \
    "${CFCTL_COLLECT_BACKEND}" \
    "true" \
    "${CFCTL_PERMISSION_JSON}" \
    "$(jq -n --arg state "${verification_state}" '{state: $state}')" \
    "$(cfctl_summary_for_items "${surface}" "[${item_json}]")" \
    "${item_json}" \
    "${CFCTL_COLLECT_BACKEND_ARTIFACT_PATH}"
}

cfctl_handle_hostname() {
  local hostname_action="${1:-verify}"
  local output
  local status
  local artifact_path
  local result_json
  local performed="true"
  local error_code=""
  local error_message=""

  case "${hostname_action}" in
    verify|diff|plan|apply) ;;
    *)
      cfctl_emit_failure "hostname" "hostname" "hostname_lifecycle" '{"state":"not_applicable","basis":"hostname_lifecycle","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_operation" "Unsupported hostname action: ${hostname_action}" "${hostname_action}"
      exit 1
      ;;
  esac

  set +e
  output="$(
    env \
      HOSTNAME_ACTION="${hostname_action}" \
      SPEC_FILE="${CFCTL_FILE}" \
      python3 "${CF_REPO_ROOT}/scripts/cf_hostname_lifecycle.py" 2>&1
  )"
  status="$?"
  set -e

  artifact_path="$(printf '%s\n' "${output}" | tail -n 1)"
  if [[ "${status}" -ne 0 || ! -f "${artifact_path}" ]]; then
    performed="false"
    error_code="execution_failed"
    error_message="${output}"
    result_json="null"
  else
    result_json="$(cat "${artifact_path}")"
  fi

  cfctl_emit_result \
    "$([[ "${performed}" == "true" ]] && echo true || echo false)" \
    "hostname" \
    "hostname" \
    "hostname_lifecycle" \
    "${performed}" \
    '{"state":"not_applicable","basis":"hostname_lifecycle","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
    "$([[ "${performed}" == "true" ]] && jq '{state: (if .ready then "verified" else "drift" end)}' <<< "${result_json}" || echo '{"state":"not_applicable"}')" \
    "$([[ "${performed}" == "true" ]] && jq '{spec_path, ready, operation_count: .plan.operation_count, mutation_enabled: .plan.mutation_enabled}' <<< "${result_json}" || jq -n --arg message "${error_message}" '{message: $message}')" \
    "${result_json}" \
    "$([[ "${performed}" == "true" ]] && printf '%s' "${artifact_path}" || printf '')" \
    "${error_code}" \
    "${error_message}" \
    "${hostname_action}"
}

cfctl_required_confirmation() {
  local surface="$1"
  local operation="$2"
  jq -r --arg surface "${surface}" --arg operation "${operation}" '
    .surfaces[$surface].actions.apply.operations[$operation].confirm // empty
  ' "${CFCTL_REGISTRY_PATH}"
}

cfctl_require_preview_ack_or_exit() {
  local surface="$1"
  local operation="$2"
  local request_json="${3:-}"
  local target_json="${4:-}"
  local trust_json
  local plan_receipt_path
  local lock_strategy
  local lock_key
  local lock_summary_json
  local lock_ttl_seconds

  if [[ -z "${request_json}" ]]; then
    request_json="$(cfctl_current_operation_request_json "${surface}" "${operation}")"
  fi

  if [[ -z "${target_json}" ]]; then
    target_json="$(cfctl_target_json)"
  fi

  CFCTL_OPERATION_ID="${CFCTL_OPERATION_ID:-$(cf_runtime_operation_id)}"
  trust_json="$(cfctl_build_trust_json "${surface}" "apply" "${operation}" "${request_json}" "${target_json}")"
  lock_strategy="$(jq -r '.lock_mode // "none"' <<< "${trust_json}")"
  lock_key="$(jq -r '.lock_key // empty' <<< "${trust_json}")"
  lock_ttl_seconds="$(jq -r '.policy.preview_ttl_seconds // 0' <<< "${trust_json}")"
  lock_summary_json="$(
    jq -n \
      --arg surface "${surface}" \
      --arg operation "${operation}" \
      --arg action "apply" \
      --arg operation_id "${CFCTL_OPERATION_ID}" \
      --argjson target "${target_json}" \
      '
        {
          action: $action,
          surface: $surface,
          operation: $operation,
          operation_id: $operation_id,
          target: $target
        }
      '
  )"

  if ! cfctl_operation_requires_preview "${surface}" "apply" "${operation}"; then
    CFCTL_TRUST_JSON="${trust_json}"
    return
  fi

  if [[ "${CFCTL_PLAN}" == "1" ]]; then
    if [[ "${lock_strategy}" == "lease" && -n "${lock_key}" ]]; then
      if ! cf_runtime_lock_acquire "${lock_key}" "${CFCTL_OPERATION_ID}" "lease" "${lock_ttl_seconds}" "${lock_summary_json}"; then
        cfctl_emit_failure "apply" "${surface}" "registry" '{"state":"unknown","basis":"lock_unavailable","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "lock_unavailable" "Another operation already holds the preview lease for ${surface} ${operation}" "${operation}"
        exit 1
      fi
    fi
    CFCTL_TRUST_JSON="${trust_json}"
    return
  fi

  if [[ -z "${CFCTL_ACK_PLAN}" ]]; then
    cfctl_emit_failure "apply" "${surface}" "registry" '{"state":"unknown","basis":"preview_required","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "preview_required" "Operation ${operation} on ${surface} requires a reviewed preview first. Run with --plan, then re-run with --ack-plan <operation-id>." "${operation}"
    exit 1
  fi

  if ! plan_receipt_path="$(cfctl_find_plan_receipt_path "${surface}" "${operation}" "${CFCTL_ACK_PLAN}")"; then
    cfctl_emit_failure "apply" "${surface}" "registry" '{"state":"unknown","basis":"preview_receipt_missing","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "preview_receipt_missing" "No matching preview receipt was found for ${surface} ${operation} and --ack-plan ${CFCTL_ACK_PLAN}" "${operation}"
    exit 1
  fi

  if ! cfctl_validate_plan_receipt_trust "${plan_receipt_path}" "${trust_json}"; then
    cfctl_emit_failure "apply" "${surface}" "registry" "{\"state\":\"unknown\",\"basis\":\"${CFCTL_PLAN_RECEIPT_ERROR_CODE}\",\"errors\":[],\"request\":null,\"status_code\":null,\"permission_family\":\"Cloudflare API\"}" "${CFCTL_PLAN_RECEIPT_ERROR_CODE}" "${CFCTL_PLAN_RECEIPT_ERROR_MESSAGE}" "${operation}"
    exit 1
  fi

  CFCTL_OPERATION_ID="${CFCTL_ACK_PLAN}"
  CFCTL_PLAN_RECEIPT_PATH="${plan_receipt_path}"
  CFCTL_TRUST_JSON="${CFCTL_PLAN_RECEIPT_TRUST_JSON}"

  if [[ "${lock_strategy}" == "apply" && -n "${lock_key}" ]]; then
    if ! cf_runtime_lock_acquire "${lock_key}" "${CFCTL_OPERATION_ID}" "apply" "$(cf_runtime_lock_ttl_seconds)" "${lock_summary_json}"; then
      cfctl_emit_failure "apply" "${surface}" "registry" '{"state":"unknown","basis":"lock_unavailable","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "lock_unavailable" "Another operation already holds the write lock for ${surface} ${operation}" "${operation}"
      exit 1
    fi
    CFCTL_LOCK_KEY="${lock_key}"
    CFCTL_LOCK_RELEASE_ON_EXIT="1"
  elif [[ "${lock_strategy}" == "lease" && -n "${lock_key}" ]]; then
    CFCTL_LOCK_KEY="${lock_key}"
    CFCTL_LOCK_RELEASE_ON_EXIT="1"
  fi
}

cfctl_apply_script_path() {
  local surface="$1"
  jq -r --arg surface "${surface}" '.surfaces[$surface].apply_script // empty' "${CFCTL_REGISTRY_PATH}"
}

cfctl_handle_diff() {
  local surface="$1"
  local specs_json
  local diff_json

  cfctl_require_surface "${surface}"
  if ! cfctl_surface_has_desired_state "${surface}"; then
    cfctl_emit_failure "diff" "${surface}" "desired_state" '{"state":"unknown","basis":"desired_state_unsupported","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_operation" "Desired-state diff is not supported for ${surface}"
    exit 1
  fi

  cfctl_action_permission_gate "${surface}" "list"
  cfctl_collect_filtered_items_or_fail "diff" "${surface}"
  specs_json="$(cfctl_filter_specs_by_current_selectors "${surface}" "$(cfctl_load_state_specs "${surface}")")"
  diff_json="$(cfctl_diff_surface_json "${surface}" "${CFCTL_FILTERED_ITEMS_JSON}" "${specs_json}")"

  cfctl_emit_result \
    "true" \
    "diff" \
    "${surface}" \
    "desired_state" \
    "true" \
    "${CFCTL_PERMISSION_JSON}" \
    '{"state":"not_applicable"}' \
    "$(jq '.summary' <<< "${diff_json}")" \
    "${diff_json}" \
    "${CFCTL_COLLECT_BACKEND_ARTIFACT_PATH}"
}

cfctl_handle_sync_apply() {
  local surface="$1"
  local diff_json
  local specs_json
  local sync_request_json
  local actionable_json
  local operations='[]'
  local diff_row
  local failure_count=0

  if ! cfctl_surface_sync_supported "${surface}"; then
    cfctl_emit_failure "apply" "${surface}" "desired_state" '{"state":"unknown","basis":"sync_unsupported","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_operation" "Desired-state sync is not supported for ${surface}" "sync"
    exit 1
  fi

  cfctl_action_permission_gate "${surface}" "list"
  cfctl_collect_filtered_items_or_fail "apply" "${surface}" "sync"
  specs_json="$(cfctl_filter_specs_by_current_selectors "${surface}" "$(cfctl_load_state_specs "${surface}")")"
  diff_json="$(cfctl_diff_surface_json "${surface}" "${CFCTL_FILTERED_ITEMS_JSON}" "${specs_json}")"
  sync_request_json="$(cfctl_sync_request_json "${surface}" "${diff_json}")"
  cfctl_require_preview_ack_or_exit "${surface}" "sync" "${sync_request_json}" "$(cfctl_target_json)"

  if [[ "$(jq '.summary.invalid_spec_count > 0 or .summary.ambiguous_count > 0' <<< "${diff_json}")" == "true" ]]; then
    cfctl_emit_result \
      "false" \
      "apply" \
      "${surface}" \
      "desired_state" \
      "false" \
      "${CFCTL_PERMISSION_JSON}" \
      '{"state":"not_applicable"}' \
      "$(jq '.summary' <<< "${diff_json}")" \
      "${diff_json}" \
      "${CFCTL_COLLECT_BACKEND_ARTIFACT_PATH}" \
      "invalid_state" \
      "Desired-state diff contains invalid or ambiguous entries" \
      "sync"
    exit 1
  fi

  actionable_json="$(
    jq '
      [
        (.desired_specs // [])[]
        | select(.proposed_operation == "create" or .proposed_operation == "update" or .proposed_operation == "delete")
      ]
    ' <<< "${diff_json}"
  )"

  if [[ "$(jq 'map(select(.proposed_operation == "delete")) | length > 0' <<< "${actionable_json}")" == "true" && "${CFCTL_CONFIRM}" != "delete" ]]; then
    cfctl_emit_failure "apply" "${surface}" "desired_state" "${CFCTL_PERMISSION_JSON}" "invalid_arguments" "Desired-state sync for ${surface} includes deletes and requires --confirm delete" "sync"
    exit 1
  fi

  if [[ "${CFCTL_PLAN}" == "1" ]]; then
    cfctl_emit_result \
      "true" \
      "apply" \
      "${surface}" \
      "desired_state" \
      "false" \
      "${CFCTL_PERMISSION_JSON}" \
      '{"state":"planned"}' \
      "$(jq -n --argjson diff "${diff_json}" '{operation: "sync", plan_mode: true, actionable_count: (($diff.desired_specs // []) | map(select(.proposed_operation != "noop" and .proposed_operation != "review" and .proposed_operation != "invalid")) | length), diff_summary: $diff.summary}')" \
      "${diff_json}" \
      "${CFCTL_COLLECT_BACKEND_ARTIFACT_PATH}" \
      "" \
      "" \
      "sync"
    return
  fi

  while IFS= read -r diff_row; do
    cfctl_execute_sync_action "${surface}" "${diff_row}"
    if [[ "${CFCTL_BACKEND_STATUS}" -ne 0 ]]; then
      failure_count=$((failure_count + 1))
    fi
    operations="$(
      jq \
        --argjson diff "${diff_row}" \
        --argjson backend_result "${CFCTL_BACKEND_ARTIFACT_JSON}" \
        --arg backend_artifact_path "${CFCTL_BACKEND_ARTIFACT_PATH}" \
        --argjson success "$([[ "${CFCTL_BACKEND_STATUS}" -eq 0 ]] && echo true || echo false)" \
        '
          . + [{
            spec_path: $diff.spec_path,
            proposed_operation: $diff.proposed_operation,
            success: $success,
            backend_artifact_path: (if $backend_artifact_path == "" then null else $backend_artifact_path end),
            backend_result: $backend_result
          }]
        ' \
        <<< "${operations}"
    )"
  done < <(jq -c '.[]' <<< "${actionable_json}")

  local sync_result
  sync_result="$(
    jq -n \
      --argjson diff "${diff_json}" \
      --argjson operations "${operations}" \
      '
        {
          diff: $diff,
          operations: $operations
        }
      '
  )"

  if [[ "${failure_count}" -gt 0 ]]; then
    cfctl_emit_result \
      "false" \
      "apply" \
      "${surface}" \
      "desired_state" \
      "true" \
      "${CFCTL_PERMISSION_JSON}" \
      '{"state":"verification_failed"}' \
      "$(jq -n --argjson diff "${diff_json}" --argjson operations "${operations}" '{operation: "sync", applied_count: ($operations | length), failed_count: ($operations | map(select(.success != true)) | length), diff_summary: $diff.summary}')" \
      "${sync_result}" \
      "${CFCTL_PLAN_RECEIPT_PATH:-${CFCTL_COLLECT_BACKEND_ARTIFACT_PATH}}" \
      "execution_failed" \
      "One or more desired-state sync operations failed" \
      "sync"
    exit 1
  fi

  cfctl_emit_result \
    "true" \
    "apply" \
    "${surface}" \
    "desired_state" \
    "true" \
    "${CFCTL_PERMISSION_JSON}" \
    '{"state":"verified"}' \
    "$(jq -n --argjson diff "${diff_json}" --argjson operations "${operations}" '{operation: "sync", applied_count: ($operations | length), failed_count: 0, diff_summary: $diff.summary}')" \
    "${sync_result}" \
    "${CFCTL_PLAN_RECEIPT_PATH:-${CFCTL_COLLECT_BACKEND_ARTIFACT_PATH}}" \
    "" \
    "" \
    "sync"
}

cfctl_handle_apply() {
  local surface="$1"
  local operation="$2"
  local required_confirm=""
  local script_path=""
  local applied="true"
  local backend_result="null"
  local verification_json
  local summary_json
  local id_value

  cfctl_require_surface "${surface}"
  if [[ "${operation}" == "sync" ]]; then
    cfctl_handle_sync_apply "${surface}"
    return
  fi

  if ! cfctl_action_supported "${surface}" "apply" "${operation}"; then
    cfctl_emit_failure "apply" "${surface}" "registry" '{"state":"unknown","basis":"unsupported_operation","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_operation" "Unsupported apply operation ${operation} for ${surface}" "${operation}"
    exit 1
  fi

  if ! cfctl_validate_requirements "${surface}" "apply" "${operation}"; then
    cfctl_emit_failure "apply" "${surface}" "registry" '{"state":"unknown","basis":"invalid_arguments","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "invalid_arguments" "Invalid selectors for ${surface} ${operation}" "${operation}"
    exit 1
  fi

  cfctl_require_preview_ack_or_exit "${surface}" "${operation}"

  if ! cfctl_lane_allowed_for_operation "${surface}" "apply" "${operation}"; then
    cfctl_emit_failure "apply" "${surface}" "registry" '{"state":"unknown","basis":"lane_not_allowed","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "invalid_arguments" "Operation ${operation} on ${surface} is not allowed on lane ${CF_ACTIVE_TOKEN_LANE:-unknown}" "${operation}"
    exit 1
  fi

  required_confirm="$(cfctl_required_confirmation "${surface}" "${operation}")"
  if [[ -n "${required_confirm}" && "${CFCTL_CONFIRM}" != "${required_confirm}" ]]; then
    cfctl_emit_failure "apply" "${surface}" "registry" '{"state":"unknown","basis":"confirmation_required","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "invalid_arguments" "Operation ${operation} on ${surface} requires --confirm ${required_confirm}" "${operation}"
    exit 1
  fi

  cfctl_action_permission_gate "${surface}" "apply" "${operation}"

  script_path="$(cfctl_apply_script_path "${surface}")"
  if [[ -z "${script_path}" ]]; then
    cfctl_emit_failure "apply" "${surface}" "registry" "${CFCTL_PERMISSION_JSON}" "unsupported_operation" "No apply backend registered for ${surface}" "${operation}"
    exit 1
  fi

  script_path="${CF_REPO_ROOT}/${script_path}"
  cfctl_resolve_zone_context
  id_value="${CFCTL_ID}"
  if [[ -z "${id_value}" ]]; then
    if [[ -n "${CFCTL_SITEKEY}" ]]; then
      id_value="${CFCTL_SITEKEY}"
    elif [[ -n "${CFCTL_JOB_ID}" ]]; then
      id_value="${CFCTL_JOB_ID}"
    elif [[ -n "${CFCTL_POLICY_ID}" ]]; then
      id_value="${CFCTL_POLICY_ID}"
    elif [[ -n "${CFCTL_TUNNEL_ID}" ]]; then
      id_value="${CFCTL_TUNNEL_ID}"
    fi
  fi

  if [[ "${CFCTL_PLAN}" == "1" ]]; then
    applied="false"
  fi

  case "${surface}" in
    access.app)
      cfctl_run_backend_script "${script_path}" \
        "APPLY=$([[ "${CFCTL_PLAN}" == "1" ]] && echo 0 || echo 1)" \
        "OPERATION=${operation}" \
        "APP_ID=${id_value}" \
        "BODY_JSON=${CFCTL_BODY_JSON}" \
        "BODY_FILE=${CFCTL_BODY_FILE}"
      ;;
    access.policy)
      cfctl_run_backend_script "${script_path}" \
        "APPLY=$([[ "${CFCTL_PLAN}" == "1" ]] && echo 0 || echo 1)" \
        "OPERATION=${operation}" \
        "APP_ID=${CFCTL_APP_ID}" \
        "POLICY_ID=${CFCTL_POLICY_ID:-${id_value}}" \
        "BODY_JSON=${CFCTL_BODY_JSON}" \
        "BODY_FILE=${CFCTL_BODY_FILE}"
      ;;
    dns.record)
      cfctl_run_backend_script "${script_path}" \
        "APPLY=$([[ "${CFCTL_PLAN}" == "1" ]] && echo 0 || echo 1)" \
        "OPERATION=${operation}" \
        "ZONE_NAME=${CFCTL_ZONE_NAME}" \
        "ZONE_ID=${CFCTL_ZONE_ID}" \
        "RECORD_ID=${id_value}" \
        "RECORD_NAME=${CFCTL_NAME}" \
        "RECORD_TYPE=${CFCTL_TYPE}" \
        "RECORD_CONTENT=${CFCTL_CONTENT}" \
        "TTL=${CFCTL_TTL}" \
        "PROXIED=${CFCTL_PROXIED}" \
        "PRIORITY=${CFCTL_PRIORITY}" \
        "COMMENT=${CFCTL_COMMENT}" \
        "TAGS_JSON=${CFCTL_TAGS_JSON}" \
        "DATA_JSON=${CFCTL_DATA_JSON}" \
        "BODY_JSON=${CFCTL_BODY_JSON}" \
        "BODY_FILE=${CFCTL_BODY_FILE}"
      ;;
    turnstile.widget)
      cfctl_run_backend_script "${script_path}" \
        "APPLY=$([[ "${CFCTL_PLAN}" == "1" ]] && echo 0 || echo 1)" \
        "OPERATION=${operation}" \
        "SITEKEY=${CFCTL_SITEKEY:-${id_value}}" \
        "BODY_JSON=${CFCTL_BODY_JSON}" \
        "BODY_FILE=${CFCTL_BODY_FILE}"
      ;;
    waiting_room)
      cfctl_run_backend_script "${script_path}" \
        "APPLY=$([[ "${CFCTL_PLAN}" == "1" ]] && echo 0 || echo 1)" \
        "OPERATION=${operation}" \
        "ZONE_NAME=${CFCTL_ZONE_NAME}" \
        "ZONE_ID=${CFCTL_ZONE_ID}" \
        "WAITING_ROOM_ID=${id_value}" \
        "BODY_JSON=${CFCTL_BODY_JSON}" \
        "BODY_FILE=${CFCTL_BODY_FILE}"
      ;;
    edge.certificate)
      cfctl_run_backend_script "${script_path}" \
        "APPLY=$([[ "${CFCTL_PLAN}" == "1" ]] && echo 0 || echo 1)" \
        "OPERATION=${operation}" \
        "ZONE_NAME=${CFCTL_ZONE_NAME}" \
        "ZONE_ID=${CFCTL_ZONE_ID}" \
        "HOSTS_JSON=${CFCTL_HOSTS_JSON}" \
        "CERTIFICATE_AUTHORITY=${CFCTL_CERTIFICATE_AUTHORITY}" \
        "VALIDATION_METHOD=${CFCTL_VALIDATION_METHOD}" \
        "VALIDITY_DAYS=${CFCTL_VALIDITY_DAYS}" \
        "CLOUDFLARE_BRANDING=${CFCTL_CLOUDFLARE_BRANDING}" \
        "BODY_JSON=${CFCTL_BODY_JSON}" \
        "BODY_FILE=${CFCTL_BODY_FILE}"
      ;;
    logpush.job)
      cfctl_run_backend_script "${script_path}" \
        "APPLY=$([[ "${CFCTL_PLAN}" == "1" ]] && echo 0 || echo 1)" \
        "OPERATION=${operation}" \
        "SCOPE_KIND=${CFCTL_SCOPE}" \
        "ZONE_NAME=${CFCTL_ZONE_NAME}" \
        "ZONE_ID=${CFCTL_ZONE_ID}" \
        "JOB_ID=${CFCTL_JOB_ID:-${id_value}}" \
        "BODY_JSON=${CFCTL_BODY_JSON}" \
        "BODY_FILE=${CFCTL_BODY_FILE}"
      ;;
    tunnel)
      cfctl_run_backend_script "${script_path}" \
        "APPLY=$([[ "${CFCTL_PLAN}" == "1" ]] && echo 0 || echo 1)" \
        "OPERATION=${operation}" \
        "TUNNEL_ID=${CFCTL_TUNNEL_ID:-${id_value}}" \
        "CLIENT_ID=${CFCTL_CLIENT_ID}" \
        "BODY_JSON=${CFCTL_BODY_JSON}" \
        "BODY_FILE=${CFCTL_BODY_FILE}"
      ;;
    *)
      cfctl_emit_failure "apply" "${surface}" "registry" "${CFCTL_PERMISSION_JSON}" "unsupported_operation" "No apply dispatcher registered for ${surface}" "${operation}"
      exit 1
      ;;
  esac

  backend_result="${CFCTL_BACKEND_ARTIFACT_JSON}"
  if [[ "$(jq -r '.verification.response == null' <<< "${backend_result}")" == "true" ]]; then
    verification_json='{"state":"not_applicable"}'
  else
    verification_json="$(
      jq '
        {
          state: (if (.verification.response.success // false) then "verified" else "verification_failed" end),
          response: (.verification.response // null)
        }
      ' <<< "${backend_result}"
    )"
  fi

  summary_json="$(
    jq -n \
      --arg operation "${operation}" \
      --argjson plan_mode "$([[ "${CFCTL_PLAN}" == "1" ]] && echo true || echo false)" \
      --argjson backend "${backend_result}" \
      '
        {
          operation: $operation,
          plan_mode: $plan_mode,
          preview_ack: (if $plan_mode == true then null else true end),
          mutation_success: ($backend.mutation_response.success // null),
          verification_success: ($backend.verification.response.success // null),
          request: ($backend.request // null)
        }
      '
  )"

  if [[ "${CFCTL_BACKEND_STATUS}" -ne 0 ]]; then
    cfctl_emit_result \
      "false" \
      "apply" \
      "${surface}" \
      "mutation_script" \
      "${applied}" \
      "${CFCTL_PERMISSION_JSON}" \
      "${verification_json}" \
      "${summary_json}" \
      "${backend_result}" \
      "${CFCTL_PLAN_RECEIPT_PATH:-${CFCTL_BACKEND_ARTIFACT_PATH}}" \
      "execution_failed" \
      "Mutation backend returned a failure" \
      "${operation}"
    exit 1
  fi

  cfctl_emit_result \
    "true" \
    "apply" \
    "${surface}" \
    "mutation_script" \
    "${applied}" \
    "${CFCTL_PERMISSION_JSON}" \
    "${verification_json}" \
    "${summary_json}" \
    "${backend_result}" \
    "${CFCTL_PLAN_RECEIPT_PATH:-${CFCTL_BACKEND_ARTIFACT_PATH}}" \
    "" \
    "" \
    "${operation}"
}

cfctl_handle_lanes() {
  local result_json
  result_json="$(cfctl_collect_lane_health_json)"

  cfctl_emit_result \
    "true" \
    "lanes" \
    "runtime" \
    "runtime" \
    "true" \
    '{"state":"not_applicable","basis":"lane_health","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
    '{"state":"not_applicable"}' \
    "$(jq '.summary' <<< "${result_json}")" \
    "${result_json}" \
    ""
}

cfctl_handle_tool_wrapper() {
  local tool="$1"
  shift
  local tool_meta_json
  local backend
  local classification_json
  local request_json
  local trust_json
  local permission_json
  local verification_json='{"state":"not_applicable"}'
  local operation
  local mode
  local requires_ack="false"
  local summary_json
  local result_json
  local base_command
  local preview_command
  local execute_command
  local args_shell
  local receipt_path=""
  local guidance_json
  local -a effective_args=()

  if ! cfctl_has_tool_wrapper "${tool}"; then
    cfctl_emit_failure "${tool}" "${tool}" "runtime" '{"state":"unknown","basis":"unknown_tool_wrapper","errors":[],"request":null,"status_code":null,"permission_family":"Wrapped CLI"}' "unsupported_command" "Unknown wrapped tool: ${tool}"
    exit 1
  fi

  cfctl_parse_wrapper_flags "$@"

  tool_meta_json="$(cfctl_tool_wrapper_meta_json "${tool}")"
  backend="$(jq -r '.backend // "runtime"' <<< "${tool_meta_json}")"
  if [[ "${#CFCTL_PASSTHROUGH_ARGS[@]}" -gt 0 ]]; then
    classification_json="$(cfctl_tool_wrapper_classification_json "${tool}" "${CFCTL_PASSTHROUGH_ARGS[@]}")"
  else
    classification_json="$(cfctl_tool_wrapper_classification_json "${tool}")"
  fi
  request_json="$(cfctl_tool_wrapper_request_json "${tool}" "${classification_json}")"
  trust_json="$(cfctl_tool_wrapper_trust_json "${tool}" "${request_json}")"
  permission_json="$(cfctl_tool_wrapper_permission_json "${tool}")"
  operation="$(jq -r '.operation // "run"' <<< "${classification_json}")"
  mode="$(jq -r '.mode // "preview_required"' <<< "${classification_json}")"

  while IFS= read -r arg; do
    effective_args+=("${arg}")
  done < <(jq -r '.effective_args[]?' <<< "${classification_json}")

  args_shell="$(cfctl_shell_join_args "${effective_args[@]}")"
  base_command="cfctl ${tool}"
  if [[ -n "${args_shell}" ]]; then
    base_command="${base_command} ${args_shell}"
  fi
  preview_command="${base_command} --plan"
  execute_command="${base_command}"

  CFCTL_OPERATION_ID="${CFCTL_OPERATION_ID:-$(cf_runtime_operation_id)}"
  CFCTL_TRUST_JSON="${trust_json}"

  if [[ "${mode}" != "read_only" ]]; then
    requires_ack="true"
  fi

  if [[ "${CFCTL_PLAN}" == "1" ]]; then
    result_json="$(
      jq -n \
        --arg tool "${tool}" \
        --arg preview_command "${preview_command}" \
        --arg execute_command "${execute_command}" \
        --argjson classification "${classification_json}" \
        --argjson request "${request_json}" \
        '
          {
            tool: $tool,
            classification: $classification,
            request: $request,
            preview_command: $preview_command,
            execute_command: $execute_command
          }
        '
    )"
    summary_json="$(
      jq -n \
        --arg tool "${tool}" \
        --arg mode "${mode}" \
        --argjson requires_ack "${requires_ack}" \
        '
          {
            tool: $tool,
            mode: $mode,
            plan_mode: true,
            requires_ack: $requires_ack
          }
        '
    )"
    cfctl_emit_result \
      "true" \
      "${tool}" \
      "${tool}" \
      "${backend}" \
      "false" \
      "${permission_json}" \
      "${verification_json}" \
      "${summary_json}" \
      "${result_json}" \
      "" \
      "" \
      "" \
      "${operation}"
    return
  fi

  if [[ -n "${CFCTL_ACK_PLAN}" ]]; then
    receipt_path="$(cfctl_find_tool_wrapper_receipt_path "${tool}" "${CFCTL_ACK_PLAN}" || true)"
    if [[ -z "${receipt_path}" ]]; then
      guidance_json="$(
        jq -n \
          --arg next_step "Create a fresh preview receipt for this wrapped command." \
          --arg recommended_command "${preview_command}" \
          '{next_step: $next_step, recommended_command: $recommended_command, recommended_lane: null}'
      )"
      cfctl_emit_result \
        "false" \
        "${tool}" \
        "${tool}" \
        "${backend}" \
        "false" \
        "${permission_json}" \
        "${verification_json}" \
        "$(jq -n --arg tool "${tool}" --arg mode "${mode}" '{tool: $tool, mode: $mode, plan_mode: false}')" \
        "$(jq -n --arg tool "${tool}" --arg preview_command "${preview_command}" '{tool: $tool, preview_command: $preview_command}')" \
        "" \
        "preview_receipt_missing" \
        "Preview receipt not found for wrapped command ${tool}" \
        "${operation}" \
        "${guidance_json}"
      exit 1
    fi

    if ! cfctl_validate_tool_wrapper_receipt "${receipt_path}" "${trust_json}"; then
      guidance_json="$(
        jq -n \
          --arg next_step "Create a fresh preview receipt, then rerun with --ack-plan <operation-id>." \
          --arg recommended_command "${preview_command}" \
          '{next_step: $next_step, recommended_command: $recommended_command, recommended_lane: null}'
      )"
      cfctl_emit_result \
        "false" \
        "${tool}" \
        "${tool}" \
        "${backend}" \
        "false" \
        "${permission_json}" \
        "${verification_json}" \
        "$(jq -n --arg tool "${tool}" --arg mode "${mode}" '{tool: $tool, mode: $mode, plan_mode: false}')" \
        "$(jq -n --arg tool "${tool}" --arg preview_command "${preview_command}" '{tool: $tool, preview_command: $preview_command}')" \
        "" \
        "${CFCTL_PLAN_RECEIPT_ERROR_CODE:-preview_receipt_missing}" \
        "${CFCTL_PLAN_RECEIPT_ERROR_MESSAGE:-Preview receipt could not be validated}" \
        "${operation}" \
        "${guidance_json}"
      exit 1
    fi
  elif [[ "${requires_ack}" == "true" ]]; then
    guidance_json="$(
      jq -n \
        --arg next_step "Review the wrapped command first, then rerun with --ack-plan <operation-id>." \
        --arg recommended_command "${preview_command}" \
        '{next_step: $next_step, recommended_command: $recommended_command, recommended_lane: null}'
    )"
    cfctl_emit_result \
      "false" \
      "${tool}" \
      "${tool}" \
      "${backend}" \
      "false" \
      "${permission_json}" \
      "${verification_json}" \
      "$(jq -n --arg tool "${tool}" --arg mode "${mode}" '{tool: $tool, mode: $mode, plan_mode: false}')" \
      "$(jq -n --arg tool "${tool}" --arg preview_command "${preview_command}" '{tool: $tool, preview_command: $preview_command}')" \
      "" \
      "preview_required" \
      "Wrapped command ${tool} requires --plan before execution" \
      "${operation}" \
      "${guidance_json}"
    exit 1
  fi

  cfctl_run_tool_wrapper "${tool}" "${classification_json}"

  if [[ "${CFCTL_WRAPPER_STATUS}" -ne 0 ]]; then
    guidance_json="$(
      jq -n \
        --arg next_step "Inspect the wrapper log for stderr and retry with a corrected command." \
        --arg recommended_command "${preview_command}" \
        '{next_step: $next_step, recommended_command: $recommended_command, recommended_lane: null}'
    )"
    summary_json="$(
      jq -n \
        --arg tool "${tool}" \
        --arg mode "${mode}" \
        --argjson exit_code "${CFCTL_WRAPPER_STATUS}" \
        '{tool: $tool, mode: $mode, plan_mode: false, exit_code: $exit_code}'
    )"
    cfctl_emit_result \
      "false" \
      "${tool}" \
      "${tool}" \
      "${backend}" \
      "true" \
      "${permission_json}" \
      "${verification_json}" \
      "${summary_json}" \
      "${CFCTL_WRAPPER_RESULT_JSON}" \
      "${CFCTL_WRAPPER_LOG_PATH}" \
      "tool_failed" \
      "Wrapped command ${tool} exited with status ${CFCTL_WRAPPER_STATUS}" \
      "${operation}" \
      "${guidance_json}"
    exit 1
  fi

  summary_json="$(
    jq -n \
      --arg tool "${tool}" \
      --arg mode "${mode}" \
      --argjson exit_code "${CFCTL_WRAPPER_STATUS}" \
      '{tool: $tool, mode: $mode, plan_mode: false, exit_code: $exit_code}'
  )"
  cfctl_emit_result \
    "true" \
    "${tool}" \
    "${tool}" \
    "${backend}" \
    "true" \
    "${permission_json}" \
    "${verification_json}" \
    "${summary_json}" \
    "${CFCTL_WRAPPER_RESULT_JSON}" \
    "${CFCTL_WRAPPER_LOG_PATH}" \
    "" \
    "" \
    "${operation}"
}

cfctl_handle_token() {
  local subcommand="${1:-}"

  case "${subcommand}" in
    permission-groups)
      shift || true
      exec env CF_RUNTIME_CALLER=cfctl "${CF_REPO_ROOT}/scripts/cf_token_permission_groups.sh" "$@"
      ;;
    mint)
      shift || true
      exec env CF_RUNTIME_CALLER=cfctl "${CF_REPO_ROOT}/scripts/cf_token_mint.sh" "$@"
      ;;
    ""|-h|--help|help)
      cat <<'EOF'
Usage:
  cfctl token permission-groups [--name <filter>] [--scope <scope>]
  cfctl token mint --name <token-name> [token options]

Examples:
  cfctl token permission-groups --name "DNS"
  cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --plan
  cfctl token mint --name dns-editor-<unique-suffix> --permission "DNS Write" --zone example.com --ttl-hours 24 --ack-plan <operation-id> --value-out /tmp/dns-editor.token
  cfctl token mint --name account-audit --permission "Account Settings Read" --ttl-hours 24 --plan
EOF
      ;;
    *)
      echo "Unknown token subcommand: ${subcommand}" >&2
      exit 1
      ;;
  esac
}

cfctl_bootstrap_permissions_catalog_json() {
  cat "${CF_REPO_ROOT}/catalog/permissions.json"
}

cfctl_bootstrap_default_profile() {
  jq -r '.default_profile // "read"' <<< "$(cfctl_bootstrap_permissions_catalog_json)"
}

cfctl_bootstrap_supported_profiles_json() {
  jq -c '.profiles | keys | sort' <<< "$(cfctl_bootstrap_permissions_catalog_json)"
}

cfctl_bootstrap_profile_exists() {
  local profile="$1"
  jq -e --arg profile "${profile}" '.profiles[$profile] != null' <<< "$(cfctl_bootstrap_permissions_catalog_json)" >/dev/null
}

cfctl_bootstrap_permissions_for_profile_json() {
  local profile="$1"
  jq -c \
    --arg profile "${profile}" \
    '
      .permissions
      | map(select((.profiles // []) | index($profile)))
      | unique_by(.scope, .name)
      | sort_by(.scope, .name)
    ' <<< "$(cfctl_bootstrap_permissions_catalog_json)"
}

cfctl_bootstrap_profile_verification_json() {
  local profile="$1"
  local zone="${2:-}"
  jq -c \
    --arg profile "${profile}" \
    --arg zone "${zone}" \
    '
      (.profiles[$profile].verification // [])
      | map(
          if $zone == "" then
            .
          else
            gsub("<zone>"; $zone)
          end
        )
    ' <<< "$(cfctl_bootstrap_permissions_catalog_json)"
}

cfctl_bootstrap_permission_requirements_json() {
  local profile="$1"
  local selected_permissions_json

  selected_permissions_json="$(cfctl_bootstrap_permissions_for_profile_json "${profile}")"
  jq -n \
    --arg profile "${profile}" \
    --argjson catalog "$(cfctl_bootstrap_permissions_catalog_json)" \
    --argjson selected_permissions "${selected_permissions_json}" \
    '
      {
        profile: $profile,
        supported_profiles: ($catalog.profiles | keys | sort),
        bootstrap_creator: $catalog.bootstrap_creator,
        operator_token: {
          purpose: "Day-to-day cfctl credential for the selected permission profile.",
          profile: $profile,
          profile_meta: $catalog.profiles[$profile],
          resource_scope: (
            if ($selected_permissions | map(select(.scope == "zone")) | length) > 0 then
              "current account plus selected zone resources"
            else
              "current account"
            end
          ),
          permissions: $selected_permissions
        }
      }
    '
}

cfctl_bootstrap_permission_validation_json() {
  local requirements_json="$1"
  local lane="${CF_TOKEN_LANE:-${CF_TOKEN_LANE_DEFAULT}}"
  local groups_capture
  local requirements_list_json

  requirements_list_json="$(
    jq '
      [
        (.bootstrap_creator.permissions[] | {name, scope, stage: "bootstrap_creator"}),
        (.operator_token.permissions[] | {name, scope, stage: "operator_token"})
      ]
      | unique_by(.name, .scope, .stage)
    ' <<< "${requirements_json}"
  )"

  if [[ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]]; then
    jq -n \
      --arg lane "${lane}" \
      --arg reason "CLOUDFLARE_ACCOUNT_ID missing" \
      --argjson requirements "${requirements_list_json}" \
      '{validated: false, lane: $lane, reason: $reason, required: $requirements, matched: [], missing: $requirements}'
    return
  fi

  if ! cf_token_available_for_lane "${lane}"; then
    jq -n \
      --arg lane "${lane}" \
      --arg reason "credential_missing" \
      --argjson requirements "${requirements_list_json}" \
      '{validated: false, lane: $lane, reason: $reason, required: $requirements, matched: [], missing: $requirements}'
    return
  fi

  cf_select_active_token
  groups_capture="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/permission_groups")"
  if [[ "$(jq -r '.success // false' <<< "${groups_capture}")" != "true" ]]; then
    jq -n \
      --arg lane "${lane}" \
      --argjson requirements "${requirements_list_json}" \
      --argjson response "${groups_capture}" \
      '{validated: false, lane: $lane, reason: "permission_group_lookup_failed", required: $requirements, matched: [], missing: $requirements, response: {status_code: $response.status_code, errors: ($response.errors // [])}}'
    return
  fi

  jq -n \
    --arg lane "${lane}" \
    --argjson requirements "${requirements_list_json}" \
    --argjson groups "${groups_capture}" \
    '
      ($groups.result // []) as $available
      | (
          $requirements
          | map(
              . as $requirement
              | (
                  if $requirement.scope == "account" then
                    "com.cloudflare.api.account"
                  elif $requirement.scope == "zone" then
                    "com.cloudflare.api.account.zone"
                  else
                    $requirement.scope
                  end
                ) as $cloudflare_scope
              | {
                  requirement: $requirement,
                  group: (
                    $available
                    | map(select(.name == $requirement.name and ((.scopes // []) | index($cloudflare_scope))))
                    | .[0] // null
                  )
                }
            )
        ) as $rows
      | {
          validated: true,
          lane: $lane,
          reason: null,
          required: $requirements,
          matched: ($rows | map(select(.group != null) | (.requirement + {id: .group.id, scopes: (.group.scopes // [])}))),
          missing: ($rows | map(select(.group == null) | .requirement))
        }
    '
}

cfctl_bootstrap_resource_flags() {
  local permissions_json="$1"
  local zone="${2:-}"
  local zone_id="${3:-}"

  if [[ "$(jq 'map(select(.scope == "zone")) | length > 0' <<< "${permissions_json}")" != "true" ]]; then
    printf ''
    return
  fi

  if [[ -n "${zone}" ]]; then
    printf ' --zone %s' "$(jq -nr --arg value "${zone}" '$value | @sh')"
    return
  fi

  if [[ -n "${zone_id}" ]]; then
    printf ' --zone-id %s' "$(jq -nr --arg value "${zone_id}" '$value | @sh')"
    return
  fi

  printf ' --all-zones-in-account'
}

cfctl_bootstrap_permission_flags() {
  local permissions_json="$1"
  local validation_json="$2"
  local use_ids="false"

  if [[ "$(jq -r '.validated == true and ((.missing // []) | length == 0)' <<< "${validation_json}")" == "true" ]]; then
    use_ids="true"
  fi

  if [[ "${use_ids}" == "true" ]]; then
    jq -r '
      [.matched[] | select(.stage == "operator_token") | .id]
      | unique
      | map("--permission-id " + (. | @sh))
      | join(" ")
    ' <<< "${validation_json}"
    return
  fi

  jq -r '
    [.[] | .name]
    | unique
    | map("--permission " + (. | @sh))
    | join(" ")
  ' <<< "${permissions_json}"
}

cfctl_bootstrap_verification_matrix_json() {
  local profile="$1"
  local zone="${2:-}"
  local verification_json

  verification_json="$(cfctl_bootstrap_profile_verification_json "${profile}" "${zone}")"
  jq -n \
    --arg profile "${profile}" \
    --arg zone "${zone}" \
    --argjson commands "${verification_json}" \
    '
      {
        profile: $profile,
        zone: (if $zone == "" then null else $zone end),
        runnable_now: ($zone != ""),
        commands: $commands,
        blocked: (
          if $zone == "" and (($commands | map(select(test("<zone>"))) | length) > 0) then
            [{
              code: "zone_required",
              message: "Pass --zone <zone> to render all profile verification commands."
            }]
          else
            []
          end
        )
      }
    '
}

cfctl_handle_bootstrap() {
  local subcommand="${1:-permissions}"
  shift || true
  local profile=""
  local zone=""
  local zone_id=""
  local requirements_json
  local validation_json
  local result_json
  local summary_json
  local token_name=""
  local ttl_hours=""
  local token_name_shell
  local permission_flags
  local resource_flags
  local plan_command
  local apply_command
  local permissions_json
  local verification_matrix_json

  case "${subcommand}" in
    permissions|verify|"")
      while [[ "$#" -gt 0 ]]; do
        case "$1" in
          --profile)
            profile="$2"
            shift 2
            ;;
          --profile=*)
            profile="${1#*=}"
            shift
            ;;
          --zone)
            zone="$2"
            shift 2
            ;;
          --zone=*)
            zone="${1#*=}"
            shift
            ;;
          --zone-id)
            zone_id="$2"
            shift 2
            ;;
          --zone-id=*)
            zone_id="${1#*=}"
            shift
            ;;
          --ttl-hours)
            ttl_hours="$2"
            shift 2
            ;;
          --ttl-hours=*)
            ttl_hours="${1#*=}"
            shift
            ;;
          --name)
            token_name="$2"
            shift 2
            ;;
          --name=*)
            token_name="${1#*=}"
            shift
            ;;
          *)
            echo "Unknown bootstrap ${subcommand} argument: $1" >&2
            exit 1
            ;;
        esac
      done

      if [[ -z "${profile}" ]]; then
        profile="${CFCTL_BOOTSTRAP_PROFILE:-$(cfctl_bootstrap_default_profile)}"
      fi

      if ! cfctl_bootstrap_profile_exists "${profile}"; then
        cfctl_emit_failure "bootstrap" "permissions" "catalog" '{"state":"unknown","basis":"unsupported_profile","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "unsupported_profile" "Unsupported bootstrap profile: ${profile}"
        exit 1
      fi

      requirements_json="$(cfctl_bootstrap_permission_requirements_json "${profile}")"
      validation_json="$(cfctl_bootstrap_permission_validation_json "${requirements_json}")"
      permissions_json="$(jq -c '.operator_token.permissions' <<< "${requirements_json}")"
      verification_matrix_json="$(cfctl_bootstrap_verification_matrix_json "${profile}" "${zone}")"
      if [[ -z "${token_name}" ]]; then
        token_name="${CFCTL_BOOTSTRAP_TOKEN_NAME:-cfctl-${profile}-operator}"
      fi
      if [[ -z "${ttl_hours}" ]]; then
        ttl_hours="${CFCTL_BOOTSTRAP_TTL_HOURS:-$(jq -r '.operator_token.profile_meta.ttl_hours // 720' <<< "${requirements_json}")}"
      fi
      token_name_shell="$(jq -nr --arg token_name "${token_name}" '$token_name | @sh')"
      permission_flags="$(cfctl_bootstrap_permission_flags "${permissions_json}" "${validation_json}")"
      resource_flags="$(cfctl_bootstrap_resource_flags "${permissions_json}" "${zone}" "${zone_id}")"
      plan_command="cfctl token mint --name ${token_name_shell} ${permission_flags}${resource_flags} --ttl-hours ${ttl_hours} --plan"
      apply_command="cfctl token mint --name ${token_name_shell} ${permission_flags}${resource_flags} --ttl-hours ${ttl_hours} --ack-plan <operation-id> --value-out <secure-path>"
      result_json="$(
        jq -n \
          --arg profile "${profile}" \
          --arg env_file "${CF_SHARED_ENV_FILE:-${CF_SHARED_ENV_FILE_DEFAULT}}" \
          --arg token_name "${token_name}" \
          --arg ttl_hours "${ttl_hours}" \
          --arg zone "${zone}" \
          --arg zone_id "${zone_id}" \
          --arg plan_command "${plan_command}" \
          --arg apply_command "${apply_command}" \
          --argjson requirements "${requirements_json}" \
          --argjson validation "${validation_json}" \
          --argjson verification_matrix "${verification_matrix_json}" \
          '
            {
              profile: $profile,
              env_file: $env_file,
              resource_target: {
                zone: (if $zone == "" then null else $zone end),
                zone_id: (if $zone_id == "" then null else $zone_id end)
              },
              stages: {
                bootstrap_creator: $requirements.bootstrap_creator,
                operator_token: ($requirements.operator_token + {
                  name: $token_name,
                  ttl_hours: ($ttl_hours | tonumber? // $ttl_hours)
                })
              },
              commands: {
                mint_operator_token_plan: $plan_command,
                mint_operator_token_apply: $apply_command
              },
              validation: $validation,
              verification: $verification_matrix,
              install_steps: [
                "Create or authorize a temporary bootstrap credential with the bootstrap_creator permissions.",
                "Set CF_DEV_TOKEN and CLOUDFLARE_ACCOUNT_ID in the cfctl env file.",
                "Run the mint_operator_token_plan command and review the artifact.",
                "Run the mint_operator_token_apply command with --ack-plan and --value-out.",
                "Replace CF_DEV_TOKEN with the minted operator token, then revoke the temporary bootstrap credential."
              ],
              notes: [
                "This report is generated from catalog/permissions.json and the current cfctl public surface contract.",
                "The operator token intentionally excludes Account API Tokens Write; keep token-minting power in a short-lived bootstrap credential.",
                "When live permission-group lookup succeeds, generated commands prefer --permission-id over permission names."
              ]
            }
          '
      )"
      summary_json="$(
        jq '
          {
            bootstrap_creator_permission_count: (.stages.bootstrap_creator.permissions | length),
            operator_permission_count: (.stages.operator_token.permissions | length),
            profile: .profile,
            validation: {
              validated: .validation.validated,
              missing_count: (.validation.missing | length),
              reason: .validation.reason
            },
            plan_command: .commands.mint_operator_token_plan
          }
        ' <<< "${result_json}"
      )"
      cfctl_emit_result \
        "true" \
        "bootstrap" \
        "${subcommand:-permissions}" \
        "catalog" \
        "true" \
        '{"state":"not_applicable","basis":"bootstrap_permissions","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
        '{"state":"not_applicable"}' \
        "${summary_json}" \
        "${result_json}" \
        ""
      ;;
    -h|--help|help)
      cat <<'EOF'
Usage:
  cfctl bootstrap permissions [--profile read|dns|hostname|deploy|security-audit|full-operator] [--zone <zone>] [--ttl-hours <n>]
  cfctl bootstrap verify [--profile read|dns|hostname|deploy|security-audit|full-operator] [--zone <zone>]

Print the temporary bootstrap credential requirements and the exact token-mint
plan/apply commands for the narrower day-to-day CF_DEV_TOKEN. The default
profile is read.
EOF
      ;;
    *)
      echo "Unknown bootstrap subcommand: ${subcommand}" >&2
      exit 1
      ;;
  esac
}

cfctl_handle_audit() {
  local subcommand="${1:-trust}"

  case "${subcommand}" in
    trust)
      cfctl_handle_doctor
      ;;
    ""|-h|--help|help)
      cat <<'EOF'
Usage:
  cfctl audit trust

Notes:
  cfctl audit trust is an alias for cfctl doctor.
EOF
      ;;
    *)
      echo "Unknown audit subcommand: ${subcommand}" >&2
      exit 1
      ;;
  esac
}

cfctl_handle_admin() {
  local subcommand="${1:-}"

  case "${subcommand}" in
    authorize-backend)
      shift || true
      local ttl_minutes="10"
      local reason=""
      local backend=""
      local backend_path
      local backend_rel
      local authorization_path
      local backends='[]'

      while [[ "$#" -gt 0 ]]; do
        case "$1" in
          --backend)
            backend="$2"
            shift 2
            ;;
          --backend=*)
            backend="${1#*=}"
            shift
            ;;
          --reason)
            reason="$2"
            shift 2
            ;;
          --reason=*)
            reason="${1#*=}"
            shift
            ;;
          --ttl-minutes)
            ttl_minutes="$2"
            shift 2
            ;;
          --ttl-minutes=*)
            ttl_minutes="${1#*=}"
            shift
            ;;
          *)
            echo "Unknown admin authorize-backend argument: $1" >&2
            exit 1
            ;;
        esac

        if [[ -n "${backend:-}" ]]; then
          if [[ "${backend}" == /* ]]; then
            backend_path="${backend}"
          else
            backend_path="${CF_REPO_ROOT}/${backend}"
          fi
          if [[ ! -f "${backend_path}" ]]; then
            echo "Backend path not found: ${backend}" >&2
            exit 1
          fi
          backend_rel="$(cf_repo_relative_path "${backend_path}")"
          backends="$(jq --arg backend "${backend_rel}" '. + [$backend]' <<< "${backends}")"
          backend=""
        fi
      done

      if [[ "$(jq 'length == 0' <<< "${backends}")" == "true" ]]; then
        echo "At least one --backend is required" >&2
        exit 1
      fi

      if [[ -z "${reason}" ]]; then
        echo "--reason is required" >&2
        exit 1
      fi

      authorization_path="$(cf_backend_authorization_issue "${backends}" "${reason}" "${ttl_minutes}")"
      cfctl_emit_result \
        "true" \
        "admin" \
        "runtime" \
        "runtime" \
        "true" \
        '{"state":"not_applicable","basis":"admin_authorization","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
        '{"state":"not_applicable"}' \
        "$(jq -n --arg path "${authorization_path}" --arg env_name "$(cf_runtime_backend_bypass_env_name)" --argjson backends "${backends}" '{authorization_path: $path, env_name: $env_name, backend_count: ($backends | length)}')" \
        "$(
          jq -n \
            --arg authorization_path "${authorization_path}" \
            --arg env_name "$(cf_runtime_backend_bypass_env_name)" \
            --arg reason "${reason}" \
            --arg ttl_minutes "${ttl_minutes}" \
            --argjson backends "${backends}" \
            '
              {
                authorization_path: $authorization_path,
                env_name: $env_name,
                export_command: ("export " + $env_name + "=" + ($authorization_path | @sh)),
                reason: $reason,
                ttl_minutes: ($ttl_minutes | tonumber),
                allowed_backends: $backends
              }
            '
        )" \
        ""
      ;;
    authorizations)
      local authorization_health_json
      authorization_health_json="$(cf_backend_authorization_health_json)"
      cfctl_emit_result \
        "true" \
        "admin" \
        "runtime" \
        "runtime" \
        "true" \
        '{"state":"not_applicable","basis":"admin_authorization_inventory","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
        '{"state":"not_applicable"}' \
        "$(jq '{authorization_count: .authorization_count, expired_count: .expired_count}' <<< "${authorization_health_json}")" \
        "${authorization_health_json}" \
        ""
      ;;
    revoke-backend)
      shift || true
      local authorization_path=""
      local resolved_path

      while [[ "$#" -gt 0 ]]; do
        case "$1" in
          --path)
            authorization_path="$2"
            shift 2
            ;;
          --path=*)
            authorization_path="${1#*=}"
            shift
            ;;
          *)
            echo "Unknown admin revoke-backend argument: $1" >&2
            exit 1
            ;;
        esac
      done

      if [[ -z "${authorization_path}" ]]; then
        echo "--path is required" >&2
        exit 1
      fi

      resolved_path="$(cf_realpath_best_effort "${authorization_path}" 2>/dev/null || true)"
      if [[ -z "${resolved_path}" ]] || ! cf_backend_authorization_revoke "${authorization_path}"; then
        cfctl_emit_failure "admin" "runtime" "runtime" '{"state":"not_applicable","basis":"admin_authorization_revoke","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' "target_not_found" "Authorization path could not be revoked: ${authorization_path}"
        exit 1
      fi

      cfctl_emit_result \
        "true" \
        "admin" \
        "runtime" \
        "runtime" \
        "true" \
        '{"state":"not_applicable","basis":"admin_authorization_revoke","errors":[],"request":null,"status_code":null,"permission_family":"Cloudflare API"}' \
        '{"state":"not_applicable"}' \
        "$(jq -n --arg path "${resolved_path}" '{revoked: true, authorization_path: $path}')" \
        "$(jq -n --arg path "${resolved_path}" '{revoked: true, authorization_path: $path}')" \
        ""
      ;;
    ""|-h|--help|help)
      cat <<'EOF'
Usage:
  cfctl admin authorize-backend --backend <path> --reason <why> [--ttl-minutes <n>]
  cfctl admin authorizations
  cfctl admin revoke-backend --path <authorization-path>

Example:
  cfctl admin authorize-backend --backend scripts/cf_api_apply.sh --reason "maintainer debug"
EOF
      ;;
    *)
      echo "Unknown admin subcommand: ${subcommand}" >&2
      exit 1
      ;;
  esac
}

cfctl_main() {
  cfctl_reset_flags
  local action="${1:-help}"

  if [[ "$#" -gt 0 ]]; then
    shift
  fi

  case "${action}" in
    help|-h|--help)
      cfctl_usage
      ;;
    doctor)
      cfctl_parse_flags "$@"
      cfctl_handle_doctor
      ;;
    audit)
      cfctl_handle_audit "$@"
      ;;
    admin)
      cfctl_handle_admin "$@"
      ;;
    bootstrap)
      cfctl_handle_bootstrap "$@"
      ;;
    surfaces)
      cfctl_parse_flags "$@"
      cfctl_handle_list_surfaces
      ;;
    docs)
      local docs_topic="${1:-}"
      if [[ "$#" -gt 0 ]]; then
        shift
      fi
      cfctl_parse_flags "$@"
      cfctl_handle_docs "${docs_topic}"
      ;;
    standards)
      local standards_arg="${1:-}"
      local standards_root=""
      if [[ "$#" -gt 0 ]]; then
        shift
      fi
      if [[ "${standards_arg}" == "audit" ]]; then
        standards_root="${1:-}"
        if [[ "$#" -gt 0 ]]; then
          shift
        fi
        cfctl_parse_flags "$@"
        cfctl_handle_standards_audit "${standards_root}"
      else
        cfctl_parse_flags "$@"
        cfctl_handle_standards "${standards_arg}"
      fi
      ;;
    previews)
      cfctl_parse_flags
      cfctl_handle_previews "${1:-list}"
      ;;
    locks)
      cfctl_parse_flags
      cfctl_handle_locks_view "${1:-list}"
      ;;
    wrangler|cloudflared)
      cfctl_handle_tool_wrapper "${action}" "$@"
      ;;
    hostname)
      local hostname_action="${1:-verify}"
      if [[ "$#" -gt 0 ]]; then
        shift
      fi
      cfctl_parse_flags "$@"
      cfctl_handle_hostname "${hostname_action}"
      ;;
    token)
      cfctl_handle_token "$@"
      ;;
    lanes)
      cfctl_parse_flags "$@"
      cfctl_handle_lanes
      ;;
    classify)
      if [[ "$#" -lt 2 ]]; then
        cfctl_usage
        exit 1
      fi
      local surface="$1"
      local operation="$2"
      shift 2
      cfctl_parse_flags "$@"
      cfctl_handle_classify "${surface}" "${operation}"
      ;;
    guide)
      if [[ "$#" -lt 2 ]]; then
        cfctl_usage
        exit 1
      fi
      local surface="$1"
      local operation="$2"
      shift 2
      cfctl_parse_flags "$@"
      cfctl_handle_guide "${surface}" "${operation}"
      ;;
    explain)
      local surface="${1:-}"
      if [[ "$#" -gt 0 ]]; then
        shift
      fi
      cfctl_parse_flags "$@"
      cfctl_handle_explain "${surface}"
      ;;
    can)
      if [[ "$#" -lt 2 ]]; then
        cfctl_usage
        exit 1
      fi
      local surface="$1"
      local operation="$2"
      shift 2
      cfctl_parse_flags "$@"
      cfctl_handle_can "${surface}" "${operation}"
      ;;
    list)
      if [[ "$#" -lt 1 ]]; then
        cfctl_usage
        exit 1
      fi
      local surface="$1"
      shift
      cfctl_parse_flags "$@"
      cfctl_handle_list_like "list" "${surface}"
      ;;
    snapshot)
      if [[ "$#" -lt 1 ]]; then
        cfctl_usage
        exit 1
      fi
      local surface="$1"
      shift
      cfctl_parse_flags "$@"
      cfctl_handle_list_like "snapshot" "${surface}"
      ;;
    get)
      if [[ "$#" -lt 1 ]]; then
        cfctl_usage
        exit 1
      fi
      local surface="$1"
      shift
      cfctl_parse_flags "$@"
      cfctl_handle_get_like "get" "${surface}"
      ;;
    verify)
      if [[ "$#" -lt 1 ]]; then
        cfctl_usage
        exit 1
      fi
      local surface="$1"
      shift
      cfctl_parse_flags "$@"
      cfctl_handle_get_like "verify" "${surface}"
      ;;
    diff)
      if [[ "$#" -lt 1 ]]; then
        cfctl_usage
        exit 1
      fi
      local surface="$1"
      shift
      cfctl_parse_flags "$@"
      cfctl_handle_diff "${surface}"
      ;;
    apply)
      if [[ "$#" -lt 2 ]]; then
        cfctl_usage
        exit 1
      fi
      local surface="$1"
      local operation="$2"
      shift 2
      cfctl_parse_flags "$@"
      cfctl_handle_apply "${surface}" "${operation}"
      ;;
    *)
      cfctl_usage
      exit 1
      ;;
  esac
}
