#!/usr/bin/env bash

CFCTL_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFCTL_REGISTRY_PATH="${CFCTL_REGISTRY_PATH:-${CF_REPO_ROOT}/catalog/surfaces.json}"
CFCTL_STANDARDS_PATH="${CFCTL_STANDARDS_PATH:-${CF_REPO_ROOT}/catalog/standards.json}"
CFCTL_DOC_BANK_PATH="${CFCTL_DOC_BANK_PATH:-${CF_REPO_ROOT}/catalog/cloudflare-doc-bank.json}"
CFCTL_STANDARDS_AUDIT_SCRIPT="${CFCTL_STANDARDS_AUDIT_SCRIPT:-${CF_REPO_ROOT}/scripts/cf_standards_audit.py}"

cfctl_reset_flags() {
  CFCTL_ID=""
  CFCTL_NAME=""
  CFCTL_DOMAIN=""
  CFCTL_FILE=""
  CFCTL_PATTERN=""
  CFCTL_SERVICE=""
  CFCTL_ZONE_NAME=""
  CFCTL_ZONE_ID=""
  CFCTL_TYPE=""
  CFCTL_SITEKEY=""
  CFCTL_APP_ID=""
  CFCTL_POLICY_ID=""
  CFCTL_JOB_ID=""
  CFCTL_SCOPE="account"
  CFCTL_BODY_JSON=""
  CFCTL_BODY_FILE=""
  CFCTL_HOSTS_JSON="[]"
  CFCTL_CERTIFICATE_AUTHORITY=""
  CFCTL_VALIDATION_METHOD=""
  CFCTL_VALIDITY_DAYS=""
  CFCTL_CLOUDFLARE_BRANDING=""
  CFCTL_CONFIRM=""
  CFCTL_ACK_PLAN=""
  CFCTL_PLAN="0"
  CFCTL_CONTENT=""
  CFCTL_TTL=""
  CFCTL_PROXIED=""
  CFCTL_PRIORITY=""
  CFCTL_COMMENT=""
  CFCTL_TAGS_JSON=""
  CFCTL_DATA_JSON=""
  CFCTL_TUNNEL_ID=""
  CFCTL_CLIENT_ID=""
  CFCTL_SINCE=""
  CFCTL_BEFORE=""
  CFCTL_ACTOR=""
  CFCTL_ACTION_TYPE=""
  CFCTL_RESOURCE_TYPE=""
  CFCTL_LIMIT=""
  CFCTL_INCLUDE_RECORDS="1"
  CFCTL_INCLUDE_CONFIG="0"
  CFCTL_ALL_LANES="0"
  CFCTL_STATE_DIR=""
  CFCTL_STRICT="0"
  CFCTL_REPAIR_HINTS="0"
  CFCTL_UNKNOWN_ARGS=""
  CFCTL_PASSTHROUGH_ARGS=()
  CFCTL_OPERATION_ID=""
  CFCTL_PLAN_RECEIPT_PATH=""
  CFCTL_TRUST_JSON="null"
  CFCTL_LOCK_KEY=""
  CFCTL_LOCK_RELEASE_ON_EXIT="0"
  CFCTL_PLAN_RECEIPT_TRUST_JSON="null"
}

cfctl_parse_flags() {
  cfctl_reset_flags

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --id) CFCTL_ID="$2"; shift 2 ;;
      --id=*) CFCTL_ID="${1#*=}"; shift ;;
      --name) CFCTL_NAME="$2"; shift 2 ;;
      --name=*) CFCTL_NAME="${1#*=}"; shift ;;
      --domain) CFCTL_DOMAIN="$2"; shift 2 ;;
      --domain=*) CFCTL_DOMAIN="${1#*=}"; shift ;;
      --file) CFCTL_FILE="$2"; shift 2 ;;
      --file=*) CFCTL_FILE="${1#*=}"; shift ;;
      --pattern) CFCTL_PATTERN="$2"; shift 2 ;;
      --pattern=*) CFCTL_PATTERN="${1#*=}"; shift ;;
      --service) CFCTL_SERVICE="$2"; shift 2 ;;
      --service=*) CFCTL_SERVICE="${1#*=}"; shift ;;
      --zone) CFCTL_ZONE_NAME="$2"; shift 2 ;;
      --zone=*) CFCTL_ZONE_NAME="${1#*=}"; shift ;;
      --zone-id) CFCTL_ZONE_ID="$2"; shift 2 ;;
      --zone-id=*) CFCTL_ZONE_ID="${1#*=}"; shift ;;
      --type) CFCTL_TYPE="$2"; shift 2 ;;
      --type=*) CFCTL_TYPE="${1#*=}"; shift ;;
      --sitekey) CFCTL_SITEKEY="$2"; shift 2 ;;
      --sitekey=*) CFCTL_SITEKEY="${1#*=}"; shift ;;
      --app-id) CFCTL_APP_ID="$2"; shift 2 ;;
      --app-id=*) CFCTL_APP_ID="${1#*=}"; shift ;;
      --policy-id) CFCTL_POLICY_ID="$2"; shift 2 ;;
      --policy-id=*) CFCTL_POLICY_ID="${1#*=}"; shift ;;
      --job-id) CFCTL_JOB_ID="$2"; shift 2 ;;
      --job-id=*) CFCTL_JOB_ID="${1#*=}"; shift ;;
      --scope) CFCTL_SCOPE="$2"; shift 2 ;;
      --scope=*) CFCTL_SCOPE="${1#*=}"; shift ;;
      --body) CFCTL_BODY_JSON="$2"; shift 2 ;;
      --body=*) CFCTL_BODY_JSON="${1#*=}"; shift ;;
      --body-file) CFCTL_BODY_FILE="$2"; shift 2 ;;
      --body-file=*) CFCTL_BODY_FILE="${1#*=}"; shift ;;
      --host) CFCTL_HOSTS_JSON="$(jq -c --arg host "$2" '. + [$host]' <<< "${CFCTL_HOSTS_JSON}")"; shift 2 ;;
      --host=*) CFCTL_HOSTS_JSON="$(jq -c --arg host "${1#*=}" '. + [$host]' <<< "${CFCTL_HOSTS_JSON}")"; shift ;;
      --hosts-json) CFCTL_HOSTS_JSON="$(jq -c '.' <<< "$2")"; shift 2 ;;
      --hosts-json=*) CFCTL_HOSTS_JSON="$(jq -c '.' <<< "${1#*=}")"; shift ;;
      --certificate-authority) CFCTL_CERTIFICATE_AUTHORITY="$2"; shift 2 ;;
      --certificate-authority=*) CFCTL_CERTIFICATE_AUTHORITY="${1#*=}"; shift ;;
      --validation-method) CFCTL_VALIDATION_METHOD="$2"; shift 2 ;;
      --validation-method=*) CFCTL_VALIDATION_METHOD="${1#*=}"; shift ;;
      --validity-days) CFCTL_VALIDITY_DAYS="$2"; shift 2 ;;
      --validity-days=*) CFCTL_VALIDITY_DAYS="${1#*=}"; shift ;;
      --cloudflare-branding) CFCTL_CLOUDFLARE_BRANDING="$2"; shift 2 ;;
      --cloudflare-branding=*) CFCTL_CLOUDFLARE_BRANDING="${1#*=}"; shift ;;
      --confirm) CFCTL_CONFIRM="$2"; shift 2 ;;
      --confirm=*) CFCTL_CONFIRM="${1#*=}"; shift ;;
      --ack-plan) CFCTL_ACK_PLAN="$2"; shift 2 ;;
      --ack-plan=*) CFCTL_ACK_PLAN="${1#*=}"; shift ;;
      --plan) CFCTL_PLAN="1"; shift ;;
      --content) CFCTL_CONTENT="$2"; shift 2 ;;
      --content=*) CFCTL_CONTENT="${1#*=}"; shift ;;
      --ttl) CFCTL_TTL="$2"; shift 2 ;;
      --ttl=*) CFCTL_TTL="${1#*=}"; shift ;;
      --proxied) CFCTL_PROXIED="$2"; shift 2 ;;
      --proxied=*) CFCTL_PROXIED="${1#*=}"; shift ;;
      --priority) CFCTL_PRIORITY="$2"; shift 2 ;;
      --priority=*) CFCTL_PRIORITY="${1#*=}"; shift ;;
      --comment) CFCTL_COMMENT="$2"; shift 2 ;;
      --comment=*) CFCTL_COMMENT="${1#*=}"; shift ;;
      --tags-json) CFCTL_TAGS_JSON="$2"; shift 2 ;;
      --tags-json=*) CFCTL_TAGS_JSON="${1#*=}"; shift ;;
      --data-json) CFCTL_DATA_JSON="$2"; shift 2 ;;
      --data-json=*) CFCTL_DATA_JSON="${1#*=}"; shift ;;
      --tunnel-id) CFCTL_TUNNEL_ID="$2"; shift 2 ;;
      --tunnel-id=*) CFCTL_TUNNEL_ID="${1#*=}"; shift ;;
      --client-id) CFCTL_CLIENT_ID="$2"; shift 2 ;;
      --client-id=*) CFCTL_CLIENT_ID="${1#*=}"; shift ;;
      --since) CFCTL_SINCE="$2"; shift 2 ;;
      --since=*) CFCTL_SINCE="${1#*=}"; shift ;;
      --before) CFCTL_BEFORE="$2"; shift 2 ;;
      --before=*) CFCTL_BEFORE="${1#*=}"; shift ;;
      --actor) CFCTL_ACTOR="$2"; shift 2 ;;
      --actor=*) CFCTL_ACTOR="${1#*=}"; shift ;;
      --action-type) CFCTL_ACTION_TYPE="$2"; shift 2 ;;
      --action-type=*) CFCTL_ACTION_TYPE="${1#*=}"; shift ;;
      --resource-type) CFCTL_RESOURCE_TYPE="$2"; shift 2 ;;
      --resource-type=*) CFCTL_RESOURCE_TYPE="${1#*=}"; shift ;;
      --limit) CFCTL_LIMIT="$2"; shift 2 ;;
      --limit=*) CFCTL_LIMIT="${1#*=}"; shift ;;
      --per-page) CFCTL_LIMIT="$2"; shift 2 ;;
      --per-page=*) CFCTL_LIMIT="${1#*=}"; shift ;;
      --include-records) CFCTL_INCLUDE_RECORDS="$2"; shift 2 ;;
      --include-records=*) CFCTL_INCLUDE_RECORDS="${1#*=}"; shift ;;
      --include-config) CFCTL_INCLUDE_CONFIG="$2"; shift 2 ;;
      --include-config=*) CFCTL_INCLUDE_CONFIG="${1#*=}"; shift ;;
      --all-lanes) CFCTL_ALL_LANES="1"; shift ;;
      --state-dir) CFCTL_STATE_DIR="$2"; shift 2 ;;
      --state-dir=*) CFCTL_STATE_DIR="${1#*=}"; shift ;;
      --strict) CFCTL_STRICT="1"; shift ;;
      --repair-hints) CFCTL_REPAIR_HINTS="1"; shift ;;
      *)
        CFCTL_PASSTHROUGH_ARGS+=("$1")
        if [[ -n "${CFCTL_UNKNOWN_ARGS}" ]]; then
          CFCTL_UNKNOWN_ARGS="${CFCTL_UNKNOWN_ARGS}, ${1}"
        else
          CFCTL_UNKNOWN_ARGS="${1}"
        fi
        shift
        ;;
    esac
  done
}

cfctl_parse_wrapper_flags() {
  cfctl_reset_flags

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --plan)
        CFCTL_PLAN="1"
        shift
        ;;
      --ack-plan)
        CFCTL_ACK_PLAN="$2"
        shift 2
        ;;
      --ack-plan=*)
        CFCTL_ACK_PLAN="${1#*=}"
        shift
        ;;
      *)
        CFCTL_PASSTHROUGH_ARGS+=("$1")
        if [[ -n "${CFCTL_UNKNOWN_ARGS}" ]]; then
          CFCTL_UNKNOWN_ARGS="${CFCTL_UNKNOWN_ARGS}, ${1}"
        else
          CFCTL_UNKNOWN_ARGS="${1}"
        fi
        shift
        ;;
    esac
  done
}

cfctl_registry_json() {
  cat "${CFCTL_REGISTRY_PATH}"
}

cfctl_standards_json() {
  cat "${CFCTL_STANDARDS_PATH}"
}

cfctl_doc_bank_json() {
  cat "${CFCTL_DOC_BANK_PATH}"
}

cfctl_has_tool_wrapper() {
  local tool="$1"
  jq -e --arg tool "${tool}" '.tool_wrappers[$tool] != null' "$(cf_runtime_catalog_path)" >/dev/null
}

cfctl_tool_wrapper_meta_json() {
  local tool="$1"
  jq -c --arg tool "${tool}" '.tool_wrappers[$tool] // empty' "$(cf_runtime_catalog_path)"
}

cfctl_tool_wrapper_script_relpath() {
  local tool="$1"
  jq -r --arg tool "${tool}" '.tool_wrappers[$tool].script // empty' "$(cf_runtime_catalog_path)"
}

cfctl_tool_wrapper_backend() {
  local tool="$1"
  jq -r --arg tool "${tool}" '.tool_wrappers[$tool].backend // empty' "$(cf_runtime_catalog_path)"
}

cfctl_tool_wrapper_log_category() {
  local tool="$1"
  jq -r --arg tool "${tool}" '.tool_wrappers[$tool].log_category // empty' "$(cf_runtime_catalog_path)"
}

cfctl_tool_wrapper_default_args_json() {
  local tool="$1"
  jq -c --arg tool "${tool}" '.tool_wrappers[$tool].default_args // []' "$(cf_runtime_catalog_path)"
}

cfctl_tool_wrapper_read_only_prefixes_json() {
  local tool="$1"
  jq -c --arg tool "${tool}" '.tool_wrappers[$tool].read_only_prefixes // []' "$(cf_runtime_catalog_path)"
}

cfctl_args_json() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]\n'
    return
  fi

  printf '%s\0' "$@" | jq -Rsc 'split("\u0000")[:-1]'
}

cfctl_shell_join_args() {
  local rendered=""
  local arg

  for arg in "$@"; do
    printf -v rendered '%s %q' "${rendered}" "${arg}"
  done

  printf '%s' "${rendered# }"
}

cfctl_tool_wrapper_classification_json() {
  local tool="$1"
  shift
  local args_json
  local default_args_json
  local read_only_prefixes_json

  args_json="$(cfctl_args_json "$@")"
  default_args_json="$(cfctl_tool_wrapper_default_args_json "${tool}")"
  read_only_prefixes_json="$(cfctl_tool_wrapper_read_only_prefixes_json "${tool}")"

  jq -n \
    --arg tool "${tool}" \
    --argjson args "${args_json}" \
    --argjson default_args "${default_args_json}" \
    --argjson read_only_prefixes "${read_only_prefixes_json}" \
    '
      ($args | if length == 0 then $default_args else . end) as $effective_args
      | (
          [
            ($read_only_prefixes // [])[] as $prefix
            | select(
                ($prefix | length) <= ($effective_args | length)
                and (
                  [range(0; ($prefix | length)) | $effective_args[.] == $prefix[.]]
                  | all
                )
              )
            | $prefix
          ][0] // null
        ) as $matched_prefix
      | {
          tool: $tool,
          input_args: $args,
          effective_args: $effective_args,
          defaulted: (($args | length) == 0),
          mode: (if $matched_prefix == null then "preview_required" else "read_only" end),
          matched_prefix: $matched_prefix,
          operation: (if ($effective_args | length) == 0 then "run" else ($effective_args[0]) end)
        }
    '
}

cfctl_has_doc_bank_topic() {
  local topic="$1"
  jq -e \
    --arg topic "${topic}" \
    '
      ($topic == "foundation")
      or ($topic == "watch")
      or ((.foundation // []) | any(.id == $topic))
      or ((.watch // []) | any(.id == $topic))
    ' \
    "${CFCTL_DOC_BANK_PATH}" >/dev/null
}

cfctl_has_standards_surface() {
  local surface="$1"
  jq -e --arg surface "${surface}" '.surfaces[$surface] != null' "${CFCTL_STANDARDS_PATH}" >/dev/null
}

cfctl_standards_audit_default_root() {
  local env_name
  env_name="$(jq -r '.audit.default_root_env // "CFCTL_AUDIT_ROOT"' "${CFCTL_STANDARDS_PATH}")"
  local from_env="${!env_name:-}"
  if [[ -n "${from_env}" ]]; then
    printf '%s\n' "${from_env}"
    return
  fi
  jq -r --arg fallback "${HOME}/dev" '.audit.default_root // $fallback' "${CFCTL_STANDARDS_PATH}"
}

cfctl_workspace_standards_audit_json() {
  local root="$1"
  python3 "${CFCTL_STANDARDS_AUDIT_SCRIPT}" \
    --root "${root}" \
    --standards-path "${CFCTL_STANDARDS_PATH}"
}

cfctl_surface_meta() {
  local surface="$1"
  jq -c --arg surface "${surface}" '.surfaces[$surface] // empty' "${CFCTL_REGISTRY_PATH}"
}

cfctl_surface_module_name() {
  local surface="$1"
  jq -r --arg surface "${surface}" '.surfaces[$surface].module // empty' "${CFCTL_REGISTRY_PATH}"
}

cfctl_surface_standards_ref() {
  local surface="$1"
  jq -r --arg surface "${surface}" '.surfaces[$surface].standards_ref // empty' "${CFCTL_REGISTRY_PATH}"
}

cfctl_surface_docs_topics_json() {
  local surface="$1"
  jq -c --arg surface "${surface}" '.surfaces[$surface].docs_topics // []' "${CFCTL_REGISTRY_PATH}"
}

cfctl_surface_inventory_script_relpath() {
  local surface="$1"
  jq -r --arg surface "${surface}" '.surfaces[$surface].inventory_script // empty' "${CFCTL_REGISTRY_PATH}"
}

cfctl_surface_apply_script_relpath() {
  local surface="$1"
  jq -r --arg surface "${surface}" '.surfaces[$surface].apply_script // empty' "${CFCTL_REGISTRY_PATH}"
}

cfctl_surface_call_module() {
  local surface="$1"
  local suffix="$2"
  shift 2

  local module
  local fn

  module="$(cfctl_surface_module_name "${surface}")"
  [[ -n "${module}" ]] || return 1

  fn="cfctl_surface_${module}_${suffix}"
  declare -F "${fn}" >/dev/null 2>&1 || return 1
  "${fn}" "$@"
}

cfctl_has_surface() {
  local surface="$1"
  jq -e --arg surface "${surface}" '.surfaces[$surface] != null' "${CFCTL_REGISTRY_PATH}" >/dev/null
}

cfctl_action_meta() {
  local surface="$1"
  local action="$2"
  local operation="${3:-}"

  jq -c \
    --arg surface "${surface}" \
    --arg action "${action}" \
    --arg operation "${operation}" \
    '
      .surfaces[$surface] as $surface_meta
      | if $surface_meta == null then
          null
        elif $action == "apply" then
          ($surface_meta.actions.apply.operations[$operation] // null)
        else
          ($surface_meta.actions[$action] // null)
        end
    ' \
    "${CFCTL_REGISTRY_PATH}"
}

cfctl_action_supported() {
  local surface="$1"
  local action="$2"
  local operation="${3:-}"

  jq -e \
    --arg surface "${surface}" \
    --arg action "${action}" \
    --arg operation "${operation}" \
    '
      .surfaces[$surface] as $surface_meta
      | if $surface_meta == null then
          false
        elif $action == "apply" then
          ($surface_meta.actions.apply.supported == true and ($surface_meta.actions.apply.operations[$operation] != null))
        else
          ($surface_meta.actions[$action].supported == true)
        end
    ' \
    "${CFCTL_REGISTRY_PATH}" >/dev/null
}

cfctl_operation_policy_json() {
  local surface="$1"
  local action="$2"
  local operation="${3:-}"
  local meta
  local runtime_policy
  local special_operation_key=""

  meta="$(cfctl_action_meta "${surface}" "${action}" "${operation}")"
  runtime_policy="$(cfctl_runtime_policy_json)"

  if [[ "${surface}" == "token" && "${operation}" == "mint" ]]; then
    special_operation_key="token.mint"
  elif [[ "${operation}" == "sync" ]]; then
    special_operation_key="sync"
  fi

  jq -n \
    --arg surface "${surface}" \
    --arg action "${action}" \
    --arg operation "${operation}" \
    --arg special_operation_key "${special_operation_key}" \
    --argjson meta "${meta}" \
    --argjson runtime_policy "${runtime_policy}" \
    '
      ($runtime_policy.preview_ack_flag // "--ack-plan") as $preview_ack_flag
      | (
          if $special_operation_key == "" then
            {}
          else
            ($runtime_policy.special_operations[$special_operation_key] // {})
          end
        ) as $special_defaults
      | ($special_defaults.risk // $meta.risk // (if $action == "apply" then "write" else "read" end)) as $risk
      | ($runtime_policy.operation_defaults[$risk] // {}) as $risk_defaults
      | {
          surface: $surface,
          action: $action,
          operation: (if $operation == "" then null else $operation end),
          risk: $risk,
          preview_required: (
            ($special_defaults.preview_required // $meta.preview_required // $risk_defaults.preview_required // false)
          ),
          confirmation: ($meta.confirm // null),
          allowed_lanes: ($special_defaults.allowed_lanes // $meta.allowed_lanes // $risk_defaults.allowed_lanes // ["dev", "global"]),
          verification_required: ($special_defaults.verification_required // $meta.verification_required // $risk_defaults.verification_required // false),
          secret_policy: ($special_defaults.secret_policy // $meta.secret_policy // $risk_defaults.secret_policy // "redacted"),
          lock_strategy: ($special_defaults.lock_strategy // $meta.lock_strategy // $risk_defaults.lock_strategy // "none"),
          preview_ttl_seconds: ($special_defaults.preview_ttl_seconds // $meta.preview_ttl_seconds // $risk_defaults.preview_ttl_seconds // ($runtime_policy.preview_ttl_seconds // 900)),
          preview_ack_flag: $preview_ack_flag,
          public_example: ($special_defaults.public_example // $meta.public_example // $risk_defaults.public_example // null),
          troubleshooting_hint: ($special_defaults.troubleshooting_hint // $meta.troubleshooting_hint // $risk_defaults.troubleshooting_hint // null)
        }
    '
}

cfctl_operation_requires_preview() {
  local surface="$1"
  local action="$2"
  local operation="${3:-}"

  [[ "$(jq -r '.preview_required' <<< "$(cfctl_operation_policy_json "${surface}" "${action}" "${operation}")")" == "true" ]]
}

cfctl_required_confirmation() {
  local surface="$1"
  local operation="${2:-}"

  jq -r '.confirm // empty' <<< "$(cfctl_action_meta "${surface}" "apply" "${operation}")"
}

cfctl_allowed_lanes_for_operation_json() {
  local surface="$1"
  local action="$2"
  local operation="${3:-}"

  jq -c '.allowed_lanes // ["dev", "global"]' <<< "$(cfctl_operation_policy_json "${surface}" "${action}" "${operation}")"
}

cfctl_policy_version() {
  local runtime_version
  local surface_version

  runtime_version="$(jq -r '.version // 0' "$(cf_runtime_catalog_path)")"
  surface_version="$(jq -r '.version // 0' "${CFCTL_REGISTRY_PATH}")"
  printf 'runtime:%s/surfaces:%s\n' "${runtime_version}" "${surface_version}"
}

cfctl_current_operation_request_json() {
  local surface="$1"
  local operation="${2:-}"
  local resolved_body="null"

  if [[ -n "${CFCTL_BODY_JSON}" || -n "${CFCTL_BODY_FILE}" ]]; then
    resolved_body="$(cf_resolve_json_payload "${CFCTL_BODY_JSON}" "${CFCTL_BODY_FILE}")"
  fi

  jq -n \
    --arg surface "${surface}" \
    --arg operation "${operation}" \
    --argjson target "$(cfctl_target_json)" \
    --argjson body "${resolved_body}" \
    --argjson hosts "${CFCTL_HOSTS_JSON}" \
    --arg certificate_authority "${CFCTL_CERTIFICATE_AUTHORITY}" \
    --arg validation_method "${CFCTL_VALIDATION_METHOD}" \
    --arg validity_days "${CFCTL_VALIDITY_DAYS}" \
    --arg cloudflare_branding "${CFCTL_CLOUDFLARE_BRANDING}" \
    --arg content "${CFCTL_CONTENT}" \
    --arg file "${CFCTL_FILE}" \
    --arg pattern "${CFCTL_PATTERN}" \
    --arg service "${CFCTL_SERVICE}" \
    --arg ttl "${CFCTL_TTL}" \
    --arg proxied "${CFCTL_PROXIED}" \
    --arg priority "${CFCTL_PRIORITY}" \
    --arg comment "${CFCTL_COMMENT}" \
    --argjson tags "$(if [[ -n "${CFCTL_TAGS_JSON}" ]]; then printf '%s\n' "${CFCTL_TAGS_JSON}"; else echo 'null'; fi)" \
    --argjson data "$(if [[ -n "${CFCTL_DATA_JSON}" ]]; then printf '%s\n' "${CFCTL_DATA_JSON}"; else echo 'null'; fi)" \
    --arg scope "${CFCTL_SCOPE}" \
    --arg confirm "${CFCTL_CONFIRM}" \
    --arg client_id "${CFCTL_CLIENT_ID}" \
    --arg since "${CFCTL_SINCE}" \
    --arg before "${CFCTL_BEFORE}" \
    --arg actor "${CFCTL_ACTOR}" \
    --arg action_type "${CFCTL_ACTION_TYPE}" \
    --arg resource_type "${CFCTL_RESOURCE_TYPE}" \
    --arg limit "${CFCTL_LIMIT}" \
    '
      {
        surface: $surface,
        operation: (if $operation == "" then null else $operation end),
        target: $target,
        body: $body,
        hosts: $hosts,
        certificate_authority: (if $certificate_authority == "" then null else $certificate_authority end),
        validation_method: (if $validation_method == "" then null else $validation_method end),
        validity_days: (if $validity_days == "" then null else $validity_days end),
        cloudflare_branding: (if $cloudflare_branding == "" then null else $cloudflare_branding end),
        content: (if $content == "" then null else $content end),
        file: (if $file == "" then null else $file end),
        pattern: (if $pattern == "" then null else $pattern end),
        service: (if $service == "" then null else $service end),
        ttl: (if $ttl == "" then null else $ttl end),
        proxied: (if $proxied == "" then null else $proxied end),
        priority: (if $priority == "" then null else $priority end),
        comment: (if $comment == "" then null else $comment end),
        tags: $tags,
        data: $data,
        scope: (if $scope == "" then null else $scope end),
        client_id: (if $client_id == "" then null else $client_id end),
        since: (if $since == "" then null else $since end),
        before: (if $before == "" then null else $before end),
        actor: (if $actor == "" then null else $actor end),
        action_type: (if $action_type == "" then null else $action_type end),
        resource_type: (if $resource_type == "" then null else $resource_type end),
        limit: (if $limit == "" then null else $limit end),
        confirm: (if $confirm == "" then null else $confirm end)
      }
      | with_entries(select(.value != null))
    '
}

cfctl_sync_request_json() {
  local surface="$1"
  local diff_json="$2"

  jq -n \
    --arg surface "${surface}" \
    --argjson diff "${diff_json}" \
    '
      {
        surface: $surface,
        operation: "sync",
        diff_summary: ($diff.summary // {}),
        desired_specs: ($diff.desired_specs // []),
        unmanaged_actual_count: ($diff.summary.unmanaged_actual_count // 0)
      }
    '
}

cfctl_build_trust_json() {
  local surface="$1"
  local action="$2"
  local operation="$3"
  local request_json="$4"
  local target_json="$5"
  local policy_json
  local policy_version
  local policy_fingerprint
  local target_fingerprint
  local request_fingerprint
  local preview_ttl_seconds
  local preview_expires_at="null"
  local lock_key="null"

  policy_json="$(cfctl_operation_policy_json "${surface}" "${action}" "${operation}")"
  policy_version="$(cfctl_policy_version)"
  policy_fingerprint="$(cf_hash_json "${policy_json}")"
  target_fingerprint="$(cf_hash_json "${target_json}")"
  request_fingerprint="$(cf_hash_json "${request_json}")"
  preview_ttl_seconds="$(jq -r '.preview_ttl_seconds // 0' <<< "${policy_json}")"

  if [[ "${preview_ttl_seconds}" != "0" ]]; then
    preview_expires_at="$(jq -Rn --arg ts "$(cf_seconds_from_now_iso8601 "${preview_ttl_seconds}")" '$ts')"
  fi

  if [[ "$(jq -r '.lock_strategy != "none"' <<< "${policy_json}")" == "true" ]]; then
    lock_key="$(jq -Rn --arg key "$(cf_runtime_lock_key "${action}" "${surface}" "${operation}" "${target_json}")" '$key')"
  fi

  jq -n \
    --arg action "${action}" \
    --arg surface "${surface}" \
    --arg operation "${operation}" \
    --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg policy_version "${policy_version}" \
    --arg policy_fingerprint "${policy_fingerprint}" \
    --arg target_fingerprint "${target_fingerprint}" \
    --arg request_fingerprint "${request_fingerprint}" \
    --argjson target "${target_json}" \
    --argjson request "${request_json}" \
    --argjson policy "${policy_json}" \
    --argjson preview_expires_at "${preview_expires_at}" \
    --argjson lock_key "${lock_key}" \
    '
      {
        action: $action,
        surface: $surface,
        operation: (if $operation == "" then null else $operation end),
        lane: $lane,
        policy_version: $policy_version,
        policy_fingerprint: $policy_fingerprint,
        target_fingerprint: $target_fingerprint,
        request_fingerprint: $request_fingerprint,
        target: $target,
        request: $request,
        policy: $policy,
        preview_expires_at: $preview_expires_at,
        lock_key: $lock_key,
        lock_mode: ($policy.lock_strategy // "none"),
        secret_policy: ($policy.secret_policy // "redacted")
      }
    '
}

cfctl_find_plan_receipt_path() {
  local surface="$1"
  local operation="$2"
  local ack_plan="$3"
  local runtime_dir="${CF_REPO_ROOT}/var/inventory/runtime"
  local candidate

  if [[ ! -d "${runtime_dir}" ]]; then
    return 1
  fi

  for candidate in "${runtime_dir}"/*.json; do
    [[ -f "${candidate}" ]] || continue
    if jq -e \
      --arg ack_plan "${ack_plan}" \
      --arg surface "${surface}" \
      --arg operation "${operation}" \
      '
        (.operation_id // "") == $ack_plan
        and .action == "apply"
        and .surface == $surface
        and .operation == $operation
        and (.summary.plan_mode // false) == true
      ' \
      "${candidate}" >/dev/null 2>&1; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  return 1
}

cfctl_validate_plan_receipt_trust() {
  local receipt_path="$1"
  local expected_trust_json="$2"
  local receipt_trust_json
  local expected_lane
  local receipt_lane
  local preview_expires_at
  local preview_expires_epoch
  local receipt_lock_mode
  local receipt_lock_key
  local receipt_operation_id

  CFCTL_PLAN_RECEIPT_TRUST_JSON="null"
  CFCTL_PLAN_RECEIPT_ERROR_CODE=""
  CFCTL_PLAN_RECEIPT_ERROR_MESSAGE=""

  receipt_trust_json="$(jq -c '.trust // null' "${receipt_path}")"
  if [[ "${receipt_trust_json}" == "null" ]]; then
    CFCTL_PLAN_RECEIPT_ERROR_CODE="preview_receipt_missing"
    CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview receipt is missing trust metadata"
    return 1
  fi

  preview_expires_at="$(jq -r '.preview_expires_at // empty' <<< "${receipt_trust_json}")"
  if [[ -n "${preview_expires_at}" ]]; then
    preview_expires_epoch="$(cf_iso8601_to_epoch "${preview_expires_at}" 2>/dev/null || true)"
    if [[ -z "${preview_expires_epoch}" || "${preview_expires_epoch}" -le "$(cf_now_epoch)" ]]; then
      CFCTL_PLAN_RECEIPT_ERROR_CODE="preview_expired"
      CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview receipt has expired"
      return 1
    fi
  fi

  expected_lane="$(jq -r '.lane // empty' <<< "${expected_trust_json}")"
  receipt_lane="$(jq -r '.lane // empty' <<< "${receipt_trust_json}")"
  if [[ "${expected_lane}" != "${receipt_lane}" ]]; then
    CFCTL_PLAN_RECEIPT_ERROR_CODE="preview_lane_mismatch"
    CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview receipt was created on a different auth lane"
    return 1
  fi

  if [[ "$(jq -r '.policy_fingerprint' <<< "${expected_trust_json}")" != "$(jq -r '.policy_fingerprint' <<< "${receipt_trust_json}")" ]]; then
    CFCTL_PLAN_RECEIPT_ERROR_CODE="preview_version_mismatch"
    CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview receipt policy no longer matches current runtime policy"
    return 1
  fi

  if [[ "$(jq -r '.target_fingerprint' <<< "${expected_trust_json}")" != "$(jq -r '.target_fingerprint' <<< "${receipt_trust_json}")" ]]; then
    CFCTL_PLAN_RECEIPT_ERROR_CODE="preview_payload_mismatch"
    CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview receipt selectors no longer match the current target"
    return 1
  fi

  if [[ "$(jq -r '.request_fingerprint' <<< "${expected_trust_json}")" != "$(jq -r '.request_fingerprint' <<< "${receipt_trust_json}")" ]]; then
    CFCTL_PLAN_RECEIPT_ERROR_CODE="preview_payload_mismatch"
    CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview receipt request body no longer matches the current payload"
    return 1
  fi

  receipt_lock_mode="$(jq -r '.lock_mode // "none"' <<< "${receipt_trust_json}")"
  receipt_lock_key="$(jq -r '.lock_key // empty' <<< "${receipt_trust_json}")"
  receipt_operation_id="$(jq -r '.operation_id // empty' "${receipt_path}")"
  if [[ "${receipt_lock_mode}" == "lease" && -n "${receipt_lock_key}" ]]; then
    if ! cf_runtime_lock_validate_lease "${receipt_lock_key}" "${receipt_operation_id}"; then
      CFCTL_PLAN_RECEIPT_ERROR_CODE="lock_unavailable"
      CFCTL_PLAN_RECEIPT_ERROR_MESSAGE="Preview lease lock is no longer valid"
      return 1
    fi
  fi

  CFCTL_PLAN_RECEIPT_TRUST_JSON="${receipt_trust_json}"
  return 0
}

cfctl_lane_allowed_for_operation() {
  local surface="$1"
  local action="$2"
  local operation="${3:-}"

  jq -e --arg lane "${CF_ACTIVE_TOKEN_LANE:-}" '. | index($lane) != null' <<< "$(cfctl_allowed_lanes_for_operation_json "${surface}" "${action}" "${operation}")" >/dev/null
}

cfctl_current_args_shell() {
  local args=()

  [[ -n "${CFCTL_ID}" ]] && args+=(--id "${CFCTL_ID}")
  [[ -n "${CFCTL_NAME}" ]] && args+=(--name "${CFCTL_NAME}")
  [[ -n "${CFCTL_DOMAIN}" ]] && args+=(--domain "${CFCTL_DOMAIN}")
  [[ -n "${CFCTL_FILE}" ]] && args+=(--file "${CFCTL_FILE}")
  [[ -n "${CFCTL_PATTERN}" ]] && args+=(--pattern "${CFCTL_PATTERN}")
  [[ -n "${CFCTL_SERVICE}" ]] && args+=(--service "${CFCTL_SERVICE}")
  [[ -n "${CFCTL_ZONE_NAME}" ]] && args+=(--zone "${CFCTL_ZONE_NAME}")
  [[ -n "${CFCTL_ZONE_ID}" ]] && args+=(--zone-id "${CFCTL_ZONE_ID}")
  [[ -n "${CFCTL_TYPE}" ]] && args+=(--type "${CFCTL_TYPE}")
  [[ -n "${CFCTL_SITEKEY}" ]] && args+=(--sitekey "${CFCTL_SITEKEY}")
  [[ -n "${CFCTL_APP_ID}" ]] && args+=(--app-id "${CFCTL_APP_ID}")
  [[ -n "${CFCTL_POLICY_ID}" ]] && args+=(--policy-id "${CFCTL_POLICY_ID}")
  [[ -n "${CFCTL_JOB_ID}" ]] && args+=(--job-id "${CFCTL_JOB_ID}")
  [[ -n "${CFCTL_SCOPE}" && "${CFCTL_SCOPE}" != "account" ]] && args+=(--scope "${CFCTL_SCOPE}")
  [[ -n "${CFCTL_BODY_JSON}" ]] && args+=(--body "${CFCTL_BODY_JSON}")
  [[ -n "${CFCTL_BODY_FILE}" ]] && args+=(--body-file "${CFCTL_BODY_FILE}")
  while IFS= read -r host; do
    [[ -n "${host}" ]] && args+=(--host "${host}")
  done < <(jq -r '.[]?' <<< "${CFCTL_HOSTS_JSON}")
  [[ -n "${CFCTL_CERTIFICATE_AUTHORITY}" ]] && args+=(--certificate-authority "${CFCTL_CERTIFICATE_AUTHORITY}")
  [[ -n "${CFCTL_VALIDATION_METHOD}" ]] && args+=(--validation-method "${CFCTL_VALIDATION_METHOD}")
  [[ -n "${CFCTL_VALIDITY_DAYS}" ]] && args+=(--validity-days "${CFCTL_VALIDITY_DAYS}")
  [[ -n "${CFCTL_CLOUDFLARE_BRANDING}" ]] && args+=(--cloudflare-branding "${CFCTL_CLOUDFLARE_BRANDING}")
  [[ -n "${CFCTL_CONTENT}" ]] && args+=(--content "${CFCTL_CONTENT}")
  [[ -n "${CFCTL_TTL}" ]] && args+=(--ttl "${CFCTL_TTL}")
  [[ -n "${CFCTL_PROXIED}" ]] && args+=(--proxied "${CFCTL_PROXIED}")
  [[ -n "${CFCTL_PRIORITY}" ]] && args+=(--priority "${CFCTL_PRIORITY}")
  [[ -n "${CFCTL_COMMENT}" ]] && args+=(--comment "${CFCTL_COMMENT}")
  [[ -n "${CFCTL_TAGS_JSON}" ]] && args+=(--tags-json "${CFCTL_TAGS_JSON}")
  [[ -n "${CFCTL_DATA_JSON}" ]] && args+=(--data-json "${CFCTL_DATA_JSON}")
  [[ -n "${CFCTL_TUNNEL_ID}" ]] && args+=(--tunnel-id "${CFCTL_TUNNEL_ID}")
  [[ -n "${CFCTL_CLIENT_ID}" ]] && args+=(--client-id "${CFCTL_CLIENT_ID}")
  [[ -n "${CFCTL_SINCE}" ]] && args+=(--since "${CFCTL_SINCE}")
  [[ -n "${CFCTL_BEFORE}" ]] && args+=(--before "${CFCTL_BEFORE}")
  [[ -n "${CFCTL_ACTOR}" ]] && args+=(--actor "${CFCTL_ACTOR}")
  [[ -n "${CFCTL_ACTION_TYPE}" ]] && args+=(--action-type "${CFCTL_ACTION_TYPE}")
  [[ -n "${CFCTL_RESOURCE_TYPE}" ]] && args+=(--resource-type "${CFCTL_RESOURCE_TYPE}")
  [[ -n "${CFCTL_LIMIT}" ]] && args+=(--limit "${CFCTL_LIMIT}")
  [[ "${CFCTL_INCLUDE_RECORDS}" != "1" ]] && args+=(--include-records "${CFCTL_INCLUDE_RECORDS}")
  [[ "${CFCTL_INCLUDE_CONFIG}" != "0" ]] && args+=(--include-config "${CFCTL_INCLUDE_CONFIG}")
  [[ -n "${CFCTL_STATE_DIR}" ]] && args+=(--state-dir "${CFCTL_STATE_DIR}")
  if [[ "${#CFCTL_PASSTHROUGH_ARGS[@]}" -gt 0 ]]; then
    args+=("${CFCTL_PASSTHROUGH_ARGS[@]}")
  fi

  if [[ "${#args[@]}" -eq 0 ]]; then
    printf ''
    return
  fi

  printf ' %q' "${args[@]}"
}

cfctl_current_selector_args_shell() {
  local args=()

  [[ -n "${CFCTL_ID}" ]] && args+=(--id "${CFCTL_ID}")
  [[ -n "${CFCTL_NAME}" ]] && args+=(--name "${CFCTL_NAME}")
  [[ -n "${CFCTL_DOMAIN}" ]] && args+=(--domain "${CFCTL_DOMAIN}")
  [[ -n "${CFCTL_FILE}" ]] && args+=(--file "${CFCTL_FILE}")
  [[ -n "${CFCTL_PATTERN}" ]] && args+=(--pattern "${CFCTL_PATTERN}")
  [[ -n "${CFCTL_SERVICE}" ]] && args+=(--service "${CFCTL_SERVICE}")
  [[ -n "${CFCTL_ZONE_NAME}" ]] && args+=(--zone "${CFCTL_ZONE_NAME}")
  [[ -n "${CFCTL_ZONE_ID}" ]] && args+=(--zone-id "${CFCTL_ZONE_ID}")
  [[ -n "${CFCTL_TYPE}" ]] && args+=(--type "${CFCTL_TYPE}")
  [[ -n "${CFCTL_SITEKEY}" ]] && args+=(--sitekey "${CFCTL_SITEKEY}")
  [[ -n "${CFCTL_APP_ID}" ]] && args+=(--app-id "${CFCTL_APP_ID}")
  [[ -n "${CFCTL_POLICY_ID}" ]] && args+=(--policy-id "${CFCTL_POLICY_ID}")
  [[ -n "${CFCTL_JOB_ID}" ]] && args+=(--job-id "${CFCTL_JOB_ID}")
  [[ -n "${CFCTL_SCOPE}" && "${CFCTL_SCOPE}" != "account" ]] && args+=(--scope "${CFCTL_SCOPE}")
  [[ -n "${CFCTL_TUNNEL_ID}" ]] && args+=(--tunnel-id "${CFCTL_TUNNEL_ID}")
  [[ -n "${CFCTL_CLIENT_ID}" ]] && args+=(--client-id "${CFCTL_CLIENT_ID}")
  [[ -n "${CFCTL_SINCE}" ]] && args+=(--since "${CFCTL_SINCE}")
  [[ -n "${CFCTL_BEFORE}" ]] && args+=(--before "${CFCTL_BEFORE}")
  [[ -n "${CFCTL_ACTOR}" ]] && args+=(--actor "${CFCTL_ACTOR}")
  [[ -n "${CFCTL_ACTION_TYPE}" ]] && args+=(--action-type "${CFCTL_ACTION_TYPE}")
  [[ -n "${CFCTL_RESOURCE_TYPE}" ]] && args+=(--resource-type "${CFCTL_RESOURCE_TYPE}")
  [[ -n "${CFCTL_LIMIT}" ]] && args+=(--limit "${CFCTL_LIMIT}")
  while IFS= read -r host; do
    [[ -n "${host}" ]] && args+=(--host "${host}")
  done < <(jq -r '.[]?' <<< "${CFCTL_HOSTS_JSON}")
  [[ "${CFCTL_INCLUDE_RECORDS}" != "1" ]] && args+=(--include-records "${CFCTL_INCLUDE_RECORDS}")
  [[ "${CFCTL_INCLUDE_CONFIG}" != "0" ]] && args+=(--include-config "${CFCTL_INCLUDE_CONFIG}")
  [[ -n "${CFCTL_STATE_DIR}" ]] && args+=(--state-dir "${CFCTL_STATE_DIR}")

  if [[ "${#args[@]}" -eq 0 ]]; then
    printf ''
    return
  fi

  printf ' %q' "${args[@]}"
}

cfctl_selector_presence_json() {
  jq -n \
    --arg id "${CFCTL_ID}" \
    --arg name "${CFCTL_NAME}" \
    --arg domain "${CFCTL_DOMAIN}" \
    --arg pattern "${CFCTL_PATTERN}" \
    --arg service "${CFCTL_SERVICE}" \
    --arg zone_name "${CFCTL_ZONE_NAME}" \
    --arg zone_id "${CFCTL_ZONE_ID}" \
    --arg type "${CFCTL_TYPE}" \
    --arg sitekey "${CFCTL_SITEKEY}" \
    --arg app_id "${CFCTL_APP_ID}" \
    --arg policy_id "${CFCTL_POLICY_ID}" \
    --arg job_id "${CFCTL_JOB_ID}" \
    --arg scope "${CFCTL_SCOPE}" \
    --arg tunnel_id "${CFCTL_TUNNEL_ID}" \
    --arg client_id "${CFCTL_CLIENT_ID}" \
    --arg since "${CFCTL_SINCE}" \
    --arg before "${CFCTL_BEFORE}" \
    --arg actor "${CFCTL_ACTOR}" \
    --arg action_type "${CFCTL_ACTION_TYPE}" \
    --arg resource_type "${CFCTL_RESOURCE_TYPE}" \
    --arg limit "${CFCTL_LIMIT}" \
    --argjson hosts "${CFCTL_HOSTS_JSON}" \
    '
      {
        id: ($id | length > 0),
        name: ($name | length > 0),
        domain: ($domain | length > 0),
        pattern: ($pattern | length > 0),
        service: ($service | length > 0),
        zone: (($zone_name | length > 0) or ($zone_id | length > 0)),
        zone_id: ($zone_id | length > 0),
        type: ($type | length > 0),
        sitekey: ($sitekey | length > 0),
        app_id: ($app_id | length > 0),
        policy_id: ($policy_id | length > 0),
        job_id: ($job_id | length > 0),
        scope: ($scope | length > 0),
        tunnel_id: ($tunnel_id | length > 0),
        client_id: ($client_id | length > 0),
        since: ($since | length > 0),
        before: ($before | length > 0),
        actor: ($actor | length > 0),
        action_type: ($action_type | length > 0),
        resource_type: ($resource_type | length > 0),
        limit: ($limit | length > 0),
        host: (($hosts | length) > 0)
      }
    '
}

cfctl_requirement_check_json() {
  local surface="$1"
  local action="$2"
  local operation="${3:-}"
  local meta
  local presence

  meta="$(cfctl_action_meta "${surface}" "${action}" "${operation}")"
  if [[ -z "${meta}" || "${meta}" == "null" ]]; then
    jq -n \
      --arg surface "${surface}" \
      --arg action "${action}" \
      --arg operation "${operation}" \
      '
        {
          ready: false,
          surface: $surface,
          action: $action,
          operation: (if $operation == "" then null else $operation end),
          missing_required: [],
          any_satisfied: false,
          selectors_any_of: [],
          required_selectors: [],
          error: "unsupported_operation"
        }
      '
    return
  fi

  presence="$(cfctl_selector_presence_json)"
  jq -n \
    --argjson meta "${meta}" \
    --argjson present "${presence}" \
    '
      ($meta.required_selectors // []) as $required
      | ($meta.selectors_any_of // []) as $any
      | {
          required_selectors: $required,
          selectors_any_of: $any,
          missing_required: [$required[]? | select(($present[.] // false) | not)],
          any_satisfied: (
            if ($any | length) == 0 then
              true
            else
              any($any[]; all(.[]; ($present[.] // false)))
            end
          )
        }
      | .ready = ((.missing_required | length) == 0 and .any_satisfied == true)
    '
}

cfctl_validate_requirements() {
  local surface="$1"
  local action="$2"
  local operation="${3:-}"
  local validation

  validation="$(cfctl_requirement_check_json "${surface}" "${action}" "${operation}")"
  if [[ "$(jq -r '.error // empty' <<< "${validation}")" == "unsupported_operation" ]]; then
    echo "Unsupported ${action} for ${surface}" >&2
    return 1
  fi

  if [[ "$(jq -r '(.missing_required | length) > 0' <<< "${validation}")" == "true" ]]; then
    echo "Missing required selectors: $(jq -r '.missing_required | join(", ")' <<< "${validation}")" >&2
    return 1
  fi

  if [[ "$(jq -r '.any_satisfied' <<< "${validation}")" != "true" ]]; then
    echo "Missing a valid selector set for ${surface} ${action}" >&2
    return 1
  fi
}

cfctl_resolve_zone_context() {
  if [[ -z "${CF_ACTIVE_AUTH_SCHEME:-}" || -z "${CF_ACTIVE_AUTH_SECRET:-}" ]]; then
    return
  fi

  if [[ -n "${CFCTL_ZONE_NAME}" && -z "${CFCTL_ZONE_ID}" ]]; then
    CFCTL_ZONE_ID="$(cf_resolve_zone_id "${CFCTL_ZONE_NAME}")"
  fi

  if [[ -n "${CFCTL_ZONE_ID}" && -z "${CFCTL_ZONE_NAME}" ]]; then
    CFCTL_ZONE_NAME="$(
      cf_api GET "/zones/${CFCTL_ZONE_ID}" | jq -r '.result.name // empty'
    )"
  fi
}

cfctl_slugify() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr '. /:' '----' | tr -cd 'a-z0-9_-'
}

cfctl_target_json() {
  cfctl_resolve_zone_context

  jq -n \
    --arg id "${CFCTL_ID}" \
    --arg name "${CFCTL_NAME}" \
    --arg domain "${CFCTL_DOMAIN}" \
    --arg file "${CFCTL_FILE}" \
    --arg pattern "${CFCTL_PATTERN}" \
    --arg service "${CFCTL_SERVICE}" \
    --arg zone "${CFCTL_ZONE_NAME}" \
    --arg zone_id "${CFCTL_ZONE_ID}" \
    --arg type "${CFCTL_TYPE}" \
    --arg sitekey "${CFCTL_SITEKEY}" \
    --arg app_id "${CFCTL_APP_ID}" \
    --arg policy_id "${CFCTL_POLICY_ID}" \
    --arg job_id "${CFCTL_JOB_ID}" \
    --arg scope "${CFCTL_SCOPE}" \
    --arg tunnel_id "${CFCTL_TUNNEL_ID}" \
    --arg client_id "${CFCTL_CLIENT_ID}" \
    --arg since "${CFCTL_SINCE}" \
    --arg before "${CFCTL_BEFORE}" \
    --arg actor "${CFCTL_ACTOR}" \
    --arg action_type "${CFCTL_ACTION_TYPE}" \
    --arg resource_type "${CFCTL_RESOURCE_TYPE}" \
    --arg limit "${CFCTL_LIMIT}" \
    --argjson hosts "${CFCTL_HOSTS_JSON}" \
    '
      {
        id: (if $id == "" then null else $id end),
        name: (if $name == "" then null else $name end),
        domain: (if $domain == "" then null else $domain end),
        file: (if $file == "" then null else $file end),
        pattern: (if $pattern == "" then null else $pattern end),
        service: (if $service == "" then null else $service end),
        zone: (if $zone == "" then null else $zone end),
        zone_id: (if $zone_id == "" then null else $zone_id end),
        type: (if $type == "" then null else $type end),
        sitekey: (if $sitekey == "" then null else $sitekey end),
        app_id: (if $app_id == "" then null else $app_id end),
        policy_id: (if $policy_id == "" then null else $policy_id end),
        job_id: (if $job_id == "" then null else $job_id end),
        scope: (if $scope == "" then null else $scope end),
        tunnel_id: (if $tunnel_id == "" then null else $tunnel_id end),
        client_id: (if $client_id == "" then null else $client_id end),
        since: (if $since == "" then null else $since end),
        before: (if $before == "" then null else $before end),
        actor: (if $actor == "" then null else $actor end),
        action_type: (if $action_type == "" then null else $action_type end),
        resource_type: (if $resource_type == "" then null else $resource_type end),
        limit: (if $limit == "" then null else $limit end),
        hosts: (if ($hosts | length) == 0 then null else $hosts end)
      }
      | with_entries(select(.value != null))
    '
}

cfctl_permission_spec_json() {
  local surface="$1"
  local action="$2"
  local operation="${3:-}"
  local permission_family
  local meta
  local module_json

  cfctl_resolve_zone_context
  meta="$(cfctl_surface_meta "${surface}")"
  permission_family="$(jq -r '.permission_family // "Cloudflare API"' <<< "${meta}")"

  if module_json="$(cfctl_surface_call_module "${surface}" "permission_spec_json" "${permission_family}" 2>/dev/null)"; then
    printf '%s\n' "${module_json}"
    return
  fi

  case "${surface}" in
    waiting_room)
      jq -n \
        --arg method "GET" \
        --arg path "/zones/${CFCTL_ZONE_ID}/waiting_rooms" \
        --arg permission_family "${permission_family}" \
        '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
      ;;
    logpush.job)
      if [[ "${CFCTL_SCOPE}" == "zone" ]]; then
        jq -n \
          --arg method "GET" \
          --arg path "/zones/${CFCTL_ZONE_ID}/logpush/jobs" \
          --arg permission_family "${permission_family}" \
          '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
      else
        jq -n \
          --arg method "GET" \
          --arg path "/accounts/${CLOUDFLARE_ACCOUNT_ID}/logpush/jobs" \
          --arg permission_family "${permission_family}" \
          '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
      fi
      ;;
    *)
      jq -n \
        --argjson meta "${meta}" \
        --arg account_id "${CLOUDFLARE_ACCOUNT_ID:-}" \
        --arg zone_id "${CFCTL_ZONE_ID:-}" \
        '
          ($meta.probe // {}) as $probe
          | if ($probe.path_template // "") == "" then
              {method: null, path: null, permission_family: ($meta.permission_family // "Cloudflare API"), inference: "no_probe_registered"}
            else
              {
                method: ($probe.method // "GET"),
                path: (
                  ($probe.path_template // "")
                  | gsub("\\{account_id\\}"; $account_id)
                  | gsub("\\{zone_id\\}"; $zone_id)
                ),
                permission_family: ($meta.permission_family // "Cloudflare API"),
                inference: "surface_read_probe"
              }
            end
        '
      ;;
    esac
}

cfctl_selector_to_item_field() {
  local surface="$1"
  local selector="$2"
  local mapped=""

  if mapped="$(cfctl_surface_call_module "${surface}" "selector_to_item_field" "${selector}" 2>/dev/null)"; then
    printf '%s\n' "${mapped}"
    return
  fi

  printf '%s\n' "${selector}"
}

cfctl_surface_discovery_command() {
  local surface="$1"
  local recommended_lane="${2:-}"
  local command=""

  if command="$(cfctl_surface_call_module "${surface}" "discovery_command" 2>/dev/null)"; then
    command="${command%$'\n'}"
    printf '%s\n' "$(cfctl_command_with_lane_prefix "${recommended_lane}" "${command}")"
    return
  fi

  printf '%s\n' "$(cfctl_command_with_lane_prefix "${recommended_lane}" "$(cfctl_build_selector_verb_command "list" "${surface}")")"
}

cfctl_surface_verify_command() {
  local surface="$1"
  local recommended_lane="${2:-}"
  local command=""

  if command="$(cfctl_surface_call_module "${surface}" "verify_command" 2>/dev/null)"; then
    command="${command%$'\n'}"
    printf '%s\n' "$(cfctl_command_with_lane_prefix "${recommended_lane}" "${command}")"
    return
  fi

  if cfctl_action_supported "${surface}" "verify"; then
    printf '%s\n' "$(cfctl_command_with_lane_prefix "${recommended_lane}" "$(cfctl_build_selector_verb_command "verify" "${surface}")")"
    return
  fi

  printf '\n'
}

cfctl_surface_prepare_sync_body() {
  local surface="$1"
  local spec_json="$2"
  local prepared=""

  if prepared="$(cfctl_surface_call_module "${surface}" "prepare_sync_body" "${spec_json}" 2>/dev/null)"; then
    printf '%s\n' "${prepared}"
    return
  fi

  jq '(.body // {})' <<< "${spec_json}"
}

cfctl_probe_permission() {
  local surface="$1"
  local action="$2"
  local operation="${3:-}"
  local requirement_json
  local requirement_error=""
  local spec
  local method
  local path
  local capture

  requirement_json="$(cfctl_requirement_check_json "${surface}" "${action}" "${operation}")"
  requirement_error="$(jq -r '.error // empty' <<< "${requirement_json}")"
  spec="$(cfctl_permission_spec_json "${surface}" "${action}" "${operation}")"
  method="$(jq -r '.method // empty' <<< "${spec}")"
  path="$(jq -r '.path // empty' <<< "${spec}")"

  if [[ -n "${requirement_error}" ]]; then
    jq -n \
      --arg permission_family "$(jq -r '.permission_family' <<< "${spec}")" \
      --arg basis "${requirement_error}" \
      --argjson selector_readiness "${requirement_json}" \
      '
        {
          state: "unknown",
          permission_family: $permission_family,
          basis: $basis,
          status_code: null,
          errors: [],
          request: null,
          selector_readiness: $selector_readiness
        }
      '
    return
  fi

  if [[ "$(jq -r '.ready' <<< "${requirement_json}")" != "true" ]]; then
    jq -n \
      --arg permission_family "$(jq -r '.permission_family' <<< "${spec}")" \
      --argjson selector_readiness "${requirement_json}" \
      '
        {
          state: "unknown",
          permission_family: $permission_family,
          basis: "selector_incomplete",
          status_code: null,
          errors: [],
          request: null,
          selector_readiness: $selector_readiness
        }
      '
    return
  fi

  if [[ -z "${method}" || -z "${path}" || "${path}" == *"{"* ]]; then
    jq -n \
      --arg permission_family "$(jq -r '.permission_family' <<< "${spec}")" \
      --arg inference "$(jq -r '.inference' <<< "${spec}")" \
      '
        {
          state: "unknown",
          permission_family: $permission_family,
          basis: $inference,
          status_code: null,
          errors: [],
          request: null
        }
      '
    return
  fi

  if [[ -z "${CF_ACTIVE_AUTH_SCHEME:-}" || -z "${CF_ACTIVE_AUTH_SECRET:-}" ]]; then
    jq -n \
      --arg permission_family "$(jq -r '.permission_family' <<< "${spec}")" \
      --argjson selector_readiness "${requirement_json}" \
      '
        {
          state: "unknown",
          permission_family: $permission_family,
          basis: "credential_missing",
          status_code: null,
          errors: [],
          request: null,
          selector_readiness: $selector_readiness
        }
      '
    return
  fi

  capture="$(cf_api_capture "${method}" "${path}")"
  jq -n \
    --arg permission_family "$(jq -r '.permission_family' <<< "${spec}")" \
    --arg inference "$(jq -r '.inference' <<< "${spec}")" \
    --argjson capture "${capture}" \
    '
      {
        state: (if ($capture.success // false) then "allowed" else "denied" end),
        permission_family: $permission_family,
        basis: $inference,
        status_code: ($capture.status_code // null),
        errors: ($capture.errors // []),
        request: ($capture.request // null)
      }
    '
}

cfctl_cleanup_runtime_context() {
  if [[ "${CFCTL_LOCK_RELEASE_ON_EXIT:-0}" == "1" && -n "${CFCTL_LOCK_KEY:-}" ]]; then
    cf_runtime_lock_release "${CFCTL_LOCK_KEY}"
  fi
}

cfctl_run_backend_script() {
  local script_path="$1"
  shift
  local output
  local status

  set +e
  output="$(env CF_RUNTIME_CALLER=cfctl CFCTL_OPERATION_ID="${CFCTL_OPERATION_ID:-}" "$@" "${script_path}" 2>&1)"
  status="$?"
  set -e

  CFCTL_BACKEND_STATUS="${status}"
  CFCTL_BACKEND_OUTPUT="${output}"
  CFCTL_BACKEND_ARTIFACT_PATH="$(printf '%s\n' "${output}" | tail -n 1)"
  if [[ ! -f "${CFCTL_BACKEND_ARTIFACT_PATH}" ]]; then
    CFCTL_BACKEND_ARTIFACT_PATH=""
    CFCTL_BACKEND_ARTIFACT_JSON="null"
  else
    CFCTL_BACKEND_ARTIFACT_JSON="$(cat "${CFCTL_BACKEND_ARTIFACT_PATH}")"
  fi
}

cfctl_collect_surface_items() {
  local surface="$1"
  local script_path=""

  CFCTL_COLLECT_BACKEND=""
  CFCTL_COLLECT_ITEMS_JSON="[]"
  CFCTL_COLLECT_ERROR_CODE=""
  CFCTL_COLLECT_ERROR_MESSAGE=""
  CFCTL_COLLECT_SOURCE_JSON="null"
  CFCTL_COLLECT_BACKEND_ARTIFACT_PATH=""

  case "${surface}" in
    zone)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_zones.sh"
      cfctl_run_backend_script "${script_path}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    pages.project)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_pages.sh"
      cfctl_run_backend_script "${script_path}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    worker.script)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_workers.sh"
      cfctl_run_backend_script "${script_path}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    worker.route)
      cfctl_resolve_zone_context
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_worker_routes.sh"
      cfctl_run_backend_script "${script_path}" "ZONE_NAME=${CFCTL_ZONE_NAME}" "ZONE_ID=${CFCTL_ZONE_ID}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    d1.database)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_d1.sh"
      cfctl_run_backend_script "${script_path}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    r2.bucket)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_r2.sh"
      cfctl_run_backend_script "${script_path}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    queue)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_queues.sh"
      cfctl_run_backend_script "${script_path}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    workflow)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_workflows.sh"
      cfctl_run_backend_script "${script_path}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    api_gateway.operation)
      cfctl_resolve_zone_context
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_api_gateway.sh"
      cfctl_run_backend_script "${script_path}" "ZONE_NAME=${CFCTL_ZONE_NAME}" "ZONE_ID=${CFCTL_ZONE_ID}" "API_GATEWAY_RESOURCE=operations"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    api_gateway.schema)
      cfctl_resolve_zone_context
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_api_gateway.sh"
      cfctl_run_backend_script "${script_path}" "ZONE_NAME=${CFCTL_ZONE_NAME}" "ZONE_ID=${CFCTL_ZONE_ID}" "API_GATEWAY_RESOURCE=schemas"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    api_gateway.discovery)
      cfctl_resolve_zone_context
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_api_gateway.sh"
      cfctl_run_backend_script "${script_path}" "ZONE_NAME=${CFCTL_ZONE_NAME}" "ZONE_ID=${CFCTL_ZONE_ID}" "API_GATEWAY_RESOURCE=discovery"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    vulnerability_scanner.scan)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_vulnerability_scanner.sh"
      cfctl_run_backend_script "${script_path}" "VULN_SCANNER_RESOURCE=scans"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    vulnerability_scanner.target_environment)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_vulnerability_scanner.sh"
      cfctl_run_backend_script "${script_path}" "VULN_SCANNER_RESOURCE=target_environments"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    vulnerability_scanner.credential_set)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_vulnerability_scanner.sh"
      cfctl_run_backend_script "${script_path}" "VULN_SCANNER_RESOURCE=credential_sets"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    access.app|access.policy)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_access.sh"
      cfctl_run_backend_script "${script_path}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    turnstile.widget)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_turnstile.sh"
      cfctl_run_backend_script "${script_path}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    dns.record)
      cfctl_resolve_zone_context
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_dns.sh"
      cfctl_run_backend_script "${script_path}" "ZONE_NAME=${CFCTL_ZONE_NAME}" "INCLUDE_RECORDS=${CFCTL_INCLUDE_RECORDS}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    waiting_room)
      cfctl_resolve_zone_context
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_waiting_rooms.sh"
      cfctl_run_backend_script "${script_path}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    edge.certificate)
      cfctl_resolve_zone_context
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_edge_certificates.sh"
      cfctl_run_backend_script "${script_path}" "ZONE_NAME=${CFCTL_ZONE_NAME}" "ZONE_ID=${CFCTL_ZONE_ID}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    audit.log)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_audit_logs.sh"
      cfctl_run_backend_script \
        "${script_path}" \
        "AUDIT_LOGS_SINCE=${CFCTL_SINCE}" \
        "AUDIT_LOGS_BEFORE=${CFCTL_BEFORE}" \
        "AUDIT_LOGS_ACTOR=${CFCTL_ACTOR}" \
        "AUDIT_LOGS_ACTION_TYPE=${CFCTL_ACTION_TYPE}" \
        "AUDIT_LOGS_RESOURCE_TYPE=${CFCTL_RESOURCE_TYPE}" \
        "AUDIT_LOGS_LIMIT=${CFCTL_LIMIT}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    logpush.job)
      cfctl_resolve_zone_context
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_logpush.sh"
      cfctl_run_backend_script "${script_path}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    tunnel)
      script_path="${CF_REPO_ROOT}/scripts/cf_inventory_tunnels.sh"
      cfctl_run_backend_script "${script_path}" "INCLUDE_CONFIG=${CFCTL_INCLUDE_CONFIG}"
      CFCTL_COLLECT_BACKEND="inventory_script"
      ;;
    *)
      CFCTL_COLLECT_ERROR_CODE="unsupported_surface"
      CFCTL_COLLECT_ERROR_MESSAGE="No backend collector registered for ${surface}"
      return
      ;;
  esac

  CFCTL_COLLECT_BACKEND_ARTIFACT_PATH="${CFCTL_BACKEND_ARTIFACT_PATH}"
  CFCTL_COLLECT_SOURCE_JSON="${CFCTL_BACKEND_ARTIFACT_JSON}"

  if [[ "${CFCTL_BACKEND_STATUS}" -ne 0 && "${CFCTL_BACKEND_ARTIFACT_PATH}" == "" ]]; then
    CFCTL_COLLECT_ERROR_CODE="execution_failed"
    CFCTL_COLLECT_ERROR_MESSAGE="${CFCTL_BACKEND_OUTPUT}"
    return
  fi

  case "${surface}" in
    zone)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.zones // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    pages.project)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.projects // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    worker.script)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.workers // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    worker.route)
      CFCTL_COLLECT_ITEMS_JSON="$(
        jq -c '
          . as $root
          | [
            (.routes.result // [])[]
            | . + {
                zone_id: $root.zone.id,
                zone_name: $root.zone.name,
                service: (.script // null)
              }
          ]
        ' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}"
      )"
      ;;
    d1.database)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.databases // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    r2.bucket)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.buckets // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    queue)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.queues // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    workflow)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.workflows // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    api_gateway.operation)
      CFCTL_COLLECT_ITEMS_JSON="$(
        jq -c '
          . as $root
          | [
            (.operations // [])[]
            | . + {
                zone_id: $root.zone.id,
                zone_name: $root.zone.name
              }
          ]
        ' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}"
      )"
      ;;
    api_gateway.schema|api_gateway.discovery)
      CFCTL_COLLECT_ITEMS_JSON="$(
        jq -c '
          . as $root
          | [
            (.schemas // [])[]
            | . + {
                zone_id: $root.zone.id,
                zone_name: $root.zone.name
              }
          ]
        ' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}"
      )"
      ;;
    vulnerability_scanner.scan)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.scans // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    vulnerability_scanner.target_environment)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.target_environments // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    vulnerability_scanner.credential_set)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.credential_sets // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    access.app)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.applications // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    access.policy)
      CFCTL_COLLECT_ITEMS_JSON="$(
        jq -c '
          [
            (.applications // [])[] as $app
            | ($app.policies // [])[]
            | . + {
                app_id: $app.id,
                app_name: $app.name,
                app_domain: $app.domain
              }
          ]
        ' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}"
      )"
      ;;
    turnstile.widget)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.widgets.result // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    dns.record)
      CFCTL_COLLECT_ITEMS_JSON="$(
        jq -c \
          --arg zone_id "${CFCTL_ZONE_ID}" \
          --arg zone_name "${CFCTL_ZONE_NAME}" \
          '
            [
              (.zones // [])[] as $zone
              | select($zone.id == $zone_id or $zone.name == $zone_name)
              | if ($zone.dns.success // false) then
                  ($zone.dns.records // [])[] | . + {zone_id: $zone.id, zone_name: $zone.name}
                else
                  empty
                end
            ]
          ' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}"
      )"
      ;;
    waiting_room)
      CFCTL_COLLECT_ITEMS_JSON="$(
        jq -c \
          --arg zone_id "${CFCTL_ZONE_ID}" \
          --arg zone_name "${CFCTL_ZONE_NAME}" \
          '
            [
              (.zones // [])[]
              | select(.zone.id == $zone_id or .zone.name == $zone_name)
              | . as $zone
              | ($zone.waiting_rooms.result // [])[]
              | . + {
                  zone_id: $zone.zone.id,
                  zone_name: $zone.zone.name
                }
            ]
          ' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}"
      )"
      ;;
    edge.certificate)
      CFCTL_COLLECT_ITEMS_JSON="$(
        jq -c \
          '
            . as $root
            | [
              (.certificate_packs.result // [])[]
              | . + {
                  zone_id: $root.zone.id,
                  zone_name: $root.zone.name
                }
            ]
          ' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}"
      )"
      ;;
    audit.log)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.events // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
    logpush.job)
      if [[ "${CFCTL_SCOPE}" == "zone" ]]; then
        CFCTL_COLLECT_ITEMS_JSON="$(
          jq -c \
            --arg zone_id "${CFCTL_ZONE_ID}" \
            --arg zone_name "${CFCTL_ZONE_NAME}" \
            '
              [
                (.zones // [])[]
                | select(.zone.id == $zone_id or .zone.name == $zone_name)
                | . as $zone
                | ($zone.jobs.result // [])[]
                | . + {
                    scope: "zone",
                    zone_id: $zone.zone.id,
                    zone_name: $zone.zone.name
                  }
              ]
            ' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}"
        )"
      else
        CFCTL_COLLECT_ITEMS_JSON="$(
          jq -c '
            [
              (.account_jobs.result // [])[]
              | . + {scope: "account"}
            ]
          ' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}"
        )"
      fi
      ;;
    tunnel)
      CFCTL_COLLECT_ITEMS_JSON="$(jq -c '.tunnels // []' <<< "${CFCTL_BACKEND_ARTIFACT_JSON}")"
      ;;
  esac
}

cfctl_filter_surface_items() {
  local surface="$1"
  local items_json="$2"

  case "${surface}" in
    zone)
      jq -c --arg id "${CFCTL_ID}" --arg name "${CFCTL_NAME}" '
        [
          .[]
          | select(
              (if $id != "" then .id == $id else true end)
              and
              (if $name != "" then .name == $name else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    pages.project)
      jq -c --arg id "${CFCTL_ID}" --arg name "${CFCTL_NAME}" --arg domain "${CFCTL_DOMAIN}" '
        [
          .[]
          | select(
              (if $id != "" then .id == $id else true end)
              and
              (if $name != "" then .name == $name else true end)
              and
              (if $domain != "" then any((.domains // [])[]?; . == $domain) else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    worker.script)
      jq -c --arg id "${CFCTL_ID}" --arg name "${CFCTL_NAME}" '
        [
          .[]
          | select(
              (if $id != "" then .id == $id else true end)
              and
              (if $name != "" then .id == $name else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    worker.route)
      jq -c --arg id "${CFCTL_ID}" --arg pattern "${CFCTL_PATTERN:-${CFCTL_NAME}}" --arg service "${CFCTL_SERVICE}" '
        [
          .[]
          | select(
              (if $id != "" then .id == $id else true end)
              and
              (if $pattern != "" then .pattern == $pattern else true end)
              and
              (if $service != "" then (.script // .service // "") == $service else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    d1.database)
      jq -c --arg id "${CFCTL_ID}" --arg name "${CFCTL_NAME}" '
        [
          .[]
          | select(
              (if $id != "" then .uuid == $id else true end)
              and
              (if $name != "" then .name == $name else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    r2.bucket)
      jq -c --arg name "${CFCTL_NAME}" '
        [
          .[]
          | select(if $name != "" then .name == $name else true end)
        ]
      ' <<< "${items_json}"
      ;;
    queue)
      jq -c --arg id "${CFCTL_ID}" --arg name "${CFCTL_NAME}" '
        [
          .[]
          | select(
              (if $id != "" then .queue_id == $id else true end)
              and
              (if $name != "" then .queue_name == $name else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    workflow)
      jq -c --arg id "${CFCTL_ID}" --arg name "${CFCTL_NAME}" '
        [
          .[]
          | select(
              (if $id != "" then .id == $id else true end)
              and
              (if $name != "" then .name == $name else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    api_gateway.operation)
      jq -c --arg id "${CFCTL_ID}" --arg endpoint "${CFCTL_NAME}" --arg domain "${CFCTL_DOMAIN}" --argjson hosts "${CFCTL_HOSTS_JSON}" '
        [
          .[]
          | select(
              (if $id != "" then ((.id // .operation_id // "") == $id) else true end)
              and
              (if $endpoint != "" then .endpoint == $endpoint else true end)
              and
              (if $domain != "" then .host == $domain else true end)
              and
              (if ($hosts | length) > 0 then (.host as $item_host | any($hosts[]; . == $item_host)) else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    api_gateway.schema|api_gateway.discovery)
      jq -c --arg id "${CFCTL_ID}" --arg name "${CFCTL_NAME}" --arg domain "${CFCTL_DOMAIN}" --argjson hosts "${CFCTL_HOSTS_JSON}" '
        [
          .[]
          | select(
              (if $id != "" then .id == $id else true end)
              and
              (if $name != "" then .title == $name else true end)
              and
              (if $domain != "" then .host == $domain else true end)
              and
              (if ($hosts | length) > 0 then (.host as $item_host | any($hosts[]; . == $item_host)) else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    vulnerability_scanner.scan)
      jq -c --arg id "${CFCTL_ID}" '
        [
          .[]
          | select(if $id != "" then .id == $id else true end)
        ]
      ' <<< "${items_json}"
      ;;
    vulnerability_scanner.target_environment|vulnerability_scanner.credential_set)
      jq -c --arg id "${CFCTL_ID}" --arg name "${CFCTL_NAME}" '
        [
          .[]
          | select(
              (if $id != "" then .id == $id else true end)
              and
              (if $name != "" then .name == $name else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    access.app)
      jq -c --arg id "${CFCTL_ID}" --arg name "${CFCTL_NAME}" --arg domain "${CFCTL_DOMAIN}" '
        [
          .[]
          | select(
              (if $id != "" then .id == $id else true end)
              and
              (if $name != "" then .name == $name else true end)
              and
              (if $domain != "" then .domain == $domain else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    access.policy)
      jq -c --arg app_id "${CFCTL_APP_ID}" --arg policy_id "${CFCTL_POLICY_ID:-${CFCTL_ID}}" --arg name "${CFCTL_NAME}" '
        [
          .[]
          | select(
              (if $app_id != "" then .app_id == $app_id else true end)
              and
              (if $policy_id != "" then .id == $policy_id else true end)
              and
              (if $name != "" then .name == $name else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    turnstile.widget)
      jq -c --arg sitekey "${CFCTL_SITEKEY:-${CFCTL_ID}}" --arg name "${CFCTL_NAME}" '
        [
          .[]
          | select(
              (if $sitekey != "" then .sitekey == $sitekey else true end)
              and
              (if $name != "" then .name == $name else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    dns.record)
      jq -c --arg id "${CFCTL_ID}" --arg name "${CFCTL_NAME}" --arg type "${CFCTL_TYPE}" '
        [
          .[]
          | select(
              (if $id != "" then .id == $id else true end)
              and
              (if $name != "" then .name == $name else true end)
              and
              (if $type != "" then .type == $type else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    waiting_room)
      jq -c --arg id "${CFCTL_ID}" --arg name "${CFCTL_NAME}" '
        [
          .[]
          | select(
              (if $id != "" then .id == $id else true end)
              and
              (if $name != "" then .name == $name else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    edge.certificate)
      jq -c --arg id "${CFCTL_ID}" --argjson hosts "${CFCTL_HOSTS_JSON}" '
        [
          .[]
          | (.hosts // []) as $item_hosts
          | select(
              (if $id != "" then .id == $id else true end)
              and
              (if ($hosts | length) > 0 then all($hosts[]; . as $host | $item_hosts | index($host) != null) else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    audit.log)
      jq -c \
        --arg id "${CFCTL_ID}" \
        --arg actor "${CFCTL_ACTOR}" \
        --arg action_type "${CFCTL_ACTION_TYPE}" \
        --arg resource_type "${CFCTL_RESOURCE_TYPE}" \
        '
          [
            .[]
            | select(
                (if $id != "" then .id == $id else true end)
                and
                (if $actor != "" then ((.actor.email // .actor.id // .actor.name // "") == $actor) else true end)
                and
                (if $action_type != "" then ((.action.type // .action // "") == $action_type) else true end)
                and
                (if $resource_type != "" then ((.resource.type // .resource_type // "") == $resource_type) else true end)
              )
          ]
        ' <<< "${items_json}"
      ;;
    logpush.job)
      jq -c --arg id "${CFCTL_JOB_ID:-${CFCTL_ID}}" --arg name "${CFCTL_NAME}" '
        [
          .[]
          | select(
              (if $id != "" then ((.id | tostring) == $id) else true end)
              and
              (if $name != "" then ((.name // "") == $name) else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    tunnel)
      jq -c --arg id "${CFCTL_TUNNEL_ID:-${CFCTL_ID}}" --arg name "${CFCTL_NAME}" '
        [
          .[]
          | select(
              (if $id != "" then .id == $id else true end)
              and
              (if $name != "" then .name == $name else true end)
            )
        ]
      ' <<< "${items_json}"
      ;;
    *)
      printf '%s\n' "${items_json}"
      ;;
  esac
}

cfctl_summary_for_items() {
  local surface="$1"
  local items_json="$2"
  local name_field="name"

  case "${surface}" in
    worker.script) name_field="id" ;;
    worker.route) name_field="pattern" ;;
    d1.database) name_field="name" ;;
    r2.bucket) name_field="name" ;;
    queue) name_field="queue_name" ;;
    tunnel) name_field="name" ;;
    turnstile.widget) name_field="name" ;;
    access.policy) name_field="name" ;;
    api_gateway.operation) name_field="endpoint" ;;
    api_gateway.schema|api_gateway.discovery) name_field="host" ;;
    audit.log) name_field="id" ;;
    vulnerability_scanner.scan) name_field="id" ;;
    vulnerability_scanner.target_environment|vulnerability_scanner.credential_set) name_field="name" ;;
  esac

  jq -n \
    --arg surface "${surface}" \
    --arg name_field "${name_field}" \
    --argjson items "${items_json}" \
    '
      {
        surface: $surface,
        count: ($items | length),
        sample_names: (
          $items
          | map(.[$name_field] // .id // .uuid // .queue_id // .sitekey // null)
          | map(select(. != null))
          | .[:10]
        )
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

  runtime_file="$(cf_inventory_file "runtime" "$(cfctl_slugify "${action}-${surface}")")"
  target_json="$(cfctl_target_json)"

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
      --argjson ok "${ok}" \
      --argjson performed "${performed}" \
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
