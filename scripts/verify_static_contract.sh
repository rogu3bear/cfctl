#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${ROOT_DIR}"

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required tool: $1" >&2
    exit 1
  }
}

die() {
  echo "static-contract verification failed: $*" >&2
  exit 1
}

assert_jq_file() {
  local label="$1"
  local expr="$2"
  local file="$3"

  jq -e "${expr}" "${file}" >/dev/null || die "${label}: assertion failed for ${file}: ${expr}"
}

assert_cross_catalog_empty() {
  local label="$1"
  local expr="$2"
  local failures

  failures="$(
    jq -c -n \
      --slurpfile runtime "${ROOT_DIR}/catalog/runtime.json" \
      --slurpfile surfaces "${ROOT_DIR}/catalog/surfaces.json" \
      --slurpfile standards "${ROOT_DIR}/catalog/standards.json" \
      --slurpfile docs "${ROOT_DIR}/catalog/cloudflare-doc-bank.json" \
      --slurpfile ownership "${ROOT_DIR}/state/ownership/resources.json" \
      "${expr}"
  )"

  if ! jq -e 'length == 0' <<< "${failures}" >/dev/null; then
    die "${label}: ${failures}"
  fi
}

assert_contains() {
  local label="$1"
  local needle="$2"
  local file="$3"

  if ! grep -Fq -- "${needle}" "${file}"; then
    die "${label}: expected to find '${needle}' in ${file}"
  fi
}

assert_not_contains() {
  local label="$1"
  local needle="$2"
  local file="$3"

  if grep -Fq -- "${needle}" "${file}"; then
    die "${label}: unexpected stale text '${needle}' in ${file}"
  fi
}

assert_not_has_line() {
  local label="$1"
  local regex="$2"
  local file="$3"

  if command -v rg >/dev/null 2>&1; then
    if rg -n "${regex}" "${file}" >/dev/null; then
      die "${label}: unexpected matching line ${regex} in ${file}"
    fi
  elif grep -En "${regex}" "${file}" >/dev/null; then
    die "${label}: unexpected matching line ${regex} in ${file}"
  fi
}

require_tool jq
require_tool python3

bash -n \
  "${ROOT_DIR}/cfctl" \
  "${ROOT_DIR}/commands/cfctl.sh" \
  "${ROOT_DIR}/lib/runtime/cfctl.sh" \
  "${ROOT_DIR}/lib/runtime/desired_state.sh" \
  "${ROOT_DIR}/scripts/lib/cfctl.sh" \
  "${ROOT_DIR}/scripts/lib/cloudflare.sh" \
  "${ROOT_DIR}/scripts/cf_wrangler.sh" \
  "${ROOT_DIR}/scripts/cf_cloudflared.sh" \
  "${ROOT_DIR}/scripts/cf_token_revoke.sh" \
  "${ROOT_DIR}/scripts/verify_access_login_method_contract.sh" \
  "${ROOT_DIR}/scripts/verify_maildesk_cf_contract.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_access_login_methods.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_audit_logs.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_api_gateway.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_vulnerability_scanner.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_worker_routes.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_email_routing_rules.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_sender_domains.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_edge_certificates.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_zone_settings.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_security_txt.sh" \
  "${ROOT_DIR}/scripts/cf_mutate_access_login_method.sh" \
  "${ROOT_DIR}/scripts/cf_mutate_email_routing_rule.sh" \
  "${ROOT_DIR}/scripts/cf_mutate_edge_certificate.sh" \
  "${ROOT_DIR}/scripts/cf_mutate_worker_route.sh" \
  "${ROOT_DIR}/scripts/cf_mutate_zone_setting.sh" \
  "${ROOT_DIR}/scripts/cf_mutate_security_txt.sh" \
  "${ROOT_DIR}/scripts/cf_mutate_zone_ruleset.sh" \
  "${ROOT_DIR}/scripts/verify_public_contract.sh" \
  "${ROOT_DIR}/scripts/verify_static_contract.sh"
for surface_module in \
  "${ROOT_DIR}/lib/surfaces/access_app.sh" \
  "${ROOT_DIR}/lib/surfaces/access_login_method.sh" \
  "${ROOT_DIR}/lib/surfaces/access_policy.sh" \
  "${ROOT_DIR}/lib/surfaces/dns_record.sh" \
  "${ROOT_DIR}/lib/surfaces/edge_certificate.sh" \
  "${ROOT_DIR}/lib/surfaces/security_txt.sh" \
  "${ROOT_DIR}/lib/surfaces/zone_setting.sh" \
  "${ROOT_DIR}/lib/surfaces/worker_route.sh" \
  "${ROOT_DIR}/lib/surfaces/tunnel.sh"; do
  bash -n "${surface_module}"
done

python3 "${ROOT_DIR}/scripts/render_capabilities_doc.py" --check "${ROOT_DIR}/docs/capabilities.md" >/dev/null
python3 "${ROOT_DIR}/scripts/verify_permission_catalog.py" >/dev/null
python3 -m py_compile "${ROOT_DIR}/scripts/cf_maildesk_cf_lifecycle.py"
"${ROOT_DIR}/scripts/verify_access_login_method_contract.sh" >/dev/null
"${ROOT_DIR}/scripts/verify_maildesk_cf_contract.sh" >/dev/null

set +e
doctor_bootstrap_json="$(
  env \
    -u CF_DEV_TOKEN \
    -u CF_GLOBAL_TOKEN \
    -u CLOUDFLARE_API_TOKEN \
    -u CLOUDFLARE_ACCOUNT_ID \
    CF_SHARED_ENV_FILE="/nonexistent/cfctl-empty-env" \
    CF_REPO_ENV_FILE="/nonexistent/cfctl-empty-env" \
    "${ROOT_DIR}/cfctl" doctor
)"
doctor_bootstrap_status=$?
set -e
if [[ -z "${doctor_bootstrap_json}" ]]; then
  die "doctor no-auth lane posture produced no JSON"
fi
jq -e '
  .action == "doctor"
  and .summary.configured_lane_count == 0
  and (.result.lanes.summary.configured_lane_count // 0) == 0
  and all(.result.lanes.lanes[]; .available == false and .error == "credential_missing")
  and (
    (
      .ok == true
      and .summary.status == "bootstrap_required"
      and (.summary.safe_next_steps | index("cfctl bootstrap permissions")) != null
    )
    or
    (
      .ok == false
      and .summary.status == "unsafe"
      and .error.code == "runtime_health_failed"
      and (
        ((.summary.secret_leak_count // 0) > 0)
        or ((.summary.unsafe_secret_sink_count // 0) > 0)
        or ((.summary.missing_backend_guards // 0) > 0)
        or ((.summary.registry_policy_gaps // 0) > 0)
        or (.summary.legacy_bypass_active == true)
      )
    )
  )
' <<< "${doctor_bootstrap_json}" >/dev/null || die "doctor no-auth lane posture assertion failed"
if jq -e '.ok == true' <<< "${doctor_bootstrap_json}" >/dev/null; then
  [[ "${doctor_bootstrap_status}" -eq 0 ]] || die "doctor bootstrap posture returned non-zero for ok response"
else
  [[ "${doctor_bootstrap_status}" -ne 0 ]] || die "doctor unsafe posture returned zero for failed response"
fi

can_bootstrap_json="$(
  env \
    -u CF_DEV_TOKEN \
    -u CF_GLOBAL_TOKEN \
    -u CLOUDFLARE_API_TOKEN \
    -u CLOUDFLARE_ACCOUNT_ID \
    CF_SHARED_ENV_FILE="/nonexistent/cfctl-empty-env" \
    CF_REPO_ENV_FILE="/nonexistent/cfctl-empty-env" \
    "${ROOT_DIR}/cfctl" can email.routing_rule --zone example.com
)"
jq -e '
  .ok == true
  and .action == "can"
  and .surface == "email.routing_rule"
  and .operation == "can"
  and .target.zone == "example.com"
  and .permission_status.basis == "credential_missing"
  and .permission_status.selector_readiness.ready == true
' <<< "${can_bootstrap_json}" >/dev/null || die "can no-auth surface posture assertion failed"

can_upsert_bootstrap_json="$(
  env \
    -u CF_DEV_TOKEN \
    -u CF_GLOBAL_TOKEN \
    -u CLOUDFLARE_API_TOKEN \
    -u CLOUDFLARE_ACCOUNT_ID \
    CF_SHARED_ENV_FILE="/nonexistent/cfctl-empty-env" \
    CF_REPO_ENV_FILE="/nonexistent/cfctl-empty-env" \
    "${ROOT_DIR}/cfctl" can email.routing_rule upsert --zone example.com --name role@example.com --service maildesk-cf-router
)"
jq -e '
  .ok == true
  and .action == "can"
  and .surface == "email.routing_rule"
  and .operation == "upsert"
  and .target.zone == "example.com"
  and .target.name == "role@example.com"
  and .target.service == "maildesk-cf-router"
  and .permission_status.basis == "credential_missing"
  and .permission_status.selector_readiness.ready == true
' <<< "${can_upsert_bootstrap_json}" >/dev/null || die "can no-auth upsert posture assertion failed"

email_routing_zone_guidance_json="$(
  ROOT_DIR="${ROOT_DIR}" bash <<'BASH'
set -euo pipefail
# shellcheck disable=SC1091
source "${ROOT_DIR}/lib/runtime/cfctl.sh"
# shellcheck disable=SC1091
source "${ROOT_DIR}/commands/cfctl.sh"

cfctl_compare_permission_all_lanes() {
  jq -n '
    {
      active_lane: "dev",
      lanes: [
        {
          lane: "dev",
          available: true,
          permission: {
            state: "unknown",
            basis: "zone_resolution_failed",
            errors: [],
            request: null,
            status_code: null,
            permission_family: "Email Routing Write"
          }
        },
        {
          lane: "global",
          available: true,
          permission: {
            state: "allowed",
            basis: "surface_read_probe",
            errors: [],
            request: {},
            status_code: 200,
            permission_family: "Email Routing Write"
          }
        }
      ],
      summary: {
        allowed_lanes: ["global"],
        denied_lanes: [],
        unknown_lanes: ["dev"]
      }
    }
  '
}

cfctl_reset_flags
CF_ACTIVE_TOKEN_LANE="dev"
CFCTL_ZONE_NAME="example.com"
CFCTL_NAME="role@example.com"
CFCTL_SERVICE="maildesk-cf-router"
permission_json='{"state":"unknown","basis":"zone_resolution_failed","errors":[],"request":null,"status_code":null,"permission_family":"Email Routing Write"}'
cfctl_failure_guidance_json "apply" "email.routing_rule" "mutation_script" "${permission_json}" "execution_failed" "Mutation backend returned a failure" "upsert"
BASH
)"
jq -e '
  .recommended_lane == "global"
  and (.next_step | type == "string" and contains("zone"))
  and (.recommended_command | startswith("CF_TOKEN_LANE=global cfctl apply email.routing_rule upsert "))
  and (.recommended_command | contains("--zone example.com"))
  and (.recommended_command | contains("--name role@example.com"))
  and (.recommended_command | contains("--service maildesk-cf-router"))
  and (.recommended_command | contains("--plan"))
' <<< "${email_routing_zone_guidance_json}" >/dev/null || die "email routing zone resolution lane guidance assertion failed"

assert_jq_file "permission profile minimality policy" '
  .profiles.read.allowed_surfaces != null
  and (.profiles.read.allowed_surfaces | index("audit.log")) != null
  and (.profiles.read.forbidden_permissions | index("* Write")) != null
  and (.profiles["security-audit"].forbidden_permissions | index("* Write")) != null
  and (.profiles["security-audit"].allowed_surfaces | index("audit.log")) != null
  and .profiles.dns.allowed_surfaces == ["dns.record", "zone"]
  and (.profiles.hostname.allowed_surfaces | index("edge.certificate")) != null
  and (.profiles.hostname.allowed_surfaces | index("zone.setting")) != null
  and (.profiles.read.allowed_surfaces | index("zone.setting")) != null
  and (.profiles["security-audit"].allowed_surfaces | index("zone.setting")) != null
  and (.permissions[] | select(.name == "Zone Settings Read" and .scope == "zone" and (.surfaces | index("zone.setting")) != null))
  and (.permissions[] | select(.name == "Zone Settings Write" and .scope == "zone" and (.profiles | index("hostname")) != null))
  and (.profiles.deploy.allowed_surfaces | index("audit.log")) != null
  and (.profiles.deploy.allowed_surfaces | index("wrangler")) != null
  and .profiles["full-operator"].allowed_surfaces == ["*"]
  and (.profiles["full-operator"].forbidden_permissions | index("Account API Tokens *")) != null
' "${ROOT_DIR}/catalog/permissions.json"
assert_jq_file "runtime public verbs" '(.public_verbs | index("docs")) != null and (.public_verbs | index("env")) != null and (.public_verbs | index("wrangler")) != null and (.public_verbs | index("cloudflared")) != null and (.public_verbs | index("hostname")) != null and (.public_verbs | index("maildesk-cf")) != null and (.public_verbs | index("ownership")) != null and (.landing_flow | index("ownership check")) != null and (.landing_flow | index("docs")) != null' "${ROOT_DIR}/catalog/runtime.json"
assert_jq_file "runtime env run policy" '
  .env_run.default_lane == "dev"
  and .env_run.requires_argv_separator == true
  and .env_run.shell_eval_allowed == false
  and .env_run.redact_child_output == true
  and (.env_run.stripped_child_env | index("CF_DEV_TOKEN")) != null
  and (.env_run.stripped_child_env | index("CF_ACTIVE_AUTH_SECRET")) != null
' "${ROOT_DIR}/catalog/runtime.json"
assert_jq_file "runtime backend guard catalog" '
  .policy.backend_guard_scripts == ["scripts/cf_api_apply.sh"]
  and .policy.special_operations["token.mint"].backend_script == "scripts/cf_token_mint.sh"
  and .policy.special_operations["token.revoke"].backend_script == "scripts/cf_token_revoke.sh"
' "${ROOT_DIR}/catalog/runtime.json"
assert_jq_file "runtime ownership registry catalog" '
  .ownership_registry.path == "state/ownership/resources.json"
  and .ownership_registry.duplicate_resource_policy == "fail"
  and (.ownership_registry.proof_classes | index("source_config")) != null
  and (.ownership_registry.proof_classes | index("live_control_plane_read")) != null
  and (.ownership_registry.proof_classes | index("preview_artifact")) != null
  and (.ownership_registry.proof_classes | index("apply_artifact")) != null
  and (.ownership_registry.proof_classes | index("post_change_verification")) != null
' "${ROOT_DIR}/catalog/runtime.json"
assert_jq_file "tool wrapper metadata" '
  .tool_wrappers.wrangler.script == "scripts/cf_wrangler.sh"
  and .tool_wrappers.wrangler.backend == "wrangler"
  and (.tool_wrappers.wrangler.default_args | index("whoami")) != null
  and (.tool_wrappers.wrangler.read_only_prefixes | map(join(" ")) | index("whoami")) != null
  and .tool_wrappers.cloudflared.script == "scripts/cf_cloudflared.sh"
  and .tool_wrappers.cloudflared.backend == "cloudflared"
  and (.tool_wrappers.cloudflared.default_args | index("version")) != null
  and (.tool_wrappers.cloudflared.read_only_prefixes | map(join(" ")) | index("tunnel list")) != null
  and (.tool_wrappers.cloudflared.read_only_prefixes | map(join(" ")) | index("tunnel token")) == null
' "${ROOT_DIR}/catalog/runtime.json"
assert_jq_file "docs bank shape" '.checked_on != null and .refresh_policy.refresh_interval_days > 0 and (.foundation | length) > 0 and (.watch | length) > 0' "${ROOT_DIR}/catalog/cloudflare-doc-bank.json"
assert_jq_file "docs bank api gateway topic" '(.foundation | any(.id == "api-gateway")) and (.foundation | any(.id == "audit-logs")) and (.watch | any(.id == "api-shield-vulnerability-scanner"))' "${ROOT_DIR}/catalog/cloudflare-doc-bank.json"
assert_jq_file "standards shape" '(.universal | length) > 0 and (.surfaces | keys | length) > 0' "${ROOT_DIR}/catalog/standards.json"
assert_jq_file "compatibility freshness thresholds" '.audit.compatibility_date_freshness.note_after_days == 30 and .audit.compatibility_date_freshness.warning_after_days == 90' "${ROOT_DIR}/catalog/standards.json"
assert_jq_file "standards audit source-context tokens" '
  (.audit.noncanonical_path_tokens | map(.token) | index("/worktrees/")) != null
  and (.audit.noncanonical_path_tokens | map(.token) | index("-deploy-dryrun/")) != null
  and (.audit.noncanonical_path_tokens | map(.token) | index("-main-asset-baseline/")) != null
' "${ROOT_DIR}/catalog/standards.json"
assert_jq_file "surface registry shape" '(.surfaces | keys | length) > 0' "${ROOT_DIR}/catalog/surfaces.json"
assert_jq_file "ownership registry shape" '
  .version == 1
  and (.resources | type == "array")
  and (.resources | length) > 0
' "${ROOT_DIR}/state/ownership/resources.json"
assert_cross_catalog_empty "ownership resource ids are unique" '
  [
    ($ownership[0].resources // [])
    | group_by(.id)
    | .[]?
    | select(length > 1)
    | {id: .[0].id, duplicate_count: length}
  ]
'
assert_cross_catalog_empty "ownership resource keys are unique" '
  [
    ($ownership[0].resources // [])
    | group_by(.resource_key)
    | .[]?
    | select(length > 1)
    | {resource_key: .[0].resource_key, owners: map(.owner)}
  ]
'
assert_cross_catalog_empty "ownership resources are complete" '
  ($runtime[0].ownership_registry.proof_classes // []) as $proof_classes
  | [
      ($ownership[0].resources // [])[] as $entry
      | $entry
      | select(
          (.id // "") == ""
          or (.resource_key // "") == ""
          or (.resource.cloudflare_surface // "") == ""
          or (.owner.system // "") == ""
          or (.owner.repo // "") == ""
          or (.deploy_lane.default // "") == ""
          or ((.secrets.env // []) | length) == 0
          or (.authority.control_plane // "") != "cfctl"
          or ((.authority.allowed_change_commands // []) | length) == 0
          or (.authority.verifier // "") == ""
          or (($proof_classes | index($entry.authority.proof_class // "")) == null)
          or (.incident_runbook // "") == ""
        )
      | {resource: (.id // null), issue: "incomplete_ownership_entry"}
    ]
'
assert_cross_catalog_empty "ownership surfaces resolve" '
  ($surfaces[0].surfaces // {}) as $surface_catalog
  | ($runtime[0].desired_state // {}) as $desired_state
  | [
      ($ownership[0].resources // [])[]
      | .resource.cloudflare_surface as $surface
      | select($surface_catalog[$surface] == null and $desired_state[$surface] == null)
      | {resource: .id, missing_surface: $surface}
    ]
'
assert_cross_catalog_empty "ownership command path is cfctl" '
  [
    ($ownership[0].resources // [])[] as $entry
    | $entry.id as $id
    | (
        ($entry.authority.allowed_change_commands // [])[]
        | select(test("^(CF_TOKEN_LANE=[a-z]+ )?(\\./)?cfctl ") | not)
        | {resource: $id, invalid_change_command: .}
      ),
      (
        ($entry.authority.verifier // "")
        | select(test("^(CF_TOKEN_LANE=[a-z]+ )?(\\./)?cfctl ") | not)
        | {resource: $id, invalid_verifier: .}
      )
    ]
'
assert_cross_catalog_empty "ownership repo ids are portable" '
  [
    ($ownership[0].resources // [])[]
    | select((.owner.repo // "") | test("^/|^~|/Users/"))
    | {resource: .id, repo: .owner.repo}
  ]
'
ownership_check_json="$(
  env \
    -u CF_DEV_TOKEN \
    -u CF_GLOBAL_TOKEN \
    -u CLOUDFLARE_API_TOKEN \
    -u CLOUDFLARE_ACCOUNT_ID \
    CF_SHARED_ENV_FILE="/nonexistent/cfctl-empty-env" \
    CF_REPO_ENV_FILE="/nonexistent/cfctl-empty-env" \
    "${ROOT_DIR}/cfctl" ownership check
)"
jq -e '
  .ok == true
  and .action == "ownership"
  and .surface == "ownership"
  and .operation == "check"
  and .summary.issue_count == 0
  and .result.resource_count > 0
  and (.result.proof_classes | index("post_change_verification")) != null
' <<< "${ownership_check_json}" >/dev/null || die "ownership check envelope assertion failed"
ownership_get_json="$(
  env \
    -u CF_DEV_TOKEN \
    -u CF_GLOBAL_TOKEN \
    -u CLOUDFLARE_API_TOKEN \
    -u CLOUDFLARE_ACCOUNT_ID \
    CF_SHARED_ENV_FILE="/nonexistent/cfctl-empty-env" \
    CF_REPO_ENV_FILE="/nonexistent/cfctl-empty-env" \
    "${ROOT_DIR}/cfctl" ownership get --resource-key "cloudflare:dns.record:*"
)"
jq -e '
  .ok == true
  and .action == "ownership"
  and .surface == "ownership"
  and .operation == "get"
  and .summary.resource_key == "cloudflare:dns.record:*"
  and .result.resource.resource.cloudflare_surface == "dns.record"
  and .result.resource.authority.control_plane == "cfctl"
' <<< "${ownership_get_json}" >/dev/null || die "ownership get envelope assertion failed"

lane_precedence_dir="$(mktemp -d "${TMPDIR:-/tmp}/cfctl-lane-precedence.XXXXXX")"
cleanup_lane_precedence_dir() {
  local base
  if [[ -z "${lane_precedence_dir:-}" || ! -d "${lane_precedence_dir}" ]]; then
    return
  fi
  base="$(basename "${lane_precedence_dir}")"
  if [[ "${base}" != cfctl-lane-precedence.* || "${lane_precedence_dir}" == "${ROOT_DIR}" || "${lane_precedence_dir}" == "${ROOT_DIR}/"* ]]; then
    printf 'refusing to remove unexpected lane precedence temp dir: %s\n' "${lane_precedence_dir}" >&2
    return 1
  fi
  rm -rf -- "${lane_precedence_dir}"
}
trap cleanup_lane_precedence_dir EXIT
lane_precedence_shared_env="${lane_precedence_dir}/shared.env"
lane_precedence_repo_env="${lane_precedence_dir}/repo.env"
printf '%s\n' \
  'CF_DEV_TOKEN=dev-token' \
  'CF_GLOBAL_TOKEN=global-token' \
  'CLOUDFLARE_EMAIL=operator@example.com' \
  'CF_TOKEN_LANE=dev' \
  > "${lane_precedence_shared_env}"
printf '%s\n' \
  'CLOUDFLARE_ACCOUNT_ID=account-id' \
  > "${lane_precedence_repo_env}"
lane_precedence_json="$(
  env \
    CF_TOKEN_LANE=global \
    CF_SHARED_ENV_FILE="${lane_precedence_shared_env}" \
    CF_REPO_ENV_FILE="${lane_precedence_repo_env}" \
    bash -c 'source "$1"; cf_load_cloudflare_env; cf_current_auth_state_json' bash "${ROOT_DIR}/scripts/lib/cloudflare.sh"
)"
jq -e '
  .CF_TOKEN_LANE == "global"
  and .CF_ACTIVE_TOKEN_ENV == "CF_GLOBAL_TOKEN"
  and .CF_ACTIVE_AUTH_SCHEME == "global_api_key"
' <<< "${lane_precedence_json}" >/dev/null || die "explicit CF_TOKEN_LANE was not preserved over env files"

env_run_shared_env="${lane_precedence_dir}/env-run.env"
printf '%s\n' \
  'CF_DEV_TOKEN=dev-token-for-env-run-static-test' \
  'CLOUDFLARE_ACCOUNT_ID=account-id' \
  > "${env_run_shared_env}"
env_run_output="$(
  env \
    -u CF_GLOBAL_TOKEN \
    -u CLOUDFLARE_API_TOKEN \
    CF_SHARED_ENV_FILE="${env_run_shared_env}" \
    CF_REPO_ENV_FILE="/nonexistent/cfctl-empty-env" \
      "${ROOT_DIR}/cfctl" env run --lane dev -- env
)"
env_run_help_output="$("${ROOT_DIR}/cfctl" env run --help)"
env_run_json="$(awk 'found { print } /^\{$/ { found=1; print }' <<< "${env_run_output}")"
grep -Fq 'cfctl env run [--lane dev|global] -- <command> [args...]' <<< "${env_run_help_output}" || die "env run help missing usage"
grep -Fq 'do not pass secrets as command args' <<< "${env_run_help_output}" || die "env run help missing argv secrecy warning"
grep -Fq 'CLOUDFLARE_API_TOKEN=[redacted]' <<< "${env_run_output}" || die "env run did not prove redacted child CLOUDFLARE_API_TOKEN"
if grep -Fq 'dev-token-for-env-run-static-test' <<< "${env_run_output}"; then
  die "env run leaked token value"
fi
if grep -Eq '^CF_DEV_TOKEN=' <<< "${env_run_output}"; then
  die "env run exposed parent CF_DEV_TOKEN to child env"
fi
jq -e '
  .ok == true
  and .action == "env"
  and .surface == "runtime"
  and .operation == "run"
  and .summary.lane == "dev"
  and .summary.exported_child_auth_env == "CLOUDFLARE_API_TOKEN"
  and .summary.child_output_redacted == true
  and .result.secret_policy.token_values_in_artifact == false
  and .result.secret_policy.shell_eval_allowed == false
	' <<< "${env_run_json}" >/dev/null || die "env run artifact assertion failed"
assert_contains "secret scan bearer requires token value" "Authorization: Bearer [A-Za-z0-9._~+/=-]{8,}" "${ROOT_DIR}/commands/cfctl.sh"
assert_contains "secret scan auth key requires token value" "X-Auth-Key: [A-Za-z0-9._~+/=-]{8,}" "${ROOT_DIR}/commands/cfctl.sh"

assert_cross_catalog_empty "surface docs topics resolve to docs bank" '
  (
    ["foundation", "watch"]
    + (($docs[0].foundation // []) | map(.id))
    + (($docs[0].watch // []) | map(.id))
    | unique
  ) as $known_topics
  | [
      ($surfaces[0].surfaces // {})
      | to_entries[]
      | .key as $surface
      | (.value.docs_topics // [])[]?
      | select(($known_topics | index(.)) == null)
      | {surface: $surface, missing_docs_topic: .}
    ]
'
assert_cross_catalog_empty "docs bank topic ids are unique" '
  [
    (($docs[0].foundation // []) + ($docs[0].watch // []))
    | group_by(.id)
    | .[]?
    | select(length > 1)
    | {docs_topic: .[0].id, duplicate_count: length}
  ]
'
assert_cross_catalog_empty "surface standards refs resolve to standards catalog" '
  ($standards[0].surfaces // {}) as $standards_surfaces
  | [
      ($surfaces[0].surfaces // {})
      | to_entries[]
      | select((.value.standards_ref // "") != "")
      | select($standards_surfaces[.value.standards_ref] == null)
      | {surface: .key, missing_standards_ref: .value.standards_ref}
    ]
'
assert_cross_catalog_empty "desired-state surfaces resolve to public surface catalog" '
  ($surfaces[0].surfaces // {}) as $surface_catalog
  | [
      ($runtime[0].desired_state // {})
      | to_entries[]
      | select((.key | IN("hostname")) | not)
      | select($surface_catalog[.key] == null)
      | {desired_state_surface: .key, issue: "missing_surface_catalog_entry"}
    ]
'
assert_cross_catalog_empty "desired-state state dirs are unique" '
  [
    ($runtime[0].desired_state // {})
    | to_entries
    | group_by(.value.state_dir)
    | .[]?
    | select(length > 1)
    | {state_dir: .[0].value.state_dir, surfaces: map(.key)}
  ]
'
assert_cross_catalog_empty "cataloged backend guard scripts are unique" '
  [
    (
      [
        ($runtime[0].policy.backend_guard_scripts // [])[],
        (
          ($runtime[0].policy.special_operations // {})
          | to_entries[]
          | .value.backend_script // empty
        ),
        (
          ($surfaces[0].surfaces // {})
          | to_entries[]
          | select(.value.actions.apply.supported == true)
          | .value.apply_script // empty
        )
      ]
    )
    | group_by(.)
    | .[]?
    | select(length > 1)
    | {backend_script: .[0], duplicate_count: length}
  ]
'
assert_cross_catalog_empty "cataloged writable surfaces declare backend scripts" '
  [
    ($surfaces[0].surfaces // {})
    | to_entries[]
    | select(.value.actions.apply.supported == true)
    | select((.value.apply_script // "") == "")
    | {surface: .key, issue: "missing_apply_script"}
  ]
'
while IFS=$'\t' read -r source_key backend_script; do
  [[ -n "${source_key}" ]] || continue
  [[ -f "${ROOT_DIR}/${backend_script}" ]] || die "cataloged backend script ${source_key}: missing ${backend_script}"
  if command -v rg >/dev/null 2>&1; then
    rg -q 'cf_require_backend_dispatch' "${ROOT_DIR}/${backend_script}" || die "cataloged backend script ${source_key}: ${backend_script} lacks cf_require_backend_dispatch"
  else
    grep -q 'cf_require_backend_dispatch' "${ROOT_DIR}/${backend_script}" || die "cataloged backend script ${source_key}: ${backend_script} lacks cf_require_backend_dispatch"
  fi
done < <(
  jq -r -n \
    --slurpfile runtime "${ROOT_DIR}/catalog/runtime.json" \
    --slurpfile surfaces "${ROOT_DIR}/catalog/surfaces.json" \
    '
      (
        [
          ($runtime[0].policy.backend_guard_scripts // [])[]
          | ["runtime.backend_guard_scripts", .]
        ]
        + [
          ($runtime[0].policy.special_operations // {})
          | to_entries[]
          | select((.value.backend_script // "") != "")
          | ["runtime.special_operations." + .key, .value.backend_script]
        ]
        + [
          ($surfaces[0].surfaces // {})
          | to_entries[]
          | select(.value.actions.apply.supported == true)
          | [.key, .value.apply_script]
        ]
      )
      | .[]
      | @tsv
    '
)
while IFS= read -r state_dir; do
  [[ -n "${state_dir}" ]] || continue
  [[ -d "${ROOT_DIR}/${state_dir}" ]] || die "desired-state state_dir missing: ${state_dir}"
done < <(
  jq -r '
    (.desired_state // {})
    | to_entries[]
    | .value.state_dir // empty
  ' "${ROOT_DIR}/catalog/runtime.json"
)
assert_jq_file "zone setting desired state" '
  .desired_state["zone.setting"].supported == true
  and .desired_state["zone.setting"].sync_supported == true
  and .desired_state["zone.setting"].state_dir == "state/zone.setting"
  and .desired_state["zone.setting"].match_selectors == ["zone", "id", "name"]
' "${ROOT_DIR}/catalog/runtime.json"
assert_jq_file "surface module bindings" '
  .surfaces["access.app"].module == "access_app"
  and .surfaces["access.app"].standards_ref == "access.app"
  and (.surfaces["access.app"].docs_topics | index("zero-trust-api")) != null
  and .surfaces["access.login_method"].module == "access_login_method"
  and .surfaces["access.login_method"].standards_ref == "access.login_method"
  and .surfaces["access.login_method"].inventory_script == "scripts/cf_inventory_access_login_methods.sh"
  and .surfaces["access.login_method"].apply_script == "scripts/cf_mutate_access_login_method.sh"
  and (.surfaces["access.login_method"].actions.apply.operations.set.selectors_any_of | any(. == ["provider_type"]))
  and .surfaces["access.policy"].module == "access_policy"
  and .surfaces["access.policy"].standards_ref == "access.policy"
  and (.surfaces["access.policy"].docs_topics | index("zero-trust-api")) != null
  and .surfaces["audit.log"].inventory_script == "scripts/cf_inventory_audit_logs.sh"
  and .surfaces["audit.log"].permission_family == "Account Settings"
  and .surfaces["audit.log"].actions.apply.supported == false
  and (.surfaces["audit.log"].docs_topics | index("audit-logs")) != null
  and .surfaces["dns.record"].module == "dns_record"
  and .surfaces["dns.record"].standards_ref == "dns.record"
  and (.surfaces["dns.record"].docs_topics | index("api-auth")) != null
  and .surfaces["zone.setting"].module == "zone_setting"
  and .surfaces["zone.setting"].standards_ref == "zone.setting"
  and .surfaces["zone.setting"].inventory_script == "scripts/cf_inventory_zone_settings.sh"
  and .surfaces["zone.setting"].apply_script == "scripts/cf_mutate_zone_setting.sh"
  and .surfaces["zone.setting"].actions.apply.operations.set.required_selectors == ["zone", "name"]
  and (.surfaces["zone.setting"].docs_topics | index("ssl-tls")) != null
  and .surfaces["edge.certificate"].module == "edge_certificate"
  and .surfaces["edge.certificate"].standards_ref == "edge.certificate"
  and (.surfaces["edge.certificate"].docs_topics | index("advanced-certificates")) != null
  and (.surfaces["hostname"] == null)
  and .surfaces["maildesk-cf"].backend == "maildesk_cf_lifecycle"
  and .surfaces["maildesk-cf"].standards_ref == "maildesk-cf"
  and .surfaces["maildesk-cf"].actions.provision.supported == true
  and .surfaces["maildesk-cf"].actions.provision.required_selectors == ["file"]
  and .surfaces["maildesk-cf"].actions.apply.supported == false
  and (.surfaces["maildesk-cf"].docs_topics | index("email-routing")) != null
  and .surfaces["sender_domain"].inventory_script == "scripts/cf_inventory_sender_domains.sh"
  and .surfaces["sender_domain"].permission_family == "Email Sending"
  and .surfaces["sender_domain"].actions.list.required_selectors == ["zone"]
  and .surfaces["sender_domain"].actions.get.selectors_any_of == [["id"], ["name"]]
  and .surfaces["sender_domain"].actions.verify.selectors_any_of == [["id"], ["name"]]
  and .surfaces["sender_domain"].actions.apply.supported == false
  and .surfaces["worker.route"].module == "worker_route"
  and .surfaces["worker.route"].standards_ref == "worker.route"
  and (.surfaces["worker.route"].docs_topics | index("workers-routes")) != null
  and .surfaces["tunnel"].module == "tunnel"
  and .surfaces["tunnel"].standards_ref == "tunnel"
  and (.surfaces["tunnel"].docs_topics | index("api-auth")) != null
  and .surfaces["api_gateway.operation"].actions.apply.supported == false
  and .surfaces["api_gateway.operation"].actions.list.required_selectors == ["zone"]
  and (.surfaces["api_gateway.operation"].docs_topics | index("api-gateway")) != null
  and .surfaces["api_gateway.schema"].actions.apply.supported == false
  and .surfaces["api_gateway.schema"].actions.list.required_selectors == ["zone"]
  and (.surfaces["api_gateway.schema"].docs_topics | index("api-gateway")) != null
  and .surfaces["api_gateway.discovery"].actions.apply.supported == false
  and .surfaces["api_gateway.discovery"].actions.list.required_selectors == ["zone"]
  and (.surfaces["api_gateway.discovery"].docs_topics | index("api-gateway")) != null
  and .surfaces["vulnerability_scanner.scan"].actions.apply.supported == false
  and (.surfaces["vulnerability_scanner.scan"].docs_topics | index("api-shield-vulnerability-scanner")) != null
  and .surfaces["vulnerability_scanner.target_environment"].actions.apply.supported == false
  and (.surfaces["vulnerability_scanner.target_environment"].docs_topics | index("api-shield-vulnerability-scanner")) != null
  and .surfaces["vulnerability_scanner.credential_set"].actions.apply.supported == false
  and (.surfaces["vulnerability_scanner.credential_set"].docs_topics | index("api-shield-vulnerability-scanner")) != null
' "${ROOT_DIR}/catalog/surfaces.json"

assert_contains "state docs preview ack" "cfctl apply dns.record sync --zone example.com --ack-plan <operation-id>" "${ROOT_DIR}/docs/state.md"
assert_not_has_line "state docs stale direct sync" '^cfctl apply dns\.record sync --zone example.com$' "${ROOT_DIR}/docs/state.md"
assert_contains "state docs scaffolding note" "Support means the desired-state engine exists for that surface." "${ROOT_DIR}/docs/state.md"
assert_contains "state readme scaffolding note" "Managed specs are opt-in." "${ROOT_DIR}/state/README.md"
assert_contains "hostname state example" "cfctl hostname verify --file state/hostname/example.yaml" "${ROOT_DIR}/state/hostname/README.md"
assert_contains "hostname checked-in spec" "service: example-edge-router" "${ROOT_DIR}/state/hostname/example.yaml"
assert_contains "maildesk state example" "cfctl maildesk-cf verify --file state/maildesk-cf/example.json" "${ROOT_DIR}/state/maildesk-cf/README.md"
assert_contains "maildesk checked-in spec" "\"script_name\": \"maildesk-cf-router\"" "${ROOT_DIR}/state/maildesk-cf/example.json"
assert_contains "cfctl prompt contract" "You are now operating as \`cfctl\`, a strict, catalog-driven Cloudflare control plane." "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt preview ack" "always require \`--plan\` first, then \`--ack-plan <operation-id>\`" "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt token revoke" "For token revocation, require \`--plan\` first" "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt error verb" "\`doctor\`, \`audit\`, \`admin\`, \`bootstrap\`, \`lanes\`, \`surfaces\`, \`docs\`, \`previews\`, \`locks\`, \`env\`, \`ownership\`, \`wrangler\`, \`cloudflared\`, \`hostname\`, \`maildesk-cf\`, \`standards\`, \`token\`, \`list\`, \`get\`, \`can\`, \`classify\`, \`guide\`, \`apply\`, \`verify\`, \`explain\`, \`snapshot\`, \`diff\`, or \`error\`." "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt env run" "For \`env run\`, require \`--\` followed by argv command tokens." "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt env run argv secrecy" "refuse requests that pass secrets as command args" "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt hostname" "For \`hostname\`, treat \`verify\`, \`diff\`, and \`plan\` as read-only composite evidence flows" "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt maildesk" "For \`maildesk-cf\`, treat \`init\`, \`verify\`, \`snapshot\`, \`diff\`, \`plan\`, and \`provision --plan\` as read-only composite evidence flows" "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt wrapper gating" "For \`wrangler\` and \`cloudflared\`, treat clearly read-only subcommands as direct wrapped executions" "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl preview inactive legacy cleanup command" "purge-inactive-legacy" "${ROOT_DIR}/commands/cfctl.sh"
assert_contains "readme wrapper examples" "cfctl wrangler --version" "${ROOT_DIR}/README.md"
assert_contains "readme env run" "cfctl env run --lane dev -- <command> [args...]" "${ROOT_DIR}/README.md"
assert_contains "readme env run argv secrecy" "do not pass secrets as command-line arguments" "${ROOT_DIR}/README.md"
assert_contains "readme inactive legacy preview cleanup" "cfctl previews purge-inactive-legacy" "${ROOT_DIR}/README.md"
assert_contains "readme source-live boundary" "Source Config Vs Live State" "${ROOT_DIR}/README.md"
assert_contains "readme hostname lifecycle" "Hostname lifecycle" "${ROOT_DIR}/README.md"
assert_contains "readme maildesk lifecycle" "maildesk-cf lifecycle" "${ROOT_DIR}/README.md"
assert_contains "readme token revoke" "cfctl token revoke --id <token-id> --ack-plan <operation-id> --confirm delete" "${ROOT_DIR}/README.md"
assert_contains "readme standards audit freshness" "checked-in Wrangler config alignment, including \`compatibility_date\` freshness" "${ROOT_DIR}/README.md"
assert_contains "readme standards audit source authority" "classify source authority" "${ROOT_DIR}/README.md"
assert_contains "public agent landing wrapper hierarchy" "cfctl wrangler ..." "${ROOT_DIR}/docs/agent-landing.md"
assert_contains "public agent landing source-live boundary" "Do not turn a source-config audit into a live Cloudflare claim." "${ROOT_DIR}/docs/agent-landing.md"
assert_contains "public readme hostname lifecycle" "Hostname lifecycle" "${ROOT_DIR}/README.md"
assert_contains "public readme maildesk lifecycle" "cfctl maildesk-cf provision --file state/maildesk-cf/example.json --plan" "${ROOT_DIR}/README.md"
assert_contains "public readme token revoke" "cfctl token revoke --id <token-id> --ack-plan <operation-id> --confirm delete" "${ROOT_DIR}/README.md"
assert_contains "agent landing decision path" "## Decision Path" "${ROOT_DIR}/docs/agent-landing.md"
assert_contains "agent landing source-live boundary" "Do not turn a source-config audit into a live Cloudflare claim." "${ROOT_DIR}/docs/agent-landing.md"
assert_contains "agent landing env run" "External command auth bridge" "${ROOT_DIR}/docs/agent-landing.md"
assert_contains "agent landing env run argv secrecy" "Never pass secrets as command args because argv is recorded as evidence." "${ROOT_DIR}/docs/agent-landing.md"
assert_contains "runbook wrapper examples" "cfctl cloudflared version" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook env run" "cfctl env run --lane dev -- env" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook env run argv secrecy" "\`env run\` records command argv as evidence; do not pass secrets as command args" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "auth runbook env run" "CF_SHARED_ENV_FILE=/Users/star/dev/.env cfctl env run --lane dev --" "${ROOT_DIR}/docs/runbooks/auth-and-env.md"
assert_contains "auth runbook env run argv secrecy" "Because argv is evidence, do not pass secrets as command" "${ROOT_DIR}/docs/runbooks/auth-and-env.md"
assert_contains "runtime policy env run" "\`cfctl env run\` strips parent lane secrets" "${ROOT_DIR}/docs/runtime-policy.md"
assert_contains "runbook inactive legacy preview cleanup" "previews purge-inactive-legacy" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook audit log read" "cfctl list audit.log" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook hostname lifecycle" "cfctl hostname verify --file state/hostname/example.yaml" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook maildesk lifecycle" "cfctl maildesk-cf verify --file state/maildesk-cf/example.json" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook token revoke" "token revoke --plan\` reads token id/name/status/expiry metadata" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook compatibility freshness" "standards audit\` reports \`compatibility_date\` aging and stale counts" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook source context summary" "\`source_context_summary\`" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook standards audit source evidence" "standards audit\` is source-config evidence" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "config standards compatibility freshness" "Compatibility-date freshness is intentionally advisory" "${ROOT_DIR}/docs/config-standards.md"
assert_contains "config standards canonical notes" "\`canonical_warning_count\`" "${ROOT_DIR}/docs/config-standards.md"
assert_contains "runtime policy inactive legacy preview cleanup" "cfctl previews purge-inactive-legacy" "${ROOT_DIR}/docs/runtime-policy.md"
assert_contains "capabilities operable note" "This table is the operable runtime surface." "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities generated note" "_Generated from \`catalog/surfaces.json\` and \`catalog/runtime.json\`." "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities module column" "| Surface | Read | Can | Apply | Verify | Desired State | Standards | Docs Topics | Module |" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities contract matrix" "## Operation Contract Matrix" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities destructive contract" "| \`dns.record\` | \`delete\` | \`destructive\` | yes | \`lease\` | yes | \`delete\` | \`dev\`, \`global\` | required: zone; one of: id / name, type |" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities email routing contract" "| \`email.routing_rule\` | \`upsert\` | \`write\` | yes | \`apply\` | yes | \`-\` | \`dev\`, \`global\` | required: zone, name, service |" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities zone setting contract" "| \`zone.setting\` | \`set\` | \`write\` | yes | \`apply\` | yes | \`-\` | \`dev\`, \`global\` | required: zone, name |" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities zone setting sync contract" "| \`zone.setting\` | \`sync\` | \`write\` | yes | \`apply\` | yes | \`-\` | \`dev\`, \`global\` | state match: zone, id, name |" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities security txt contract" "| \`security.txt\` | \`upsert\` | \`write\` | yes | \`apply\` | yes | \`-\` | \`dev\`, \`global\` | required: zone |" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities security txt sync contract" "| \`security.txt\` | \`sync\` | \`write\` | yes | \`apply\` | yes | \`-\` | \`dev\`, \`global\` | state match: zone |" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "state docs zone setting" "- \`zone.setting\`" "${ROOT_DIR}/docs/state.md"
assert_contains "state readme zone setting" "- \`zone.setting\`" "${ROOT_DIR}/state/README.md"
assert_contains "state docs security txt" "- \`security.txt\`" "${ROOT_DIR}/docs/state.md"
assert_contains "state readme security txt" "- \`security.txt\`" "${ROOT_DIR}/state/README.md"
assert_jq_file "mlnavigator reply spf desired state" '
  .match.zone == "mlnavigator.com"
  and .match.name == "reply.mlnavigator.com"
  and .match.type == "TXT"
  and .body.content == "v=spf1 include:_spf.mx.cloudflare.net ~all"
  and .body.ttl == 300
  and .body.proxied == false
' "${ROOT_DIR}/state/dns.record/mlnavigator-reply-spf.json"
assert_jq_file "founder public surveys access app state" '
  .match.domain == "founder.mlnavigator.com/api/public-surveys"
  and .intent.classification == "intentional_public_carveout"
  and .body.name == "Founder Public Survey API"
  and .body.type == "self_hosted"
  and .body.domain == "founder.mlnavigator.com/api/public-surveys"
' "${ROOT_DIR}/state/access.app/founder-public-surveys.json"
assert_jq_file "mlnavigator survey retire access app state" '
  .match.domain == "survey.mlnavigator.com"
  and .intent.classification == "retire_legacy_public_surface"
  and .delete == true
' "${ROOT_DIR}/state/access.app/mlnavigator-survey-retire.json"
assert_jq_file "founder public surveys bypass policy state" '
  .match.app_id == "ef0898ec-1d46-4515-8326-6a244ea8c54e"
  and .match.name == "Bypass Everyone"
  and .intent.classification == "intentional_public_carveout_policy"
  and .body.decision == "bypass"
  and .body.include == [{"everyone": {}}]
  and .body.exclude == []
  and .body.require == []
  and .body.precedence == 1
' "${ROOT_DIR}/state/access.policy/founder-public-surveys-bypass.json"
assert_jq_file "adapteros security txt state" '
  .match.zone == "adapteros.com"
  and .body.enabled == true
  and .body.contact == ["mailto:security@adapteros.com"]
  and .body.canonical == ["https://adapteros.com/.well-known/security.txt"]
  and .body.policy == ["https://adapteros.com/security"]
' "${ROOT_DIR}/state/security.txt/adapteros-com.json"
assert_jq_file "mlnavigator security txt state" '
  .match.zone == "mlnavigator.com"
  and .body.enabled == true
  and .body.contact == ["mailto:security@mlnavigator.com"]
  and .body.canonical == ["https://mlnavigator.com/.well-known/security.txt"]
' "${ROOT_DIR}/state/security.txt/mlnavigator-com.json"
assert_contains "capabilities read-only surfaces" "## Read-Only Surfaces" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities read-only warning" "Mutation should not be inferred from an inventory script alone." "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities hostname composite" "Composite lifecycle commands:" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities maildesk composite" "cfctl maildesk-cf provision --file state/maildesk-cf/<name>.json --plan" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "docs bank tracked vs operable note" "Tracked here does not automatically mean operable through \`cfctl\` today" "${ROOT_DIR}/docs/cloudflare-doc-bank.md"
assert_contains "docs bank audit logs" "Audit Logs v2" "${ROOT_DIR}/docs/cloudflare-doc-bank.md"
assert_contains "public contract live verifier note" "This is a live account smoke test." "${ROOT_DIR}/scripts/verify_public_contract.sh"
assert_contains "contract workflow static gate" "python3 scripts/verify_permission_catalog.py --cfctl ./cfctl" "${ROOT_DIR}/.github/workflows/cfctl-contract.yml"
assert_contains "contract workflow live gate" "./scripts/verify_public_contract.sh" "${ROOT_DIR}/.github/workflows/cfctl-contract.yml"
assert_contains "contract workflow manual secret gate" "Live Cloudflare contract requires:" "${ROOT_DIR}/.github/workflows/cfctl-contract.yml"
assert_contains "contract workflow scheduled secret skip" "Skipping scheduled live Cloudflare contract" "${ROOT_DIR}/.github/workflows/cfctl-contract.yml"
assert_contains "contract workflow protected environment" "environment: cfctl-live" "${ROOT_DIR}/.github/workflows/cfctl-contract.yml"
assert_contains "public contract inactive legacy preview cleanup" "previews purge-inactive-legacy" "${ROOT_DIR}/scripts/verify_public_contract.sh"
assert_contains "permission doctrine source" "Cloudflare API token permissions are resource-scoped" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine environment" "cfctl-live" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine bootstrap creator" "Account API Tokens Write" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine profile read" "- \`read\`: default inventory and audit profile, including \`audit.log\`." "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine profile dns" "- \`dns\`: DNS record read/write profile" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine profile hostname" "- \`hostname\`: composite hostname lifecycle profile" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine profile deploy" "- \`deploy\`: Worker, Pages, D1, R2, Queues" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine profile security audit" "- \`security-audit\`: read-only API-security" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine profile full operator" "- \`full-operator\`: broad local operator profile" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine token exclusion" "Operator profiles must not include \`Account API Tokens *\` permissions." "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine read forbidden" "Read-risk profiles must not include \`* Write\`, \`* Revoke\`, or \`* Run\`" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine account settings blast radius" "\`Account Settings Read\` is the coarse Cloudflare permission behind" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "readme permission doctrine" "docs/permission-doctrine.md" "${ROOT_DIR}/README.md"
assert_contains "runbook permission doctrine" "docs/permission-doctrine.md" "${ROOT_DIR}/docs/runbooks/cfctl.md"

echo "static-contract verification passed"
