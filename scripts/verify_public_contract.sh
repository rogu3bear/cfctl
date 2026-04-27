#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFCTL="${ROOT_DIR}/cfctl"

# This is a live account smoke test. It validates the public contract against the
# current local auth lanes and real Cloudflare account access on this machine.

cd "${ROOT_DIR}"

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required tool: $1" >&2
    exit 1
  }
}

die() {
  echo "public-contract verification failed: $*" >&2
  exit 1
}

run_json() {
  local expect="$1"
  local label="$2"
  shift 2

  local out=""
  local status=0

  set +e
  out="$("$@" 2>/dev/null)"
  status=$?
  set -e

  case "${expect}" in
    success)
      [[ "${status}" -eq 0 ]] || die "${label}: expected success, got exit ${status}"
      ;;
    failure)
      [[ "${status}" -ne 0 ]] || die "${label}: expected failure, got exit 0"
      ;;
    *)
      die "unknown expectation: ${expect}"
      ;;
  esac

  jq -e '.' >/dev/null <<< "${out}" || die "${label}: output was not valid JSON"
  printf '%s\n' "${out}"
}

assert_artifact_exists() {
  local label="$1"
  local json="$2"
  local artifact_path

  artifact_path="$(jq -r '.artifact_path // empty' <<< "${json}")"
  [[ -n "${artifact_path}" ]] || die "${label}: missing artifact_path"
  [[ -f "${artifact_path}" ]] || die "${label}: artifact_path does not exist: ${artifact_path}"
}

assert_backend_artifact_exists() {
  local label="$1"
  local json="$2"
  local artifact_path

  artifact_path="$(jq -r '.backend_artifact_path // empty' <<< "${json}")"
  [[ -n "${artifact_path}" ]] || die "${label}: missing backend_artifact_path"
  [[ -f "${artifact_path}" ]] || die "${label}: backend_artifact_path does not exist: ${artifact_path}"
}

assert_json() {
  local label="$1"
  local expression="$2"
  local json="$3"

  jq -e "${expression}" >/dev/null <<< "${json}" || die "${label}: assertion failed: ${expression}"
}

require_tool jq

unique_suffix="$(date -u +%Y%m%d%H%M%S)-$$"
token_name="dns-editor-${unique_suffix}"

cleanup_previews_json="$(run_json success "previews purge-expired" "${CFCTL}" previews purge-expired)"
assert_artifact_exists "previews purge-expired" "${cleanup_previews_json}"
assert_json "previews purge-expired" '.ok == true and .action == "previews"' "${cleanup_previews_json}"

cleanup_locks_json="$(run_json success "locks clear-stale" "${CFCTL}" locks clear-stale)"
assert_artifact_exists "locks clear-stale" "${cleanup_locks_json}"
assert_json "locks clear-stale" '.ok == true and .action == "locks"' "${cleanup_locks_json}"

wrangler_version_json="$(run_json success "wrangler --version" "${CFCTL}" wrangler --version)"
assert_artifact_exists "wrangler --version" "${wrangler_version_json}"
assert_backend_artifact_exists "wrangler --version" "${wrangler_version_json}"
assert_json "wrangler --version" '.ok == true and .action == "wrangler" and .surface == "wrangler" and .backend == "wrangler" and .summary.mode == "read_only" and .result.exit_code == 0' "${wrangler_version_json}"

wrangler_default_json="$(run_json success "wrangler default" "${CFCTL}" wrangler)"
assert_artifact_exists "wrangler default" "${wrangler_default_json}"
assert_backend_artifact_exists "wrangler default" "${wrangler_default_json}"
assert_json "wrangler default" '.ok == true and .action == "wrangler" and .result.classification.defaulted == true and .result.classification.operation == "whoami" and .result.exit_code == 0' "${wrangler_default_json}"

cloudflared_version_json="$(run_json success "cloudflared version" "${CFCTL}" cloudflared version)"
assert_artifact_exists "cloudflared version" "${cloudflared_version_json}"
assert_backend_artifact_exists "cloudflared version" "${cloudflared_version_json}"
assert_json "cloudflared version" '.ok == true and .action == "cloudflared" and .surface == "cloudflared" and .backend == "cloudflared" and .summary.mode == "read_only" and .result.exit_code == 0' "${cloudflared_version_json}"

cloudflared_default_json="$(run_json success "cloudflared default" "${CFCTL}" cloudflared)"
assert_artifact_exists "cloudflared default" "${cloudflared_default_json}"
assert_backend_artifact_exists "cloudflared default" "${cloudflared_default_json}"
assert_json "cloudflared default" '.ok == true and .action == "cloudflared" and .result.classification.defaulted == true and .result.classification.operation == "version" and .result.exit_code == 0' "${cloudflared_default_json}"

cloudflared_plan_json="$(run_json success "cloudflared tunnel create --plan" "${CFCTL}" cloudflared tunnel create preview-tunnel --plan)"
assert_artifact_exists "cloudflared tunnel create --plan" "${cloudflared_plan_json}"
assert_json "cloudflared tunnel create --plan" '.ok == true and .action == "cloudflared" and .summary.plan_mode == true and .summary.requires_ack == true and .result.classification.mode == "preview_required"' "${cloudflared_plan_json}"

wrangler_plan_json="$(run_json success "wrangler deploy --plan" "${CFCTL}" wrangler deploy --plan)"
assert_artifact_exists "wrangler deploy --plan" "${wrangler_plan_json}"
assert_json "wrangler deploy --plan" '.ok == true and .action == "wrangler" and .summary.plan_mode == true and .summary.requires_ack == true and .result.classification.mode == "preview_required"' "${wrangler_plan_json}"

wrangler_preview_required_json="$(run_json failure "wrangler deploy preview-required" "${CFCTL}" wrangler deploy)"
assert_artifact_exists "wrangler deploy preview-required" "${wrangler_preview_required_json}"
assert_json "wrangler deploy preview-required" '.ok == false and .action == "wrangler" and .error.code == "preview_required" and .error.recommended_command != null' "${wrangler_preview_required_json}"

doctor_json="$(run_json success "doctor --strict" "${CFCTL}" doctor --strict)"
assert_artifact_exists "doctor --strict" "${doctor_json}"
assert_json "doctor --strict" '.ok == true and .action == "doctor" and .summary.status == "healthy"' "${doctor_json}"

standards_all_json="$(run_json success "standards" "${CFCTL}" standards)"
assert_artifact_exists "standards" "${standards_all_json}"
assert_json "standards" '.ok == true and .action == "standards" and .surface == "all" and (.result.universal | length) > 0 and ((.result.surfaces | length) > 0)' "${standards_all_json}"

docs_all_json="$(run_json success "docs" "${CFCTL}" docs)"
assert_artifact_exists "docs" "${docs_all_json}"
assert_json "docs" '.ok == true and .action == "docs" and .surface == "all" and .summary.foundation_count > 0 and .summary.watch_count > 0 and .summary.freshness.refresh_interval_days > 0' "${docs_all_json}"

docs_watch_json="$(run_json success "docs watch" "${CFCTL}" docs watch)"
assert_artifact_exists "docs watch" "${docs_watch_json}"
assert_json "docs watch" '.ok == true and .action == "docs" and .surface == "watch" and (.result.items | length) > 0' "${docs_watch_json}"

docs_browser_run_json="$(run_json success "docs browser-run" "${CFCTL}" docs browser-run)"
assert_artifact_exists "docs browser-run" "${docs_browser_run_json}"
assert_json "docs browser-run" '.ok == true and .action == "docs" and .surface == "browser-run" and .result.entry.id == "browser-run" and .result.kind == "watch"' "${docs_browser_run_json}"

standards_dns_json="$(run_json success "standards dns.record" "${CFCTL}" standards dns.record)"
assert_artifact_exists "standards dns.record" "${standards_dns_json}"
assert_json "standards dns.record" '.ok == true and .action == "standards" and .surface == "dns.record" and .result.standard.stance != null and ((.result.standard.standards | length) > 0)' "${standards_dns_json}"

standards_worker_runtime_json="$(run_json success "standards worker.runtime" "${CFCTL}" standards worker.runtime)"
assert_artifact_exists "standards worker.runtime" "${standards_worker_runtime_json}"
assert_json "standards worker.runtime" '.ok == true and .action == "standards" and .surface == "worker.runtime" and .summary.standards_only == true and ((.result.standard.audit_features | length) > 0)' "${standards_worker_runtime_json}"

standards_worker_errors_json="$(run_json success "standards worker.errors" "${CFCTL}" standards worker.errors)"
assert_artifact_exists "standards worker.errors" "${standards_worker_errors_json}"
assert_json "standards worker.errors" '.ok == true and .action == "standards" and .surface == "worker.errors" and .summary.standards_only == true and ((.result.standard.standards | length) >= 4)' "${standards_worker_errors_json}"

standards_audit_json="$(run_json success "standards audit" "${CFCTL}" standards audit)"
assert_artifact_exists "standards audit" "${standards_audit_json}"
assert_json "standards audit" '.ok == true and .action == "standards" and .surface == "audit" and .summary.config_file_count > 0 and .result.coverage.uncovered_feature_count == 0' "${standards_audit_json}"

audit_json="$(run_json success "audit trust" "${CFCTL}" audit trust)"
assert_artifact_exists "audit trust" "${audit_json}"
assert_json "audit trust" '.ok == true and .action == "doctor" and .summary.status != null' "${audit_json}"

permission_groups_json="$(run_json success "token permission-groups" "${CFCTL}" token permission-groups --name DNS)"
assert_artifact_exists "token permission-groups" "${permission_groups_json}"
assert_json "token permission-groups" '.ok == true and .action == "token.permission-groups" and ((.result.permission_groups | length) > 0)' "${permission_groups_json}"

classify_dns_json="$(
  run_json success \
    "classify dns.record upsert" \
    "${CFCTL}" classify dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT
)"
assert_artifact_exists "classify dns.record upsert" "${classify_dns_json}"
assert_json "classify dns.record upsert" '.ok == true and .result.selector_readiness.ready == true and .permission_status.basis != "selector_incomplete"' "${classify_dns_json}"

can_dns_json="$(
  run_json success \
    "can dns.record upsert --all-lanes" \
    env CF_TOKEN_LANE=global "${CFCTL}" can dns.record upsert --zone example.com --name _ops-smoke.example.com --type TXT --all-lanes
)"
assert_artifact_exists "can dns.record upsert --all-lanes" "${can_dns_json}"
assert_json "can dns.record upsert --all-lanes" '.ok == true and ((.result.summary.allowed_lanes | index("global")) != null) and ((.result.lanes | map(select(.lane == "global" and .permission.state == "allowed")) | length) == 1)' "${can_dns_json}"

token_plan_json="$(
  run_json success \
    "token mint --plan" \
    "${CFCTL}" token mint --name "${token_name}" --permission "DNS Write" --zone example.com --ttl-hours 24 --plan
)"
assert_artifact_exists "token mint --plan" "${token_plan_json}"
assert_json "token mint --plan" '.ok == true and .action == "token.mint" and .planned == true and (.operation_id | type == "string")' "${token_plan_json}"

token_failure_json="$(
  run_json failure \
    "token mint preview-required" \
    "${CFCTL}" token mint --name account-audit --permission "Account Settings Read" --ttl-hours 24
)"
assert_artifact_exists "token mint preview-required" "${token_failure_json}"
assert_json "token mint preview-required" '.ok == false and .action == "token.mint" and .error.code == "preview_required"' "${token_failure_json}"

echo "public-contract verification passed"
