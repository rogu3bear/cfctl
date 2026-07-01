#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() {
  echo "maildesk-cf contract verification failed: $*" >&2
  exit 1
}

require_source_line() {
  local label="$1"
  local needle="$2"
  local file="$3"

  if ! grep -Fq -- "${needle}" "${file}"; then
    die "${label}: expected source line '${needle}' in ${file}"
  fi
}

fixture_file="$(mktemp "${TMPDIR:-/tmp}/maildesk-cf-fixture.XXXXXX")"
missing_fixture_file="$(mktemp "${TMPDIR:-/tmp}/maildesk-cf-missing-fixture.XXXXXX")"
unverified_sender_fixture_file="$(mktemp "${TMPDIR:-/tmp}/maildesk-cf-unverified-sender.XXXXXX")"
cloudflare_sender_spec_file="$(mktemp "${TMPDIR:-/tmp}/maildesk-cf-cloudflare-sender-spec.XXXXXX")"
caller_spec_dir="$(mktemp -d "${TMPDIR:-/tmp}/maildesk-cf-caller-spec.XXXXXX")"
trap 'rm -f "${fixture_file}" "${missing_fixture_file}" "${unverified_sender_fixture_file}" "${cloudflare_sender_spec_file}"; rm -rf "${caller_spec_dir}"' EXIT

require_source_line "worker evidence lane" '"worker.script": run_cfctl(["list", "worker.script"], lane="global"),' "${ROOT_DIR}/scripts/cf_maildesk_cf_lifecycle.py"
require_source_line "d1 evidence lane" '"d1.database": run_cfctl(["list", "d1.database"], lane="global"),' "${ROOT_DIR}/scripts/cf_maildesk_cf_lifecycle.py"
require_source_line "r2 evidence lane" '"r2.bucket": run_cfctl(["list", "r2.bucket"], lane="global"),' "${ROOT_DIR}/scripts/cf_maildesk_cf_lifecycle.py"
require_source_line "queue evidence lane" '"queue": run_cfctl(["list", "queue"], lane="global"),' "${ROOT_DIR}/scripts/cf_maildesk_cf_lifecycle.py"

cat >"${fixture_file}" <<'JSON'
{
  "workers": [
    {"id": "maildesk-cf"},
    {"id": "maildesk-cf-router"}
  ],
  "d1": [
    {"name": "maildesk-cf-db"},
    {"name": "maildesk-cf-preview-db"}
  ],
  "r2": [
    {"name": "maildesk-cf-raw-mail"},
    {"name": "maildesk-cf-raw-mail-preview"}
  ],
  "queues": [
    {"queue_name": "maildesk-cf-jobs"}
  ],
  "domains": {
    "example.com": {
      "email_routing": {"enabled": true},
      "email_routing_rules": [
        {"recipient": "abuse@example.com", "service": "maildesk-cf-router"},
        {"recipient": "dmarc@example.com", "service": "maildesk-cf-router"},
        {"recipient": "founders@example.com", "service": "maildesk-cf-router"},
        {"recipient": "info@example.com", "service": "maildesk-cf-router"},
        {"recipient": "legal@example.com", "service": "maildesk-cf-router"},
        {"recipient": "noreply@example.com", "service": "maildesk-cf-router"},
        {"recipient": "postmaster@example.com", "service": "maildesk-cf-router"},
        {"recipient": "security@example.com", "service": "maildesk-cf-router"},
        {"recipient": "operator-a@example.com", "service": "maildesk-cf-router"},
        {"recipient": "operator-b@example.com", "service": "maildesk-cf-router"}
      ],
      "dns_records": [
        {"type": "TXT", "name": "example.com", "content": "v=spf1 include:_spf.mx.cloudflare.net ~all"},
        {"type": "TXT", "name": "_dmarc.example.com", "content": "v=DMARC1; p=none; rua=mailto:dmarc@example.com"}
      ]
    }
  },
  "sender": {
    "domains": [
      {"domain": "example.com", "name": "example.com", "status": "verified", "enabled": true}
    ]
  }
}
JSON

cat >"${missing_fixture_file}" <<'JSON'
{
  "workers": [],
  "d1": [],
  "r2": [],
  "queues": [],
  "domains": {
    "example.com": {
      "email_routing": {"enabled": false},
      "email_routing_rules": [],
      "dns_records": []
    }
  },
  "sender": {
    "provider_readback": "not_available"
  }
}
JSON

cat >"${unverified_sender_fixture_file}" <<'JSON'
{
  "workers": [
    {"id": "maildesk-cf"},
    {"id": "maildesk-cf-router"}
  ],
  "d1": [
    {"name": "maildesk-cf-db"},
    {"name": "maildesk-cf-preview-db"}
  ],
  "r2": [
    {"name": "maildesk-cf-raw-mail"},
    {"name": "maildesk-cf-raw-mail-preview"}
  ],
  "queues": [
    {"queue_name": "maildesk-cf-jobs"}
  ],
  "domains": {
    "example.com": {
      "email_routing": {"enabled": true},
      "email_routing_rules": [
        {"recipient": "abuse@example.com", "service": "maildesk-cf-router"},
        {"recipient": "dmarc@example.com", "service": "maildesk-cf-router"},
        {"recipient": "founders@example.com", "service": "maildesk-cf-router"},
        {"recipient": "info@example.com", "service": "maildesk-cf-router"},
        {"recipient": "legal@example.com", "service": "maildesk-cf-router"},
        {"recipient": "noreply@example.com", "service": "maildesk-cf-router"},
        {"recipient": "postmaster@example.com", "service": "maildesk-cf-router"},
        {"recipient": "security@example.com", "service": "maildesk-cf-router"},
        {"recipient": "operator-a@example.com", "service": "maildesk-cf-router"},
        {"recipient": "operator-b@example.com", "service": "maildesk-cf-router"}
      ],
      "dns_records": [
        {"type": "TXT", "name": "example.com", "content": "v=spf1 include:_spf.mx.cloudflare.net ~all"},
        {"type": "TXT", "name": "_dmarc.example.com", "content": "v=DMARC1; p=none; rua=mailto:dmarc@example.com"}
      ]
    }
  },
  "sender": {
    "provider": "cloudflare_email_service",
    "domains": []
  }
}
JSON

jq '.sender = {"mode": "cloudflare_email_service", "authenticated_domains": ["example.com"]}' \
  "${ROOT_DIR}/state/maildesk-cf/example.json" >"${cloudflare_sender_spec_file}"

jq -e '
  .sender.mode == "disabled"
  and (.sender.authenticated_domains | length) == 0
' "${ROOT_DIR}/state/maildesk-cf/example.json" >/dev/null || die "checked-in maildesk-cf example must default to disabled outbound sender mode"

output="$(
  MAILDESK_CF_EVIDENCE_FILE="${fixture_file}" \
  MAILDESK_CF_ACTION=verify \
  SPEC_FILE="${ROOT_DIR}/state/maildesk-cf/example.json" \
  python3 "${ROOT_DIR}/scripts/cf_maildesk_cf_lifecycle.py"
)"
artifact_path="$(printf '%s\n' "${output}" | tail -n 1)"
[[ -f "${artifact_path}" ]] || die "verify artifact was not written"

jq -e '
  .readiness.template_ready == true
  and .readiness.instance_ready == true
  and .readiness.edge_ready == true
  and .readiness.mail_ready == true
  and .checks.sender.mode.normalized == "disabled"
  and .checks.sender.ready == true
  and (.drift_classes | index("provider_status_unavailable")) == null
  and (.drift_classes | index("sender_adapter_receive_only")) == null
  and (.drift_classes | index("sender_domain_drift")) == null
  and (.drift_classes | index("optional_live_send_not_requested")) != null
  and (.plan.operations | length) == 0
' "${artifact_path}" >/dev/null || die "fixture readiness contract did not match"

missing_output="$(
  MAILDESK_CF_EVIDENCE_FILE="${missing_fixture_file}" \
  MAILDESK_CF_ACTION=diff \
  SPEC_FILE="${ROOT_DIR}/state/maildesk-cf/example.json" \
  python3 "${ROOT_DIR}/scripts/cf_maildesk_cf_lifecycle.py"
)"
missing_artifact_path="$(printf '%s\n' "${missing_output}" | tail -n 1)"
[[ -f "${missing_artifact_path}" ]] || die "missing-resource artifact was not written"

jq -e '
  .readiness.edge_ready == false
  and (.drift_classes | index("missing_resource")) != null
  and (.drift_classes | index("email_routing_alias_drift")) != null
  and (.drift_classes | index("dns_authentication_drift")) == null
  and (.drift_classes | index("sender_adapter_receive_only")) == null
  and any(.plan.operations[]; .surface == "d1.database" and .preview_command == "cfctl wrangler d1 create maildesk-cf-db --plan" and .blocked == null)
  and any(.plan.operations[]; .surface == "d1.database" and .preview_command == "cfctl wrangler d1 create maildesk-cf-preview-db --plan" and .blocked == null)
  and any(.plan.operations[]; .surface == "r2.bucket" and .preview_command == "cfctl wrangler r2 bucket create maildesk-cf-raw-mail --plan" and .blocked == null)
  and any(.plan.operations[]; .surface == "r2.bucket" and .preview_command == "cfctl wrangler r2 bucket create maildesk-cf-raw-mail-preview --plan" and .blocked == null)
  and any(.plan.operations[]; .surface == "queue" and .preview_command == "cfctl wrangler queues create maildesk-cf-jobs --plan" and .blocked == null)
' "${missing_artifact_path}" >/dev/null || die "missing-resource drift classes did not match"

unverified_sender_output="$(
  MAILDESK_CF_EVIDENCE_FILE="${unverified_sender_fixture_file}" \
  MAILDESK_CF_ACTION=verify \
  SPEC_FILE="${cloudflare_sender_spec_file}" \
  python3 "${ROOT_DIR}/scripts/cf_maildesk_cf_lifecycle.py"
)"
unverified_sender_artifact_path="$(printf '%s\n' "${unverified_sender_output}" | tail -n 1)"
[[ -f "${unverified_sender_artifact_path}" ]] || die "unverified-sender artifact was not written"

jq -e '
  .readiness.edge_ready == true
  and .readiness.mail_ready == false
  and (.drift_classes | index("sender_domain_drift")) != null
  and (.drift_classes | index("provider_status_unavailable")) == null
  and any(.plan.operations[]; .surface == "sender_domain" and .preview_command == "CF_TOKEN_LANE=global cfctl apply sender_domain enable --zone example.com --name example.com --plan" and .blocked == null)
' "${unverified_sender_artifact_path}" >/dev/null || die "unverified sender-domain drift contract did not match"

cfctl_output="$(
  MAILDESK_CF_EVIDENCE_FILE="${fixture_file}" \
  "${ROOT_DIR}/cfctl" maildesk-cf provision --file "${ROOT_DIR}/state/maildesk-cf/example.json" --plan
)"
operation_id="$(jq -r '.operation_id // empty' <<< "${cfctl_output}")"
[[ -n "${operation_id}" ]] || die "cfctl provision --plan did not emit operation_id"
jq -e '
  .ok == true
  and .action == "maildesk-cf"
  and .operation == "provision"
  and .summary.plan_mode == true
  and .summary.edge_ready == true
  and .summary.mail_ready == true
' <<< "${cfctl_output}" >/dev/null || die "cfctl provision --plan envelope did not match"

cp "${ROOT_DIR}/state/maildesk-cf/example.json" "${caller_spec_dir}/caller-relative.json"
caller_spec_physical_dir="$(cd -P "${caller_spec_dir}" && pwd)"
caller_relative_output="$(
  cd "${caller_spec_dir}"
  MAILDESK_CF_EVIDENCE_FILE="${fixture_file}" \
    "${ROOT_DIR}/cfctl" maildesk-cf verify --file caller-relative.json
)"
jq -e \
  --arg expected_spec "${caller_spec_physical_dir}/caller-relative.json" \
  '
    .ok == true
    and .summary.spec_path == $expected_spec
    and .summary.edge_ready == true
    and .summary.mail_ready == true
  ' <<< "${caller_relative_output}" >/dev/null || die "caller-relative maildesk-cf spec path did not resolve"

standards_output="$("${ROOT_DIR}/cfctl" standards maildesk-cf)"
jq -e '
  .ok == true
  and .action == "standards"
  and .surface == "maildesk-cf"
  and .summary.standard_count >= 4
  and .summary.desired_state_supported == true
  and .result.runtime.backend == "maildesk_cf_lifecycle"
' <<< "${standards_output}" >/dev/null || die "maildesk-cf standards envelope did not match"

classify_output="$(
  "${ROOT_DIR}/cfctl" classify maildesk-cf provision --file "${ROOT_DIR}/state/maildesk-cf/example.json"
)"
jq -e '
  .ok == true
  and .action == "classify"
  and .surface == "maildesk-cf"
  and .operation == "provision"
  and .summary.preview_required == true
  and .summary.selector_ready == true
  and .result.policy.public_example == "cfctl maildesk-cf provision --file state/maildesk-cf/<name>.json --plan"
' <<< "${classify_output}" >/dev/null || die "maildesk-cf classify envelope did not match"

guide_output="$(
  "${ROOT_DIR}/cfctl" guide maildesk-cf provision --file "${ROOT_DIR}/state/maildesk-cf/example.json"
)"
jq -e '
  .ok == true
  and .action == "guide"
  and .surface == "maildesk-cf"
  and .operation == "provision"
  and (.result.commands.preview | contains("cfctl maildesk-cf provision"))
  and (.result.commands.preview | contains("--plan"))
  and (.result.commands.apply_blocked | contains("--ack-plan <operation-id>"))
  and any(.result.steps[]; contains("Do not run the ack command"))
' <<< "${guide_output}" >/dev/null || die "maildesk-cf guide envelope did not match"

set +e
ack_output="$(
  MAILDESK_CF_EVIDENCE_FILE="${fixture_file}" \
  "${ROOT_DIR}/cfctl" maildesk-cf provision --file "${ROOT_DIR}/state/maildesk-cf/example.json" --ack-plan "${operation_id}"
)"
ack_status=$?
set -e
[[ "${ack_status}" -ne 0 ]] || die "cfctl provision --ack-plan should be blocked in this tranche"
jq -e '
  .ok == false
  and .error.code == "unsupported_operation"
  and (.error.message | contains("composite provision apply is blocked"))
' <<< "${ack_output}" >/dev/null || die "cfctl provision --ack-plan block envelope did not match"

echo "maildesk-cf contract verification passed"
