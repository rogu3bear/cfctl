#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() {
  echo "maildesk-cf contract verification failed: $*" >&2
  exit 1
}

fixture_file="$(mktemp "${TMPDIR:-/tmp}/maildesk-cf-fixture.XXXXXX.json")"
missing_fixture_file="$(mktemp "${TMPDIR:-/tmp}/maildesk-cf-missing-fixture.XXXXXX.json")"
trap 'rm -f "${fixture_file}" "${missing_fixture_file}"' EXIT

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
    "provider_readback": "not_available"
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
  and .readiness.mail_ready == false
  and (.drift_classes | index("provider_status_unavailable")) != null
  and (.drift_classes | index("optional_live_send_not_requested")) != null
  and (.plan.operations | length) == 1
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
  and (.drift_classes | index("dns_authentication_drift")) != null
' "${missing_artifact_path}" >/dev/null || die "missing-resource drift classes did not match"

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
  and .summary.mail_ready == false
' <<< "${cfctl_output}" >/dev/null || die "cfctl provision --plan envelope did not match"

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
