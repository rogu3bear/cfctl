#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"
# shellcheck disable=SC1091
source "${ROOT_DIR}/lib/runtime/desired_state.sh"

fail() {
  echo "state audit contract verification failed: $*" >&2
  exit 1
}

assert_jq() {
  local label="$1"
  local expr="$2"
  local payload="$3"

  jq -e "${expr}" <<< "${payload}" >/dev/null || fail "${label}: ${expr}"
}

# Fully converged: account-scoped surface in sync, zone-scoped surface in sync,
# posture passing.
CONVERGED_TARGETS='[
  {"surface":"access.app","scope":"account","zone":null,"ok":true,"result":{"summary":{"drift_count":0,"create_count":0,"update_count":0,"delete_count":0,"in_sync_count":5,"invalid_spec_count":0,"ambiguous_count":0,"unmanaged_actual_count":12},"desired_specs":[{"spec_path":"a/beta.json","match":{"domain":"beta.example.com"},"status":"in_sync","proposed_operation":"noop"}]}},
  {"surface":"zone.setting","scope":"zone","zone":"example.com","ok":true,"result":{"summary":{"drift_count":0,"create_count":0,"update_count":0,"delete_count":0,"in_sync_count":4,"invalid_spec_count":0,"ambiguous_count":0,"unmanaged_actual_count":50},"desired_specs":[{"spec_path":"z/ssl.json","match":{"zone":"example.com","name":"ssl"},"status":"in_sync","proposed_operation":"noop"}]}}
]'
CONVERGED_POSTURE='{"summary":{"status":"pass","fail_count":0,"warning_count":0,"failing_checks":[]},"otp":{"provider_present":true}}'

CONVERGED_JSON="$(cfctl_state_audit_rollup_json "${CONVERGED_TARGETS}" "${CONVERGED_POSTURE}")"
assert_jq "converged verdict is true" '.converged == true' "${CONVERGED_JSON}"
assert_jq "converged has empty remediation queue" '(.remediation_queue | length) == 0 and (.summary.actionable_spec_count == 0)' "${CONVERGED_JSON}"
assert_jq "converged reports posture pass" '.summary.posture_status == "pass" and .summary.posture_fail_count == 0' "${CONVERGED_JSON}"
assert_jq "converged counts targets" '.summary.surface_target_count == 2 and .summary.drifted_target_count == 0' "${CONVERGED_JSON}"

# Drifted: a zone-setting update, a DNS create, and a posture fail.
DRIFTED_TARGETS='[
  {"surface":"zone.setting","scope":"zone","zone":"leakbar.com","ok":true,"result":{"summary":{"drift_count":4,"create_count":0,"update_count":4,"delete_count":0,"in_sync_count":0,"invalid_spec_count":0,"ambiguous_count":0,"unmanaged_actual_count":50},"desired_specs":[{"spec_path":"z/ssl.json","match":{"zone":"leakbar.com","name":"ssl"},"status":"drift","proposed_operation":"update"},{"spec_path":"z/mintls.json","match":{"zone":"leakbar.com","name":"min_tls_version"},"status":"drift","proposed_operation":"update"}]}},
  {"surface":"dns.record","scope":"zone","zone":"mlnavigator.com","ok":true,"result":{"summary":{"drift_count":0,"create_count":1,"update_count":0,"delete_count":0,"in_sync_count":0,"invalid_spec_count":0,"ambiguous_count":0,"unmanaged_actual_count":25},"desired_specs":[{"spec_path":"d/spf.json","match":{"zone":"mlnavigator.com","name":"reply.mlnavigator.com","type":"TXT"},"status":"missing_actual","proposed_operation":"create"}]}}
]'
DRIFTED_POSTURE='{"summary":{"status":"fail","fail_count":2,"warning_count":2,"failing_checks":["otp_only_where_intended","every_self_hosted_app_has_allow_policy"]},"otp":{"provider_present":true}}'

DRIFTED_JSON="$(cfctl_state_audit_rollup_json "${DRIFTED_TARGETS}" "${DRIFTED_POSTURE}")"
assert_jq "drift verdict is not converged" '.converged == false' "${DRIFTED_JSON}"
assert_jq "remediation queue enumerates every actionable spec" '(.remediation_queue | length) == 3' "${DRIFTED_JSON}"
assert_jq "remediation carries ready sync commands" '.remediation_queue[0].sync_command | startswith("CF_TOKEN_LANE=global cfctl apply ") and endswith("--plan")' "${DRIFTED_JSON}"
assert_jq "zone-scoped command names the zone" '(.remediation_queue | map(select(.surface == "dns.record")) | .[0].sync_command) == "CF_TOKEN_LANE=global cfctl apply dns.record sync --zone mlnavigator.com --plan"' "${DRIFTED_JSON}"
assert_jq "distinct commands dedupe per surface/zone" '(.summary.distinct_sync_commands | length) == 2' "${DRIFTED_JSON}"
assert_jq "posture fail forces non-convergence even without state delta" '.summary.posture_fail_count == 2' "${DRIFTED_JSON}"
assert_jq "drifted target count reflects surfaces with work" '.summary.drifted_target_count == 2 and .summary.state_delta_total == 3' "${DRIFTED_JSON}"

# State converged but posture failing must still be non-converged.
POSTURE_ONLY_JSON="$(cfctl_state_audit_rollup_json "$(jq -c '[.[0]]' <<< "${CONVERGED_TARGETS}")" "${DRIFTED_POSTURE}")"
assert_jq "clean state + failing posture is not converged" '.converged == false and (.remediation_queue | length) == 0 and .summary.posture_fail_count == 2' "${POSTURE_ONLY_JSON}"

# Unreadable target (diff failed, e.g. lane lacks scope) blocks convergence.
UNREADABLE_TARGETS='[{"surface":"access.app","scope":"account","zone":null,"ok":false,"result":null,"error":"diff_failed"}]'
UNREADABLE_JSON="$(cfctl_state_audit_rollup_json "${UNREADABLE_TARGETS}" "null")"
assert_jq "unreadable target is surfaced and blocks convergence" '.converged == false and (.unreadable_targets | length) == 1 and .summary.unreadable_target_count == 1' "${UNREADABLE_JSON}"
assert_jq "absent posture reports not_run without failing" '.summary.posture_status == "not_run" and .summary.posture_fail_count == 0' "${UNREADABLE_JSON}"

echo "state audit contract verification passed."
