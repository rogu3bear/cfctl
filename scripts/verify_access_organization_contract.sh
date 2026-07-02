#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/cf_mutate_access_organization.sh"

fail() {
  echo "access.organization contract verification failed: $*" >&2
  exit 1
}

assert_jq() {
  local label="$1"
  local expr="$2"
  local payload="$3"

  jq -e "${expr}" <<< "${payload}" >/dev/null || fail "${label}: ${expr}"
}

ORG_JSON='{
  "name": "Example Org",
  "auth_domain": "example.cloudflareaccess.com",
  "session_duration": "24h",
  "is_ui_read_only": false,
  "auto_redirect_to_identity": false,
  "login_design": {"background_color": "#fff", "logo_path": "/logo.png"},
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-02T00:00:00Z"
}'

DURATION_PATCH_JSON="$(access_org_patch_json "set-session-duration" "12h" "")"
assert_jq "session-duration patch" '.ok == true and .patch == {"session_duration":"12h"}' "${DURATION_PATCH_JSON}"

COMBO_DURATION_JSON="$(access_org_patch_json "set-session-duration" "1h30m" "")"
assert_jq "combined duration accepted" '.ok == true' "${COMBO_DURATION_JSON}"

BAD_DURATION_JSON="$(access_org_patch_json "set-session-duration" "tomorrow" "")"
assert_jq "invalid duration fails closed" '.ok == false and .error_code == "invalid_arguments"' "${BAD_DURATION_JSON}"

EMPTY_DURATION_JSON="$(access_org_patch_json "set-session-duration" "" "")"
assert_jq "empty duration fails closed" '.ok == false' "${EMPTY_DURATION_JSON}"

BOOL_PATCH_JSON="$(access_org_patch_json "set-ui-read-only" "true" "")"
assert_jq "ui-read-only patch" '.ok == true and .patch == {"is_ui_read_only":true}' "${BOOL_PATCH_JSON}"

BAD_BOOL_JSON="$(access_org_patch_json "set-auto-redirect-to-identity" "yes" "")"
assert_jq "non-boolean flag fails closed" '.ok == false and .error_code == "invalid_arguments"' "${BAD_BOOL_JSON}"

UPDATE_PATCH_JSON="$(access_org_patch_json "update" "" '{"login_design":{"background_color":"#000"}}')"
assert_jq "update patch passes through" '.ok == true and .patch.login_design.background_color == "#000"' "${UPDATE_PATCH_JSON}"

UPDATE_NO_BODY_JSON="$(access_org_patch_json "update" "" "")"
assert_jq "update without body fails closed" '.ok == false and .error_code == "body_required"' "${UPDATE_NO_BODY_JSON}"

UNSUPPORTED_JSON="$(access_org_patch_json "delete" "" "")"
assert_jq "unsupported operation fails closed" '.ok == false and .error_code == "unsupported_operation"' "${UNSUPPORTED_JSON}"

PLAN_JSON="$(access_org_plan_json "${ORG_JSON}" '{"session_duration":"12h"}' "account-1")"
assert_jq "plan targets the org PUT" '.status == "update" and .request.method == "PUT" and .request.path == "/accounts/account-1/access/organizations"' "${PLAN_JSON}"
assert_jq "plan changes only the targeted field" '.changed_fields == [{"field":"session_duration","before":"24h","after":"12h"}]' "${PLAN_JSON}"
assert_jq "plan preserves unrelated fields" '.request.body.name == "Example Org" and .request.body.login_design.logo_path == "/logo.png" and .request.body.is_ui_read_only == false' "${PLAN_JSON}"
assert_jq "plan strips read-only timestamps" '(.request.body | has("created_at") | not) and (.request.body | has("updated_at") | not)' "${PLAN_JSON}"

NOOP_PLAN_JSON="$(access_org_plan_json "${ORG_JSON}" '{"session_duration":"24h"}' "account-1")"
assert_jq "equal value is a noop" '.status == "noop" and .request == null and .summary.noop_count == 1' "${NOOP_PLAN_JSON}"

MERGE_PLAN_JSON="$(access_org_plan_json "${ORG_JSON}" '{"login_design":{"background_color":"#000"}}' "account-1")"
assert_jq "recursive merge keeps sibling keys" '.request.body.login_design.background_color == "#000" and .request.body.login_design.logo_path == "/logo.png"' "${MERGE_PLAN_JSON}"

VERIFY_OK_JSON="$(access_org_verify_json '{"session_duration":"12h","name":"Example Org"}' "${PLAN_JSON}")"
assert_jq "verify passes on matching readback" '.success == true and .result.checked_field_count == 1' "${VERIFY_OK_JSON}"

VERIFY_BAD_JSON="$(access_org_verify_json '{"session_duration":"24h"}' "${PLAN_JSON}")"
assert_jq "verify fails on stale readback" '.success == false and .errors[0].code == "readback_mismatch"' "${VERIFY_BAD_JSON}"

echo "access.organization contract verification passed."
