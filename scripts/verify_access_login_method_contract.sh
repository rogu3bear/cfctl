#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/cf_mutate_access_login_method.sh"

fail() {
  echo "access.login_method contract verification failed: $*" >&2
  exit 1
}

assert_jq() {
  local label="$1"
  local expr="$2"
  local payload="$3"

  jq -e "${expr}" <<< "${payload}" >/dev/null || fail "${label}: ${expr}"
}

PROVIDERS_JSON='[
  {"id":"otp-1","name":"One-time PIN","type":"onetimepin"},
  {"id":"saml-1","name":"Okta","type":"saml"}
]'

RESOLVED_JSON="$(access_login_method_resolve_provider_json "${PROVIDERS_JSON}" "" "onetimepin" "")"
assert_jq "onetimepin provider resolves" '.ok == true and .provider.id == "otp-1"' "${RESOLVED_JSON}"

MISSING_JSON="$(access_login_method_resolve_provider_json "${PROVIDERS_JSON}" "" "github" "")"
assert_jq "missing provider fails" '.ok == false and .error_code == "provider_not_found"' "${MISSING_JSON}"

DUPLICATE_TYPE_JSON="$(access_login_method_resolve_provider_json '[{"id":"otp-1","name":"OTP 1","type":"onetimepin"},{"id":"otp-2","name":"OTP 2","type":"onetimepin"}]' "" "onetimepin" "")"
assert_jq "duplicate provider type fails" '.ok == false and .error_code == "provider_ambiguous" and .match_count == 2' "${DUPLICATE_TYPE_JSON}"

DUPLICATE_NAME_JSON="$(access_login_method_resolve_provider_json '[{"id":"otp-1","name":"Shared","type":"onetimepin"},{"id":"saml-1","name":"Shared","type":"saml"}]' "" "" "Shared")"
assert_jq "duplicate provider name fails" '.ok == false and .error_code == "provider_ambiguous" and .match_count == 2' "${DUPLICATE_NAME_JSON}"

APPS_JSON='[
  {
    "id":"app-1",
    "uid":"uid-1",
    "aud":"aud-1",
    "created_at":"2026-01-01T00:00:00Z",
    "updated_at":"2026-01-02T00:00:00Z",
    "tags":["do-not-send"],
    "name":"Docs",
    "domain":"docs.example.org",
    "type":"self_hosted",
    "allowed_idps":["saml-1"],
    "auto_redirect_to_identity":false,
    "session_duration":"24h",
    "policies":[
      {"id":"policy-1","name":"Allow","decision":"allow","precedence":1,"include":[{"everyone":{}}]}
    ]
  }
]'

OTP_PROVIDERS_JSON='[{"id":"otp-1","name":"One-time PIN","type":"onetimepin"}]'

PLAN_JSON="$(access_login_method_plan_json "${APPS_JSON}" "set" "${OTP_PROVIDERS_JSON}" "account-1" "" "" "")"
assert_jq "plan sees drift" '.ok == true and .summary.target_count == 1 and .summary.update_count == 1 and .changes[0].status == "update"' "${PLAN_JSON}"
assert_jq "plan pins exactly the provider" '.changes[0].desired_allowed_idps == ["otp-1"] and .changes[0].request.body.allowed_idps == ["otp-1"]' "${PLAN_JSON}"
assert_jq "body keeps app type" '.changes[0].request.body.type == "self_hosted"' "${PLAN_JSON}"
assert_jq "body normalizes policies" '.changes[0].request.body.policies == [{"id":"policy-1","precedence":1}]' "${PLAN_JSON}"
assert_jq "body preserves unrelated settings" '.changes[0].request.body.session_duration == "24h" and .changes[0].request.body.auto_redirect_to_identity == false' "${PLAN_JSON}"
assert_jq "body drops read-only fields" '(.changes[0].request.body | has("id") | not) and (.changes[0].request.body | has("uid") | not) and (.changes[0].request.body | has("aud") | not) and (.changes[0].request.body | has("created_at") | not) and (.changes[0].request.body | has("updated_at") | not) and (.changes[0].request.body | has("tags") | not)' "${PLAN_JSON}"

PINNED_PLAN_JSON="$(access_login_method_plan_json '[{"id":"app-1","name":"Docs","domain":"docs.example.org","type":"self_hosted","allowed_idps":["otp-1"],"policies":[]}]' "set" "${OTP_PROVIDERS_JSON}" "account-1" "" "" "")"
assert_jq "already pinned is noop" '.summary.update_count == 0 and .summary.noop_count == 1 and .changes[0].status == "noop"' "${PINNED_PLAN_JSON}"

MULTI_RESOLVED_JSON="$(access_login_method_resolve_providers_json "${PROVIDERS_JSON}" '["otp-1","saml-1"]')"
assert_jq "multi resolver matches all ids" '.ok == true and .match_count == 2 and (.matches | map(.id)) == ["otp-1","saml-1"]' "${MULTI_RESOLVED_JSON}"

MULTI_MISSING_JSON="$(access_login_method_resolve_providers_json "${PROVIDERS_JSON}" '["otp-1","ghost-1"]')"
assert_jq "multi resolver fails closed on missing id" '.ok == false and .error_code == "provider_not_found" and .missing == ["ghost-1"]' "${MULTI_MISSING_JSON}"

MULTI_EMPTY_JSON="$(access_login_method_resolve_providers_json "${PROVIDERS_JSON}" '[]')"
assert_jq "multi resolver requires at least one id" '.ok == false and .error_code == "missing_provider_selector"' "${MULTI_EMPTY_JSON}"

MULTI_APP_JSON='[{"id":"app-1","name":"Docs","domain":"docs.example.org","type":"self_hosted","allowed_idps":["saml-1"],"policies":[]}]'

SET_LIST_PLAN_JSON="$(access_login_method_plan_json "${MULTI_APP_JSON}" "set-list" '[{"id":"otp-1","name":"One-time PIN","type":"onetimepin"},{"id":"saml-1","name":"Okta","type":"saml"}]' "account-1" "" "" "")"
assert_jq "set-list pins the explicit set" '.ok == true and .changes[0].status == "update" and .changes[0].desired_allowed_idps == ["otp-1","saml-1"] and .changes[0].request.body.allowed_idps == ["otp-1","saml-1"]' "${SET_LIST_PLAN_JSON}"

SET_LIST_NOOP_JSON="$(access_login_method_plan_json '[{"id":"app-1","name":"Docs","domain":"docs.example.org","type":"self_hosted","allowed_idps":["saml-1","otp-1"],"policies":[]}]' "set-list" '[{"id":"otp-1","name":"One-time PIN","type":"onetimepin"},{"id":"saml-1","name":"Okta","type":"saml"}]' "account-1" "" "" "")"
assert_jq "set-list is order-insensitive for noop" '.ok == true and .changes[0].status == "noop" and .summary.noop_count == 1' "${SET_LIST_NOOP_JSON}"

ADD_PLAN_JSON="$(access_login_method_plan_json "${MULTI_APP_JSON}" "add" "${OTP_PROVIDERS_JSON}" "account-1" "" "" "")"
assert_jq "add unions the provider into the current set" '.ok == true and .changes[0].status == "update" and .changes[0].desired_allowed_idps == ["saml-1","otp-1"]' "${ADD_PLAN_JSON}"

ADD_NOOP_JSON="$(access_login_method_plan_json '[{"id":"app-1","name":"Docs","domain":"docs.example.org","type":"self_hosted","allowed_idps":["saml-1","otp-1"],"policies":[]}]' "add" "${OTP_PROVIDERS_JSON}" "account-1" "" "" "")"
assert_jq "add is idempotent" '.changes[0].status == "noop"' "${ADD_NOOP_JSON}"

REMOVE_PLAN_JSON="$(access_login_method_plan_json '[{"id":"app-1","name":"Docs","domain":"docs.example.org","type":"self_hosted","allowed_idps":["saml-1","otp-1"],"policies":[]}]' "remove" "${OTP_PROVIDERS_JSON}" "account-1" "" "" "")"
assert_jq "remove subtracts the provider" '.ok == true and .changes[0].status == "update" and .changes[0].desired_allowed_idps == ["saml-1"] and .changes[0].request.body.allowed_idps == ["saml-1"]' "${REMOVE_PLAN_JSON}"

REMOVE_NOOP_JSON="$(access_login_method_plan_json "${MULTI_APP_JSON}" "remove" "${OTP_PROVIDERS_JSON}" "account-1" "" "" "")"
assert_jq "remove of an absent provider is a noop" '.changes[0].status == "noop"' "${REMOVE_NOOP_JSON}"

REMOVE_EMPTY_JSON="$(access_login_method_plan_json '[{"id":"app-1","name":"Docs","domain":"docs.example.org","type":"self_hosted","allowed_idps":["otp-1"],"policies":[]}]' "remove" "${OTP_PROVIDERS_JSON}" "account-1" "" "" "")"
assert_jq "remove refuses to empty allowed_idps" '.ok == false and .error_code == "empty_allowed_idps_result" and .changes[0].status == "blocked_empty_result" and .changes[0].request == null' "${REMOVE_EMPTY_JSON}"

VERIFY_OK_JSON="$(access_login_method_verify_json '[{"id":"app-1","name":"Docs","domain":"docs.example.org","allowed_idps":["otp-1","saml-1"]}]' "${SET_LIST_PLAN_JSON}")"
assert_jq "verify accepts order-insensitive readback" '.success == true and .result.verified_count == 1' "${VERIFY_OK_JSON}"

VERIFY_MISMATCH_JSON="$(access_login_method_verify_json '[{"id":"app-1","name":"Docs","domain":"docs.example.org","allowed_idps":["saml-1"]}]' "${SET_LIST_PLAN_JSON}")"
assert_jq "verify rejects mismatched readback" '.success == false and .errors[0].code == "readback_mismatch"' "${VERIFY_MISMATCH_JSON}"

echo "access.login_method contract verification passed."
