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

PLAN_JSON="$(access_login_method_plan_json "${APPS_JSON}" '{"id":"otp-1","name":"One-time PIN","type":"onetimepin"}' "account-1" "" "" "")"
assert_jq "plan sees drift" '.ok == true and .summary.target_count == 1 and .summary.update_count == 1 and .changes[0].status == "update"' "${PLAN_JSON}"
assert_jq "body keeps app type" '.changes[0].request.body.type == "self_hosted"' "${PLAN_JSON}"
assert_jq "body normalizes policies" '.changes[0].request.body.policies == [{"id":"policy-1","precedence":1}]' "${PLAN_JSON}"
assert_jq "body preserves unrelated settings" '.changes[0].request.body.session_duration == "24h" and .changes[0].request.body.auto_redirect_to_identity == false' "${PLAN_JSON}"
assert_jq "body drops read-only fields" '(.changes[0].request.body | has("id") | not) and (.changes[0].request.body | has("uid") | not) and (.changes[0].request.body | has("aud") | not) and (.changes[0].request.body | has("created_at") | not) and (.changes[0].request.body | has("updated_at") | not) and (.changes[0].request.body | has("tags") | not)' "${PLAN_JSON}"

PINNED_PLAN_JSON="$(access_login_method_plan_json '[{"id":"app-1","name":"Docs","domain":"docs.example.org","type":"self_hosted","allowed_idps":["otp-1"],"policies":[]}]' '{"id":"otp-1","name":"One-time PIN","type":"onetimepin"}' "account-1" "" "" "")"
assert_jq "already pinned is noop" '.summary.update_count == 0 and .summary.noop_count == 1 and .changes[0].status == "noop"' "${PINNED_PLAN_JSON}"

echo "access.login_method contract verification passed."
