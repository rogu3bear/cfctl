#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/cf_mutate_access_identity_provider.sh"

fail() {
  echo "access.idp contract verification failed: $*" >&2
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

RESOLVED_JSON="$(access_idp_resolve_target_json "${PROVIDERS_JSON}" "" "onetimepin" "")"
assert_jq "onetimepin target resolves by type" '.ok == true and .provider.id == "otp-1"' "${RESOLVED_JSON}"

RESOLVED_BY_ID_JSON="$(access_idp_resolve_target_json "${PROVIDERS_JSON}" "saml-1" "" "")"
assert_jq "target resolves by id" '.ok == true and .provider.type == "saml"' "${RESOLVED_BY_ID_JSON}"

MISSING_JSON="$(access_idp_resolve_target_json "${PROVIDERS_JSON}" "" "github" "")"
assert_jq "missing target fails closed" '.ok == false and .error_code == "provider_not_found"' "${MISSING_JSON}"

NO_SELECTOR_JSON="$(access_idp_resolve_target_json "${PROVIDERS_JSON}" "" "" "")"
assert_jq "empty selector fails closed" '.ok == false and .error_code == "missing_provider_selector"' "${NO_SELECTOR_JSON}"

AMBIGUOUS_JSON="$(access_idp_resolve_target_json '[{"id":"a","name":"Shared","type":"saml"},{"id":"b","name":"Shared","type":"oidc"}]' "" "" "Shared")"
assert_jq "ambiguous target fails closed" '.ok == false and .error_code == "provider_ambiguous" and .match_count == 2' "${AMBIGUOUS_JSON}"

OTP_BODY_JSON="$(access_idp_build_create_body_json "onetimepin" "" "")"
assert_jq "onetimepin default body" '.ok == true and .body == {"name":"One-time PIN","type":"onetimepin","config":{}}' "${OTP_BODY_JSON}"

OTP_NAMED_BODY_JSON="$(access_idp_build_create_body_json "onetimepin" "Email PIN" "")"
assert_jq "onetimepin default body honors --name" '.ok == true and .body.name == "Email PIN"' "${OTP_NAMED_BODY_JSON}"

SAML_NO_BODY_JSON="$(access_idp_build_create_body_json "saml" "" "")"
assert_jq "non-otp create requires body" '.ok == false and .error_code == "body_required"' "${SAML_NO_BODY_JSON}"

NO_TYPE_JSON="$(access_idp_build_create_body_json "" "" "")"
assert_jq "typeless create fails closed" '.ok == false and .error_code == "missing_type"' "${NO_TYPE_JSON}"

TYPE_MISMATCH_JSON="$(access_idp_build_create_body_json "saml" "" '{"name":"X","type":"oidc","config":{}}')"
assert_jq "type mismatch fails closed" '.ok == false and .error_code == "type_mismatch"' "${TYPE_MISMATCH_JSON}"

EXPLICIT_BODY_JSON="$(access_idp_build_create_body_json "" "" '{"name":"Okta","type":"saml","config":{"issuer_url":"https://x"}}')"
assert_jq "explicit body passes through" '.ok == true and .body.type == "saml" and .body.config.issuer_url == "https://x"' "${EXPLICIT_BODY_JSON}"

REDACTED_JSON="$(access_idp_redact_body_json '{"name":"Okta","type":"oidc","config":{"client_id":"public-id","client_secret":"super-secret","auth_url":"https://x"}}')"
assert_jq "config secrets are redacted" '.config.client_secret == "[redacted]" and .config.client_id == "public-id" and .config.auth_url == "https://x"' "${REDACTED_JSON}"

CREATE_PLAN_JSON="$(access_idp_plan_json "create" '[{"id":"saml-1","name":"Okta","type":"saml"}]' "null" '{"name":"One-time PIN","type":"onetimepin","config":{}}' "account-1")"
assert_jq "otp create plans a POST" '.change.status == "create" and .change.request.method == "POST" and .change.request.path == "/accounts/account-1/access/identity_providers"' "${CREATE_PLAN_JSON}"

NOOP_PLAN_JSON="$(access_idp_plan_json "create" "${PROVIDERS_JSON}" "null" '{"name":"One-time PIN","type":"onetimepin","config":{}}' "account-1")"
assert_jq "otp create is noop when already enabled" '.change.status == "noop" and .change.request == null and .summary.noop_count == 1' "${NOOP_PLAN_JSON}"

DELETE_PLAN_JSON="$(access_idp_plan_json "delete" "${PROVIDERS_JSON}" '{"id":"otp-1","name":"One-time PIN","type":"onetimepin"}' "null" "account-1")"
assert_jq "otp delete plans a DELETE by id" '.change.status == "delete" and .change.request.method == "DELETE" and .change.request.path == "/accounts/account-1/access/identity_providers/otp-1"' "${DELETE_PLAN_JSON}"

UPDATE_PLAN_JSON="$(access_idp_plan_json "update" "${PROVIDERS_JSON}" '{"id":"saml-1","name":"Okta","type":"saml"}' '{"name":"Okta Renamed","type":"saml","config":{}}' "account-1")"
assert_jq "update plans a PUT by id" '.change.status == "update" and .change.request.method == "PUT" and .change.request.path == "/accounts/account-1/access/identity_providers/saml-1"' "${UPDATE_PLAN_JSON}"

CREATE_VERIFY_JSON="$(access_idp_verify_json "create" "${PROVIDERS_JSON}" "" "onetimepin" "One-time PIN")"
assert_jq "create verify passes on readback" '.success == true and (.result.readback | length) == 1' "${CREATE_VERIFY_JSON}"

CREATE_VERIFY_MISSING_JSON="$(access_idp_verify_json "create" '[{"id":"saml-1","name":"Okta","type":"saml"}]' "" "onetimepin" "")"
assert_jq "create verify fails when provider absent" '.success == false and .errors[0].code == "readback_mismatch"' "${CREATE_VERIFY_MISSING_JSON}"

DELETE_VERIFY_JSON="$(access_idp_verify_json "delete" '[{"id":"saml-1","name":"Okta","type":"saml"}]' "otp-1" "" "")"
assert_jq "delete verify passes when provider gone" '.success == true' "${DELETE_VERIFY_JSON}"

DELETE_VERIFY_PRESENT_JSON="$(access_idp_verify_json "delete" "${PROVIDERS_JSON}" "otp-1" "" "")"
assert_jq "delete verify fails when provider persists" '.success == false' "${DELETE_VERIFY_PRESENT_JSON}"

UPDATE_VERIFY_JSON="$(access_idp_verify_json "update" '[{"id":"saml-1","name":"Okta Renamed","type":"saml"}]' "saml-1" "saml" "Okta Renamed")"
assert_jq "update verify checks readback fields" '.success == true' "${UPDATE_VERIFY_JSON}"

echo "access.idp contract verification passed."
