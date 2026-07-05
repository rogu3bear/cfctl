#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/cf_audit_access_posture.sh"

fail() {
  echo "access posture contract verification failed: $*" >&2
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

ALLOW_POLICY='[{"id":"p1","decision":"allow","precedence":1}]'

CLEAN_APPS_JSON='[
  {"id":"app-1","name":"Docs","domain":"docs.example.org","type":"self_hosted","allowed_idps":["saml-1"],"app_launcher_visible":false,"auto_redirect_to_identity":true,"policies":[{"id":"p1","decision":"allow","precedence":1}]}
]'

CLEAN_JSON="$(access_posture_checks_json "${CLEAN_APPS_JSON}" '[{"id":"saml-1","name":"Okta","type":"saml"}]' "[]" "" "")"
assert_jq "clean fixture passes every check" '.summary.fail_count == 0 and .summary.warning_count == 0 and .summary.pass_count == .summary.check_count' "${CLEAN_JSON}"
assert_jq "otp check passes when provider absent" '(.checks[] | select(.id == "otp_only_where_intended") | .status) == "pass" and .otp.provider_present == false' "${CLEAN_JSON}"
assert_jq "otp intent check passes with no otp specs" '(.checks[] | select(.id == "otp_intent_specs_justified") | .status) == "pass"' "${CLEAN_JSON}"

DIRTY_APPS_JSON='[
  {"id":"app-1","name":"Bare","domain":"bare.example.org","type":"self_hosted","allowed_idps":[],"app_launcher_visible":true,"auto_redirect_to_identity":false,"policies":[]},
  {"id":"app-2","name":"OtpApp","domain":"otp.example.org","type":"self_hosted","allowed_idps":["otp-1"],"app_launcher_visible":false,"auto_redirect_to_identity":true,"policies":[{"id":"p1","decision":"allow","precedence":1}]},
  {"id":"app-3","name":"Intended","domain":"intended.example.org","type":"self_hosted","allowed_idps":["otp-1"],"app_launcher_visible":false,"auto_redirect_to_identity":true,"policies":[{"id":"p2","decision":"allow","precedence":1}]}
]'
INTENDED_JSON='[
  {"domain":"intended.example.org","allowed_idps":["otp-1"],"classification":"authenticated_counterparty_portal"},
  {"domain":"quieted.example.org","allowed_idps":["otp-1"],"classification":null}
]'

DIRTY_JSON="$(access_posture_checks_json "${DIRTY_APPS_JSON}" "${PROVIDERS_JSON}" "${INTENDED_JSON}" "" "")"
assert_jq "empty allowed_idps fails required check" '(.checks[] | select(.id == "self_hosted_apps_have_explicit_idps") | .status) == "fail" and ((.checks[] | select(.id == "self_hosted_apps_have_explicit_idps") | .offenders | map(.id)) == ["app-1"])' "${DIRTY_JSON}"
assert_jq "unintended otp fails with annotated offender row" '((.checks[] | select(.id == "otp_only_where_intended") | .offenders) == [{"id":"app-2","name":"OtpApp","domain":"otp.example.org","app_launcher_visible":false,"auto_redirect_to_identity":true,"has_allow_policy":true}])' "${DIRTY_JSON}"
assert_jq "otp check records intent source" '(.checks[] | select(.id == "otp_only_where_intended") | .intended_domains) == ["intended.example.org","quieted.example.org"]' "${DIRTY_JSON}"
assert_jq "launcher visibility warns" '(.checks[] | select(.id == "self_hosted_not_launcher_visible") | .status) == "fail" and (.checks[] | select(.id == "self_hosted_not_launcher_visible") | .level) == "recommended"' "${DIRTY_JSON}"
assert_jq "missing allow policy fails" '((.checks[] | select(.id == "every_self_hosted_app_has_allow_policy") | .offenders | map(.id)) == ["app-1"])' "${DIRTY_JSON}"
assert_jq "summary separates required fails from warnings" '.summary.fail_count == 4 and .summary.warning_count == 2 and (.summary.failing_checks | length) == 6' "${DIRTY_JSON}"
assert_jq "unjustified otp spec fails the intent check" '((.checks[] | select(.id == "otp_intent_specs_justified") | .status) == "fail") and ((.checks[] | select(.id == "otp_intent_specs_justified") | .offenders) == [{"domain":"quieted.example.org","classification":null}])' "${DIRTY_JSON}"

SCOPED_JSON="$(access_posture_checks_json "${DIRTY_APPS_JSON}" "${PROVIDERS_JSON}" "${INTENDED_JSON}" "" "otp.example.org")"
assert_jq "domain scope limits the audit" '.scoped_app_count == 1 and (.checks[] | select(.id == "self_hosted_apps_have_explicit_idps") | .status) == "pass" and ((.checks[] | select(.id == "otp_only_where_intended") | .offenders | map(.id)) == ["app-2"])' "${SCOPED_JSON}"
assert_jq "domain scope limits the otp intent check" '(.checks[] | select(.id == "otp_intent_specs_justified") | .status) == "pass"' "${SCOPED_JSON}"

NO_OTP_PROVIDER_JSON="$(access_posture_checks_json "${DIRTY_APPS_JSON}" '[{"id":"saml-1","name":"Okta","type":"saml"}]' "${INTENDED_JSON}" "" "")"
assert_jq "otp check passes account-wide when provider deleted" '(.checks[] | select(.id == "otp_only_where_intended") | .status) == "pass"' "${NO_OTP_PROVIDER_JSON}"
assert_jq "otp intent check passes when provider deleted" '(.checks[] | select(.id == "otp_intent_specs_justified") | .status) == "pass"' "${NO_OTP_PROVIDER_JSON}"

echo "access posture contract verification passed."
