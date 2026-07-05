#!/usr/bin/env bash

# Live Access posture audit: evaluates the account's Access applications and
# identity providers against machine pass/fail checks, each tagged with the
# catalog/standards.json id it enforces. This is live Cloudflare truth — the
# deliberate counterpart to the source-config-only `cfctl standards audit`.
#
# OTP intent: an app legitimately allows the onetimepin provider when a
# desired-state spec in state/access.app/*.json lists the OTP provider id in
# body.allowed_idps for that app's domain. Everything else that allows OTP is
# flagged, so OTP exposure is always a recorded decision.
#
# Inputs (env from cfctl audit dispatch):
#   APP_ID / APP_DOMAIN  optional scope to one application

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

access_posture_checks_json() {
  local apps_json="$1"
  local providers_json="$2"
  local intended_json="$3"
  local app_id="$4"
  local app_domain="$5"

  jq -n \
    --argjson apps "${apps_json}" \
    --argjson providers "${providers_json}" \
    --argjson intended "${intended_json}" \
    --arg app_id "${app_id}" \
    --arg app_domain "${app_domain}" \
    '
      def offender_row: {id, name: (.name // null), domain: (.domain // null)};

      (
        $apps
        | map(select(
            (if $app_id != "" then .id == $app_id else true end)
            and
            (if $app_domain != "" then .domain == $app_domain else true end)
          ))
      ) as $scoped
      | ($scoped | map(select(.type == "self_hosted"))) as $self_hosted
      | (($providers | map(select(.type == "onetimepin")) | first // null)) as $otp
      | ($otp.id // null) as $otp_id
      | (
          $intended
          | map(select($otp_id != null and ((.allowed_idps // []) | index($otp_id)) != null))
          | map(.domain)
          | map(select(. != null))
        ) as $otp_intended_domains
      | [
          (
            ($self_hosted | map(select((.allowed_idps // []) | length == 0)) | map(offender_row)) as $offenders
            | {
                id: "self_hosted_apps_have_explicit_idps",
                standard_ref: "access.app.allowed-idps-explicit",
                level: "required",
                title: "Every self_hosted app pins an explicit allowed_idps set",
                status: (if ($offenders | length) == 0 then "pass" else "fail" end),
                offender_count: ($offenders | length),
                offenders: $offenders
              }
          ),
          (
            (
              if $otp_id == null then []
              else
                $scoped
                | map(select(((.allowed_idps // []) | index($otp_id)) != null))
                | map(select(.domain as $domain | ($otp_intended_domains | index($domain)) == null))
                | map(
                    offender_row
                    + {
                        app_launcher_visible: (.app_launcher_visible == true),
                        auto_redirect_to_identity: (.auto_redirect_to_identity == true),
                        has_allow_policy: (((.policies // []) | map(select((.decision // "") == "allow")) | length) > 0)
                      }
                  )
              end
            ) as $offenders
            | {
                id: "otp_only_where_intended",
                standard_ref: "access.login_method.multi-idp-explicit",
                level: "required",
                title: "The onetimepin login method is only allowed where desired state records it",
                status: (if ($offenders | length) == 0 then "pass" else "fail" end),
                otp_provider_id: $otp_id,
                intended_domains: $otp_intended_domains,
                offender_count: ($offenders | length),
                offenders: $offenders
              }
          ),
          (
            ($self_hosted | map(select(.app_launcher_visible == true)) | map(offender_row)) as $offenders
            | {
                id: "self_hosted_not_launcher_visible",
                standard_ref: "access.app.explicit-identity-shape",
                level: "recommended",
                title: "self_hosted apps stay out of the app launcher unless deliberately published",
                status: (if ($offenders | length) == 0 then "pass" else "fail" end),
                offender_count: ($offenders | length),
                offenders: $offenders
              }
          ),
          (
            ($self_hosted | map(select(.auto_redirect_to_identity == false)) | map(offender_row)) as $offenders
            | {
                id: "self_hosted_auto_redirect_explicit",
                standard_ref: "access.login_method.full-app-put",
                level: "recommended",
                title: "self_hosted apps auto-redirect to their identity provider",
                status: (if ($offenders | length) == 0 then "pass" else "fail" end),
                offender_count: ($offenders | length),
                offenders: $offenders
              }
          ),
          (
            (
              $self_hosted
              | map(select(((.policies // []) | map(select((.decision // "") == "allow")) | length) == 0))
              | map(offender_row)
            ) as $offenders
            | {
                id: "every_self_hosted_app_has_allow_policy",
                standard_ref: "access.policy.match-logic-explicit",
                level: "required",
                title: "Every self_hosted app carries at least one allow policy",
                status: (if ($offenders | length) == 0 then "pass" else "fail" end),
                offender_count: ($offenders | length),
                offenders: $offenders
              }
          ),
          (
            (
              if $otp_id == null then []
              else
                $intended
                | map(select(((.allowed_idps // []) | index($otp_id)) != null))
                | (if $app_domain != "" then map(select(.domain == $app_domain)) else . end)
                | map(
                    (.classification // "") as $c
                    | select((["authenticated_counterparty_portal", "intentional_public_carveout"] | index($c)) == null)
                  )
                | map({domain: (.domain // null), classification: (.classification // null)})
              end
            ) as $offenders
            | {
                id: "otp_intent_specs_justified",
                standard_ref: "access.idp.otp-deliberate",
                level: "required",
                title: "Every desired-state spec that grants onetimepin records a justified OTP intent",
                status: (if ($offenders | length) == 0 then "pass" else "fail" end),
                offender_count: ($offenders | length),
                offenders: $offenders
              }
          )
        ] as $checks
      | {
          scope: ({
            app_id: (if $app_id == "" then null else $app_id end),
            app_domain: (if $app_domain == "" then null else $app_domain end)
          } | with_entries(select(.value != null))),
          scoped_app_count: ($scoped | length),
          self_hosted_app_count: ($self_hosted | length),
          otp: {
            provider_present: ($otp_id != null),
            provider_id: $otp_id,
            intended_domains: $otp_intended_domains
          },
          checks: $checks,
          summary: {
            check_count: ($checks | length),
            pass_count: ($checks | map(select(.status == "pass")) | length),
            fail_count: ($checks | map(select(.status == "fail" and .level == "required")) | length),
            warning_count: ($checks | map(select(.status == "fail" and .level == "recommended")) | length),
            offender_total: ($checks | map(.offender_count) | add),
            failing_checks: ($checks | map(select(.status == "fail")) | map(.id))
          }
        }
    '
}

main() {
  cf_load_cloudflare_env
  cf_require_tools curl jq
  cf_require_api_auth
  cf_require_account_id
  cf_setup_log_pipe "audit-access-posture" "build"

  local app_id="${APP_ID:-}"
  local app_domain="${APP_DOMAIN:-}"
  local apps_response
  local providers_response
  local intended_json='[]'
  local checks_json
  local report_json
  local output_file
  local intended_files

  apps_response="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps")"
  providers_response="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/identity_providers")"

  intended_files=("${ROOT_DIR}/state/access.app"/*.json)
  if [[ -e "${intended_files[0]}" ]]; then
    intended_json="$(
      jq -sc 'map({domain: (.match.domain // null), allowed_idps: (.body.allowed_idps // []), classification: (.intent.classification // null)})' \
        "${intended_files[@]}"
    )"
  fi

  checks_json="$(
    access_posture_checks_json \
      "$(jq -c '.result // []' <<< "${apps_response}")" \
      "$(jq -c '.result // []' <<< "${providers_response}")" \
      "${intended_json}" \
      "${app_id}" \
      "${app_domain}"
  )"

  output_file="$(cf_inventory_file "access" "access-posture")"
  report_json="$(
    jq -n \
      --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
      --argjson checks "${checks_json}" \
      '{generated_at: $generated_at} + $checks'
  )"

  cf_write_json_file "${output_file}" "${report_json}"

  echo "Audited live Access posture."
  echo "${report_json}" | jq '.summary + {otp_login_enabled: .otp.provider_present}'
  cf_print_log_footer
  echo "${output_file}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
