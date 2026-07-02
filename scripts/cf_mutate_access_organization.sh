#!/usr/bin/env bash

# Mutates the Cloudflare Access organization (Zero Trust org settings — a
# singleton with account-wide blast radius) via field-scoped
# read-modify-write. The live GET returns the full org object (no secrets),
# so every operation merges onto live state and PUTs the merged body — never
# a blind replace:
#   set-session-duration          SETTING_VALUE like "24h" / "30m" / "1h30m"
#   set-ui-read-only              SETTING_VALUE true|false
#   set-auto-redirect-to-identity SETTING_VALUE true|false
#   update                        BODY_JSON/BODY_FILE merged (recursive) onto live org
#
# Inputs (env from cfctl apply dispatch):
#   OPERATION      one of the operations above
#   SETTING_VALUE  value for the field-scoped operations (--content)
#   BODY_JSON / BODY_FILE  patch object for update (--body / --body-file)
#   APPLY          0 plan-only | 1 apply
#
# Preview/ack gating is enforced centrally by cfctl_handle_apply.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

access_org_patch_json() {
  local operation="$1"
  local setting_value="$2"
  local patch_body_json="$3"

  jq -n \
    --arg operation "${operation}" \
    --arg setting_value "${setting_value}" \
    --argjson patch "$(if [[ -n "${patch_body_json}" ]]; then printf '%s' "${patch_body_json}"; else printf 'null'; fi)" \
    '
      def bool_or_null($raw):
        if $raw == "true" then true elif $raw == "false" then false else null end;

      if $operation == "set-session-duration" then
        if ($setting_value | test("^([0-9]+h)?([0-9]+m)?$")) and $setting_value != "" then
          {ok: true, patch: {session_duration: $setting_value}, error_code: null, error_message: null}
        else
          {ok: false, patch: null, error_code: "invalid_arguments", error_message: "set-session-duration requires --content like 24h, 30m, or 1h30m."}
        end
      elif $operation == "set-ui-read-only" then
        bool_or_null($setting_value) as $flag
        | if $flag == null then
            {ok: false, patch: null, error_code: "invalid_arguments", error_message: "set-ui-read-only requires --content true or false."}
          else
            {ok: true, patch: {is_ui_read_only: $flag}, error_code: null, error_message: null}
          end
      elif $operation == "set-auto-redirect-to-identity" then
        bool_or_null($setting_value) as $flag
        | if $flag == null then
            {ok: false, patch: null, error_code: "invalid_arguments", error_message: "set-auto-redirect-to-identity requires --content true or false."}
          else
            {ok: true, patch: {auto_redirect_to_identity: $flag}, error_code: null, error_message: null}
          end
      elif $operation == "update" then
        if $patch == null or ($patch | type) != "object" then
          {ok: false, patch: null, error_code: "body_required", error_message: "update requires --body/--body-file with a JSON object patch."}
        elif ($patch | length) == 0 then
          {ok: false, patch: null, error_code: "invalid_arguments", error_message: "update patch must set at least one field."}
        else
          {ok: true, patch: $patch, error_code: null, error_message: null}
        end
      else
        {ok: false, patch: null, error_code: "unsupported_operation", error_message: ("Unsupported access.organization operation: " + $operation)}
      end
    '
}

access_org_plan_json() {
  local org_json="$1"
  local patch_json="$2"
  local account_id="$3"

  jq -n \
    --argjson org "${org_json}" \
    --argjson patch "${patch_json}" \
    --arg account_id "${account_id}" \
    '
      def mutable_body:
        del(.created_at, .updated_at);

      ($org | mutable_body) as $current
      | ($current * $patch) as $desired
      | ($patch | keys) as $patched_keys
      | ($patched_keys | map(select($current[.] != $desired[.]))) as $changed_keys
      | {
          ok: true,
          changed_fields: (
            $changed_keys
            | map({field: ., before: $current[.], after: $desired[.]})
          ),
          patched_keys: $patched_keys,
          status: (if ($changed_keys | length) == 0 then "noop" else "update" end),
          request: (
            if ($changed_keys | length) == 0 then null
            else {
              method: "PUT",
              path: ("/accounts/" + $account_id + "/access/organizations"),
              body: $desired
            }
            end
          ),
          summary: {
            status: (if ($changed_keys | length) == 0 then "noop" else "update" end),
            changed_field_count: ($changed_keys | length),
            update_count: (if ($changed_keys | length) == 0 then 0 else 1 end),
            noop_count: (if ($changed_keys | length) == 0 then 1 else 0 end),
            failure_count: 0
          }
        }
    '
}

access_org_verify_json() {
  local org_json="$1"
  local plan_json="$2"

  jq -n \
    --argjson org "${org_json}" \
    --argjson plan "${plan_json}" \
    '
      ($plan.changed_fields // []) as $expected
      | (
          $expected
          | map(. as $change | {
              field: $change.field,
              expected: $change.after,
              actual: $org[$change.field],
              verified: ($org[$change.field] == $change.after)
            })
        ) as $rows
      | {
          success: (($rows | map(select(.verified != true)) | length) == 0),
          errors: (
            if (($rows | map(select(.verified != true)) | length) == 0) then []
            else [{code: "readback_mismatch", message: "Access organization readback did not match the planned field changes."}]
            end
          ),
          messages: [],
          result: {
            checked_field_count: ($rows | length),
            fields: $rows
          }
        }
    '
}

access_org_report_json() {
  local apply="$1"
  local operation="$2"
  local plan_json="$3"
  local mutation_response_json="$4"
  local verification_response_json="$5"
  local error_code="$6"
  local error_message="$7"

  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg apply "${apply}" \
    --arg operation "${operation}" \
    --arg error_code "${error_code}" \
    --arg error_message "${error_message}" \
    --argjson plan "${plan_json}" \
    --argjson mutation_response "${mutation_response_json}" \
    --argjson verification_response "${verification_response_json}" \
    '
      (if $verification_response == null then 0 elif ($verification_response.success // false) then 0 else 1 end) as $verification_failure_count
      | (if $mutation_response == null then 0 elif ($mutation_response.success // false) then 0 else 1 end) as $mutation_failure_count
      | (($plan.summary // {status: null, changed_field_count: null, update_count: null, noop_count: null, failure_count: 0}) + {
          operation: $operation,
          failure_count: (
            if $error_code != "" then 1
            else ($mutation_failure_count + $verification_failure_count)
            end
          )
        }) as $summary
      | {
          generated_at: $generated_at,
          surface: "access-organization",
          operation: $operation,
          apply: ($apply == "1"),
          changed_fields: ($plan.changed_fields // []),
          request: ($plan.request // null),
          summary: $summary,
          mutation_response: (
            if $error_code != "" then {
              success: false,
              errors: [{code: $error_code, message: $error_message}],
              messages: [],
              result: null
            }
            else $mutation_response
            end
          ),
          verification: {
            response: $verification_response
          }
        }
    '
}

access_org_write_report() {
  local report_file="$1"
  local report_json="$2"

  report_json="$(cf_redact_json "${report_json}")"
  cf_write_json_file "${report_file}" "${report_json}"
}

access_org_fail() {
  local report_file="$1"
  local apply="$2"
  local operation="$3"
  local plan_json="$4"
  local error_code="$5"
  local error_message="$6"
  local report_json

  report_json="$(access_org_report_json "${apply}" "${operation}" "${plan_json}" "null" "null" "${error_code}" "${error_message}")"
  access_org_write_report "${report_file}" "${report_json}"
  echo "${report_json}" | jq '{summary, mutation_response}'
  cf_print_log_footer
  echo "${report_file}"
  exit 1
}

main() {
  cf_load_cloudflare_env
  cf_require_tools curl jq
  cf_require_api_auth
  cf_require_account_id
  cf_require_backend_dispatch "cfctl apply access.organization <operation> ..."
  cf_setup_log_pipe "operations" "build"

  local operation="${OPERATION:-}"
  local apply="${APPLY:-0}"
  local setting_value="${SETTING_VALUE:-}"
  local patch_body_json=""
  local report_file
  local org_response
  local org_json
  local patch_build_json
  local patch_json
  local plan_json='{"ok":false,"changed_fields":[],"request":null,"summary":{"status":null,"changed_field_count":null,"update_count":null,"noop_count":null,"failure_count":1}}'
  local mutation_response_json="null"
  local verification_response_json="null"
  local report_json
  local response
  local verify_response

  report_file="$(cf_inventory_file "operations" "access-organization-mutation")"

  if [[ -n "${BODY_JSON:-}" || -n "${BODY_FILE:-}" ]]; then
    patch_body_json="$(cf_resolve_json_payload "${BODY_JSON:-}" "${BODY_FILE:-}")"
  fi

  patch_build_json="$(access_org_patch_json "${operation}" "${setting_value}" "${patch_body_json}")"
  if [[ "$(jq -r '.ok == true' <<< "${patch_build_json}")" != "true" ]]; then
    access_org_fail "${report_file}" "${apply}" "${operation}" "${plan_json}" "$(jq -r '.error_code' <<< "${patch_build_json}")" "$(jq -r '.error_message' <<< "${patch_build_json}")"
  fi
  patch_json="$(jq -c '.patch' <<< "${patch_build_json}")"

  org_response="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/organizations")"
  if [[ "$(jq -r '.success == true' <<< "${org_response}")" != "true" ]]; then
    access_org_fail "${report_file}" "${apply}" "${operation}" "${plan_json}" "organization_read_failed" "Unable to read the Access organization."
  fi
  org_json="$(jq -c '.result // {}' <<< "${org_response}")"

  plan_json="$(access_org_plan_json "${org_json}" "${patch_json}" "${CLOUDFLARE_ACCOUNT_ID}")"

  echo "Prepared Access organization mutation."
  echo "${plan_json}" | jq '{status, changed_fields, summary}'

  if [[ "${apply}" != "1" ]]; then
    report_json="$(access_org_report_json "${apply}" "${operation}" "${plan_json}" "null" "null" "" "")"
    access_org_write_report "${report_file}" "${report_json}"
    echo "Dry run only. Re-run through cfctl with --ack-plan <operation-id> to apply."
    cf_print_log_footer
    echo "${report_file}"
    exit 0
  fi

  if [[ "$(jq -r '.status' <<< "${plan_json}")" == "noop" ]]; then
    report_json="$(access_org_report_json "${apply}" "${operation}" "${plan_json}" '{"success":true,"errors":[],"messages":["noop: desired state already present"],"result":null}' '{"success":true,"errors":[],"messages":[],"result":{"checked_field_count":0,"fields":[]}}' "" "")"
    access_org_write_report "${report_file}" "${report_json}"
    echo "${report_json}" | jq '{summary, verification}'
    cf_print_log_footer
    echo "${report_file}"
    exit 0
  fi

  response="$(
    cf_api_capture PUT "$(jq -r '.request.path' <<< "${plan_json}")" \
      -H "Content-Type: application/json" \
      --data "$(jq -c '.request.body' <<< "${plan_json}")"
  )"
  mutation_response_json="$(cf_redact_json "${response}")"

  if [[ "$(jq -r '.success == true' <<< "${mutation_response_json}")" != "true" ]]; then
    report_json="$(access_org_report_json "${apply}" "${operation}" "${plan_json}" "${mutation_response_json}" "null" "" "")"
    access_org_write_report "${report_file}" "${report_json}"
    echo "${report_json}" | jq '{summary, mutation_response}'
    cf_print_log_footer
    echo "${report_file}"
    exit 1
  fi

  verify_response="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/organizations")"
  if [[ "$(jq -r '.success == true' <<< "${verify_response}")" == "true" ]]; then
    verification_response_json="$(access_org_verify_json "$(jq -c '.result // {}' <<< "${verify_response}")" "${plan_json}")"
  else
    verification_response_json="${verify_response}"
  fi

  report_json="$(access_org_report_json "${apply}" "${operation}" "${plan_json}" "${mutation_response_json}" "${verification_response_json}" "" "")"
  access_org_write_report "${report_file}" "${report_json}"
  echo "${report_json}" | jq '{summary, mutation_response, verification}'
  cf_print_log_footer
  echo "${report_file}"

  if [[ "$(jq -r '.success == true' <<< "${verification_response_json}")" != "true" ]]; then
    exit 1
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
