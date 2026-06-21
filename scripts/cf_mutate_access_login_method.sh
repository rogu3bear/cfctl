#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

access_login_method_resolve_provider_json() {
  local providers_json="$1"
  local provider_id="$2"
  local provider_type="$3"
  local provider_name="$4"

  jq -n \
    --argjson providers "${providers_json}" \
    --arg provider_id "${provider_id}" \
    --arg provider_type "${provider_type}" \
    --arg provider_name "${provider_name}" \
    '
      ([ $provider_id, $provider_type, $provider_name ] | map(select(. != "")) | length) as $selector_count
      | (
          $providers
          | map({
              id,
              name: (.name // null),
              type: (.type // null)
            })
          | map(select(
              (if $provider_id != "" then .id == $provider_id else true end)
              and
              (if $provider_type != "" then .type == $provider_type else true end)
              and
              (if $provider_name != "" then .name == $provider_name else true end)
            ))
        ) as $matches
      | {
          ok: ($selector_count > 0 and ($matches | length) == 1),
          selector: ({
            id: (if $provider_id == "" then null else $provider_id end),
            type: (if $provider_type == "" then null else $provider_type end),
            name: (if $provider_name == "" then null else $provider_name end)
          } | with_entries(select(.value != null))),
          selector_count: $selector_count,
          match_count: ($matches | length),
          provider: (if ($matches | length) == 1 then $matches[0] else null end),
          matches: $matches,
          error_code: (
            if $selector_count == 0 then "missing_provider_selector"
            elif ($matches | length) == 0 then "provider_not_found"
            elif ($matches | length) > 1 then "provider_ambiguous"
            else null
            end
          ),
          error_message: (
            if $selector_count == 0 then "Specify exactly one existing Access identity provider target with --provider-id, --provider-type, or --provider-name."
            elif ($matches | length) == 0 then "No existing Access identity provider matched the provider selector."
            elif ($matches | length) > 1 then "Provider selector matched multiple Access identity providers; use --provider-id or a more specific selector."
            else null
            end
          )
        }
    '
}

access_login_method_plan_json() {
  local apps_json="$1"
  local provider_json="$2"
  local account_id="$3"
  local app_id="$4"
  local app_name="$5"
  local app_domain="$6"

  jq -n \
    --argjson apps "${apps_json}" \
    --argjson provider "${provider_json}" \
    --arg account_id "${account_id}" \
    --arg app_id "${app_id}" \
    --arg app_name "${app_name}" \
    --arg app_domain "${app_domain}" \
    '
      def mutable_body($provider_id):
        del(.id, .uid, .aud, .created_at, .updated_at, .tags)
        | .allowed_idps = [$provider_id]
        | .policies = ((.policies // []) | map({id: (.id // null), precedence: (.precedence // null)}));

      (
        $apps
        | map(select(
            (if $app_id != "" then .id == $app_id else true end)
            and
            (if $app_name != "" then .name == $app_name else true end)
            and
            (if $app_domain != "" then .domain == $app_domain else true end)
          ))
      ) as $targets
      | (
          $targets
          | map(
              . as $app
              | (($app.allowed_idps // []) == [$provider.id]) as $already_pinned
              | {
                  app: {
                    id: $app.id,
                    name: ($app.name // null),
                    domain: ($app.domain // null),
                    type: ($app.type // null)
                  },
                  allowed_idps_before: ($app.allowed_idps // []),
                  desired_allowed_idps: [$provider.id],
                  desired_provider: $provider,
                  auto_redirect_to_identity: ($app.auto_redirect_to_identity // null),
                  policy_decisions: (($app.policies // []) | map(.decision // empty) | unique),
                  status: (if $already_pinned then "noop" else "update" end),
                  request: {
                    method: "PUT",
                    path: ("/accounts/" + $account_id + "/access/apps/" + $app.id),
                    body: ($app | mutable_body($provider.id))
                  }
                }
            )
        ) as $changes
      | {
          provider: $provider,
          target_selector: ({
            id: (if $app_id == "" then null else $app_id end),
            name: (if $app_name == "" then null else $app_name end),
            domain: (if $app_domain == "" then null else $app_domain end)
          } | with_entries(select(.value != null))),
          changes: $changes,
          summary: {
            target_count: ($targets | length),
            update_count: ($changes | map(select(.status == "update")) | length),
            noop_count: ($changes | map(select(.status == "noop")) | length),
            failure_count: 0,
            provider_id: $provider.id,
            provider_name: ($provider.name // null),
            provider_type: ($provider.type // null),
            app_ids: ($targets | map(.id))
          },
          ok: (($targets | length) > 0),
          error_code: (if ($targets | length) == 0 then "target_not_found" else null end),
          error_message: (if ($targets | length) == 0 then "No Access applications matched the app selector." else null end)
        }
    '
}

access_login_method_verify_json() {
  local apps_json="$1"
  local plan_json="$2"

  jq -n \
    --argjson apps "${apps_json}" \
    --argjson plan "${plan_json}" \
    '
      ($plan.provider.id) as $provider_id
      | ($plan.summary.app_ids // []) as $target_ids
      | (
          $target_ids
          | map(. as $app_id | ($apps[]? | select(.id == $app_id)) as $app | {
              id: $app_id,
              name: ($app.name // null),
              domain: ($app.domain // null),
              allowed_idps: ($app.allowed_idps // []),
              verified: (($app.allowed_idps // []) == [$provider_id])
            })
        ) as $rows
      | {
          success: (($rows | map(select(.verified != true)) | length) == 0 and ($rows | length) == ($target_ids | length)),
          errors: (
            if (($rows | map(select(.verified != true)) | length) == 0 and ($rows | length) == ($target_ids | length)) then []
            else [{
              code: "readback_mismatch",
              message: "One or more targeted Access applications did not read back with exactly the desired identity provider."
            }]
            end
          ),
          messages: [],
          result: {
            provider_id: $provider_id,
            target_count: ($target_ids | length),
            verified_count: ($rows | map(select(.verified == true)) | length),
            apps: $rows,
            failures: ($rows | map(select(.verified != true)))
          }
        }
    '
}

access_login_method_report_json() {
  local apply="$1"
  local operation="$2"
  local provider_resolution_json="$3"
  local plan_json="$4"
  local mutation_results_json="$5"
  local verification_response_json="$6"
  local error_code="$7"
  local error_message="$8"

  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg apply "${apply}" \
    --arg operation "${operation}" \
    --arg error_code "${error_code}" \
    --arg error_message "${error_message}" \
    --argjson provider_resolution "${provider_resolution_json}" \
    --argjson plan "${plan_json}" \
    --argjson mutation_results "${mutation_results_json}" \
    --argjson verification_response "${verification_response_json}" \
    '
      ($mutation_results | map(select(.success != true)) | length) as $mutation_failure_count
      | (if $verification_response == null then 0 elif ($verification_response.success // false) then 0 else 1 end) as $verification_failure_count
      | (($plan.summary // {
          target_count: null,
          update_count: null,
          noop_count: null,
          failure_count: 0
        }) + {
          failure_count: (
            if $error_code != "" then 1
            else ($mutation_failure_count + $verification_failure_count)
            end
          )
        }) as $summary
      | {
          generated_at: $generated_at,
          surface: "access-login-method",
          operation: $operation,
          apply: ($apply == "1"),
          provider_resolution: $provider_resolution,
          provider: ($provider_resolution.provider // $plan.provider // null),
          request: {
            operation: $operation,
            target_selector: ($plan.target_selector // {}),
            provider_selector: ($provider_resolution.selector // {}),
            update_count: ($summary.update_count // null),
            changes: (($plan.changes // []) | map({
              app: .app,
              status: .status,
              path: .request.path
            }))
          },
          summary: $summary,
          changes: ($plan.changes // []),
          mutation_response: (
            if $error_code != "" then {
              success: false,
              errors: [{code: $error_code, message: $error_message}],
              messages: [],
              result: null
            }
            elif $apply != "1" then null
            else {
              success: ($mutation_failure_count == 0),
              errors: (
                $mutation_results
                | map(select(.success != true))
                | map({code: "mutation_failed", message: ("Access app update failed for " + (.app_id // "unknown"))})
              ),
              messages: [],
              result: $mutation_results
            }
            end
          ),
          verification: {
            response: $verification_response
          }
        }
    '
}

access_login_method_write_report() {
  local report_file="$1"
  local report_json="$2"

  report_json="$(cf_redact_json "${report_json}")"
  cf_write_json_file "${report_file}" "${report_json}"
}

main() {
  cf_load_cloudflare_env
  cf_require_tools curl jq
  cf_require_api_auth
  cf_require_account_id
  cf_require_backend_dispatch "cfctl apply access.login_method set ..."
  cf_setup_log_pipe "operations" "build"

  local operation="${OPERATION:-set}"
  local apply="${APPLY:-0}"
  local app_id="${APP_ID:-}"
  local app_name="${APP_NAME:-}"
  local app_domain="${APP_DOMAIN:-}"
  local provider_id="${PROVIDER_ID:-}"
  local provider_type="${PROVIDER_TYPE:-}"
  local provider_name="${PROVIDER_NAME:-}"
  local report_file
  local apps_response
  local providers_response
  local apps_json
  local providers_json
  local provider_resolution_json
  local provider_json
  local plan_json
  local mutation_results_json="[]"
  local verification_response_json="null"
  local report_json
  local row
  local response
  local response_redacted
  local verify_response

  report_file="$(cf_inventory_file "operations" "access-login-method-mutation")"

  if [[ "${operation}" != "set" ]]; then
    provider_resolution_json="$(jq -n '{ok:false, selector:{}, selector_count:0, match_count:0, provider:null, matches:[], error_code:"unsupported_operation", error_message:"Unsupported access.login_method operation."}')"
    plan_json="$(jq -n '{ok:false, summary:{target_count:null, update_count:null, noop_count:null, failure_count:1}, changes:[] }')"
    report_json="$(access_login_method_report_json "${apply}" "${operation}" "${provider_resolution_json}" "${plan_json}" "[]" "null" "unsupported_operation" "Unsupported access.login_method operation.")"
    access_login_method_write_report "${report_file}" "${report_json}"
    echo "${report_json}" | jq '{summary, mutation_response}'
    cf_print_log_footer
    echo "${report_file}"
    exit 1
  fi

  apps_response="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps")"
  providers_response="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/identity_providers")"

  if [[ "$(jq -r '.success == true' <<< "${apps_response}")" != "true" ]]; then
    provider_resolution_json="$(jq -n '{ok:false, selector:{}, selector_count:0, match_count:0, provider:null, matches:[], error_code:"apps_read_failed", error_message:"Unable to read Access applications."}')"
    plan_json="$(jq -n --argjson apps "${apps_response}" '{ok:false, summary:{target_count:null, update_count:null, noop_count:null, failure_count:1}, changes:[], apps_response:$apps}')"
    report_json="$(access_login_method_report_json "${apply}" "${operation}" "${provider_resolution_json}" "${plan_json}" "[]" "null" "apps_read_failed" "Unable to read Access applications.")"
    access_login_method_write_report "${report_file}" "${report_json}"
    echo "${report_json}" | jq '{summary, mutation_response}'
    cf_print_log_footer
    echo "${report_file}"
    exit 1
  fi

  if [[ "$(jq -r '.success == true' <<< "${providers_response}")" != "true" ]]; then
    provider_resolution_json="$(jq -n '{ok:false, selector:{}, selector_count:0, match_count:0, provider:null, matches:[], error_code:"providers_read_failed", error_message:"Unable to read Access identity providers."}')"
    plan_json="$(jq -n --argjson providers "${providers_response}" '{ok:false, summary:{target_count:null, update_count:null, noop_count:null, failure_count:1}, changes:[], providers_response:$providers}')"
    report_json="$(access_login_method_report_json "${apply}" "${operation}" "${provider_resolution_json}" "${plan_json}" "[]" "null" "providers_read_failed" "Unable to read Access identity providers.")"
    access_login_method_write_report "${report_file}" "${report_json}"
    echo "${report_json}" | jq '{summary, mutation_response}'
    cf_print_log_footer
    echo "${report_file}"
    exit 1
  fi

  apps_json="$(jq -c '.result // []' <<< "${apps_response}")"
  providers_json="$(jq -c '.result // []' <<< "${providers_response}")"
  provider_resolution_json="$(access_login_method_resolve_provider_json "${providers_json}" "${provider_id}" "${provider_type}" "${provider_name}")"

  if [[ "$(jq -r '.ok == true' <<< "${provider_resolution_json}")" != "true" ]]; then
    plan_json="$(jq -n '{ok:false, summary:{target_count:null, update_count:null, noop_count:null, failure_count:1}, changes:[] }')"
    report_json="$(access_login_method_report_json "${apply}" "${operation}" "${provider_resolution_json}" "${plan_json}" "[]" "null" "$(jq -r '.error_code' <<< "${provider_resolution_json}")" "$(jq -r '.error_message' <<< "${provider_resolution_json}")")"
    access_login_method_write_report "${report_file}" "${report_json}"
    echo "${report_json}" | jq '{summary, provider_resolution, mutation_response}'
    cf_print_log_footer
    echo "${report_file}"
    exit 1
  fi

  provider_json="$(jq -c '.provider' <<< "${provider_resolution_json}")"
  plan_json="$(access_login_method_plan_json "${apps_json}" "${provider_json}" "${CLOUDFLARE_ACCOUNT_ID}" "${app_id}" "${app_name}" "${app_domain}")"

  if [[ "$(jq -r '.ok == true' <<< "${plan_json}")" != "true" ]]; then
    report_json="$(access_login_method_report_json "${apply}" "${operation}" "${provider_resolution_json}" "${plan_json}" "[]" "null" "$(jq -r '.error_code' <<< "${plan_json}")" "$(jq -r '.error_message' <<< "${plan_json}")")"
    access_login_method_write_report "${report_file}" "${report_json}"
    echo "${report_json}" | jq '{summary, mutation_response}'
    cf_print_log_footer
    echo "${report_file}"
    exit 1
  fi

  echo "Prepared Access login-method reconciliation."
  echo "${plan_json}" | jq '{provider, target_selector, summary, changes: (.changes | map({app, status, allowed_idps_before, desired_allowed_idps}))}'

  if [[ "${apply}" != "1" ]]; then
    report_json="$(access_login_method_report_json "${apply}" "${operation}" "${provider_resolution_json}" "${plan_json}" "[]" "null" "" "")"
    access_login_method_write_report "${report_file}" "${report_json}"
    echo "Dry run only. Re-run through cfctl with --ack-plan <operation-id> to update drifted apps."
    cf_print_log_footer
    echo "${report_file}"
    exit 0
  fi

  while IFS= read -r row; do
    [[ -n "${row}" ]] || continue
    response="$(
      cf_api_capture PUT "$(jq -r '.request.path' <<< "${row}")" \
        -H "Content-Type: application/json" \
        --data "$(jq -c '.request.body' <<< "${row}")"
    )"
    response_redacted="$(cf_redact_json "${response}")"
    mutation_results_json="$(
      jq \
        --argjson row "${row}" \
        --argjson response "${response_redacted}" \
        '
          . + [{
            app_id: $row.app.id,
            app_name: $row.app.name,
            app_domain: $row.app.domain,
            success: ($response.success // false),
            response: $response
          }]
        ' <<< "${mutation_results_json}"
    )"
  done < <(jq -c '.changes[] | select(.status == "update")' <<< "${plan_json}")

  if [[ "$(jq -r 'map(select(.success != true)) | length' <<< "${mutation_results_json}")" != "0" ]]; then
    verification_response_json="$(jq -n '{success:false, errors:[{code:"mutation_failed", message:"One or more Access app updates failed; readback verification was skipped."}], messages:[], result:null}')"
    report_json="$(access_login_method_report_json "${apply}" "${operation}" "${provider_resolution_json}" "${plan_json}" "${mutation_results_json}" "${verification_response_json}" "" "")"
    access_login_method_write_report "${report_file}" "${report_json}"
    echo "${report_json}" | jq '{summary, mutation_response, verification}'
    cf_print_log_footer
    echo "${report_file}"
    exit 1
  fi

  verify_response="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps")"
  if [[ "$(jq -r '.success == true' <<< "${verify_response}")" == "true" ]]; then
    verification_response_json="$(access_login_method_verify_json "$(jq -c '.result // []' <<< "${verify_response}")" "${plan_json}")"
  else
    verification_response_json="${verify_response}"
  fi

  report_json="$(access_login_method_report_json "${apply}" "${operation}" "${provider_resolution_json}" "${plan_json}" "${mutation_results_json}" "${verification_response_json}" "" "")"
  access_login_method_write_report "${report_file}" "${report_json}"
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
