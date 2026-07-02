#!/usr/bin/env bash

# Mutates Cloudflare Access identity providers (login methods):
#   create: POST   /accounts/:id/access/identity_providers
#           `--type onetimepin` with no body synthesizes the canonical
#           {"name":"One-time PIN","type":"onetimepin","config":{}} body —
#           this is the account-wide OTP enable. Every other provider type
#           requires an operator-supplied --body/--body-file because provider
#           configs carry operator secrets that cfctl must not invent.
#           Creating onetimepin when one already exists is a noop.
#   update: PUT    /accounts/:id/access/identity_providers/:uuid (body required;
#           the live GET omits config secrets, so a blind read-modify-write
#           would blank them).
#   delete: DELETE /accounts/:id/access/identity_providers/:uuid
#           `--type onetimepin` resolves the singleton — the OTP disable.
#
# Inputs (env from cfctl apply dispatch):
#   OPERATION  create | update | delete
#   IDP_ID     provider id      (update/delete target; --id)
#   IDP_TYPE   provider type    (create type or update/delete target; --type)
#   IDP_NAME   provider name    (create name or update/delete target; --name)
#   BODY_JSON / BODY_FILE       provider body (--body / --body-file)
#   APPLY      0 plan-only | 1 apply
#
# Preview/ack gating is enforced centrally by cfctl_handle_apply; secret-ish
# config values are redacted before any body lands in an artifact.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

access_idp_resolve_target_json() {
  local providers_json="$1"
  local idp_id="$2"
  local idp_type="$3"
  local idp_name="$4"

  jq -n \
    --argjson providers "${providers_json}" \
    --arg idp_id "${idp_id}" \
    --arg idp_type "${idp_type}" \
    --arg idp_name "${idp_name}" \
    '
      ([ $idp_id, $idp_type, $idp_name ] | map(select(. != "")) | length) as $selector_count
      | (
          $providers
          | map({
              id,
              name: (.name // null),
              type: (.type // null)
            })
          | map(select(
              (if $idp_id != "" then .id == $idp_id else true end)
              and
              (if $idp_type != "" then .type == $idp_type else true end)
              and
              (if $idp_name != "" then .name == $idp_name else true end)
            ))
        ) as $matches
      | {
          ok: ($selector_count > 0 and ($matches | length) == 1),
          selector: ({
            id: (if $idp_id == "" then null else $idp_id end),
            type: (if $idp_type == "" then null else $idp_type end),
            name: (if $idp_name == "" then null else $idp_name end)
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
            if $selector_count == 0 then "Specify exactly one existing Access identity provider target with --id, --type, or --name."
            elif ($matches | length) == 0 then "No existing Access identity provider matched the selector."
            elif ($matches | length) > 1 then "Selector matched multiple Access identity providers; use --id or a more specific selector."
            else null
            end
          )
        }
    '
}

access_idp_build_create_body_json() {
  local idp_type="$1"
  local idp_name="$2"
  local body_json="$3"

  jq -n \
    --arg idp_type "${idp_type}" \
    --arg idp_name "${idp_name}" \
    --argjson body "$(if [[ -n "${body_json}" ]]; then printf '%s' "${body_json}"; else printf 'null'; fi)" \
    '
      if $body != null then
        ($body.type // "") as $body_type
        | if $body_type == "" and $idp_type == "" then
            {ok: false, body: null, error_code: "missing_type", error_message: "Provider body must declare .type, or pass --type."}
          elif $body_type != "" and $idp_type != "" and $body_type != $idp_type then
            {ok: false, body: null, error_code: "type_mismatch", error_message: "--type disagrees with body .type; drop one or make them match."}
          else
            {ok: true, body: ($body | .type = (if $body_type != "" then $body_type else $idp_type end)), error_code: null, error_message: null}
          end
      elif $idp_type == "onetimepin" then
        {
          ok: true,
          body: {
            name: (if $idp_name != "" then $idp_name else "One-time PIN" end),
            type: "onetimepin",
            config: {}
          },
          error_code: null,
          error_message: null
        }
      elif $idp_type == "" then
        {ok: false, body: null, error_code: "missing_type", error_message: "create requires --type (only onetimepin has a default body) or an explicit --body."}
      else
        {ok: false, body: null, error_code: "body_required", error_message: ("Provider type " + $idp_type + " requires an explicit --body/--body-file; cfctl only synthesizes the onetimepin body.")}
      end
    '
}

access_idp_redact_body_json() {
  local body_json="$1"

  jq -c '
    if type == "object" and (.config | type) == "object" then
      .config |= with_entries(
        if (.key | test("secret|token|password|private"; "i")) then .value = "[redacted]" else . end
      )
    else .
    end
  ' <<< "${body_json}"
}

access_idp_plan_json() {
  local operation="$1"
  local providers_json="$2"
  local target_json="$3"
  local body_redacted_json="$4"
  local account_id="$5"

  jq -n \
    --arg operation "${operation}" \
    --arg account_id "${account_id}" \
    --argjson providers "${providers_json}" \
    --argjson target "${target_json}" \
    --argjson body "${body_redacted_json}" \
    '
      (($providers | map(select(.type == "onetimepin")) | length) > 0) as $onetimepin_present
      | (
          if $operation == "create" then
            if ($body.type // "") == "onetimepin" and $onetimepin_present then
              {status: "noop", request: null}
            else
              {status: "create", request: {method: "POST", path: ("/accounts/" + $account_id + "/access/identity_providers"), body: $body}}
            end
          elif $operation == "update" then
            {status: "update", request: {method: "PUT", path: ("/accounts/" + $account_id + "/access/identity_providers/" + $target.id), body: $body}}
          else
            {status: "delete", request: {method: "DELETE", path: ("/accounts/" + $account_id + "/access/identity_providers/" + $target.id), body: null}}
          end
        ) as $change
      | {
          ok: true,
          operation: $operation,
          target: $target,
          desired: {
            type: ($body.type // ($target.type // null)),
            name: ($body.name // ($target.name // null))
          },
          change: $change,
          summary: {
            operation: $operation,
            status: $change.status,
            provider_count_before: ($providers | length),
            onetimepin_present_before: $onetimepin_present,
            update_count: (if $change.status == "noop" then 0 else 1 end),
            noop_count: (if $change.status == "noop" then 1 else 0 end),
            failure_count: 0
          }
        }
    '
}

access_idp_verify_json() {
  local operation="$1"
  local providers_json="$2"
  local target_id="$3"
  local desired_type="$4"
  local desired_name="$5"

  jq -n \
    --arg operation "${operation}" \
    --arg target_id "${target_id}" \
    --arg desired_type "${desired_type}" \
    --arg desired_name "${desired_name}" \
    --argjson providers "${providers_json}" \
    '
      (
        if $operation == "create" then
          ($providers | map(select(
            (if $desired_type != "" then .type == $desired_type else true end)
            and
            (if $desired_name != "" then .name == $desired_name else true end)
          ))) as $matches
          | {verified: (($matches | length) > 0), readback: $matches}
        elif $operation == "update" then
          ($providers | map(select(.id == $target_id))) as $matches
          | {
              verified: (
                ($matches | length) == 1
                and (if $desired_name != "" then $matches[0].name == $desired_name else true end)
                and (if $desired_type != "" then $matches[0].type == $desired_type else true end)
              ),
              readback: $matches
            }
        else
          ($providers | map(select(.id == $target_id))) as $matches
          | {verified: (($matches | length) == 0), readback: $matches}
        end
      ) as $check
      | {
          success: $check.verified,
          errors: (
            if $check.verified then []
            else [{code: "readback_mismatch", message: ("Access identity provider readback did not confirm the " + $operation + ".")}]
            end
          ),
          messages: [],
          result: {
            operation: $operation,
            target_id: (if $target_id == "" then null else $target_id end),
            readback: ($check.readback | map({id, name: (.name // null), type: (.type // null)}))
          }
        }
    '
}

access_idp_report_json() {
  local apply="$1"
  local operation="$2"
  local target_resolution_json="$3"
  local plan_json="$4"
  local mutation_response_json="$5"
  local verification_response_json="$6"
  local error_code="$7"
  local error_message="$8"

  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg apply "${apply}" \
    --arg operation "${operation}" \
    --arg error_code "${error_code}" \
    --arg error_message "${error_message}" \
    --argjson target_resolution "${target_resolution_json}" \
    --argjson plan "${plan_json}" \
    --argjson mutation_response "${mutation_response_json}" \
    --argjson verification_response "${verification_response_json}" \
    '
      (if $verification_response == null then 0 elif ($verification_response.success // false) then 0 else 1 end) as $verification_failure_count
      | (if $mutation_response == null then 0 elif ($mutation_response.success // false) then 0 else 1 end) as $mutation_failure_count
      | (($plan.summary // {operation: $operation, status: null, update_count: null, noop_count: null, failure_count: 0}) + {
          failure_count: (
            if $error_code != "" then 1
            else ($mutation_failure_count + $verification_failure_count)
            end
          )
        }) as $summary
      | {
          generated_at: $generated_at,
          surface: "access-idp",
          operation: $operation,
          apply: ($apply == "1"),
          target_resolution: $target_resolution,
          provider: ($target_resolution.provider // null),
          request: ($plan.change.request // null),
          plan: $plan,
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

access_idp_write_report() {
  local report_file="$1"
  local report_json="$2"

  report_json="$(cf_redact_json "${report_json}")"
  cf_write_json_file "${report_file}" "${report_json}"
}

access_idp_fail() {
  local report_file="$1"
  local apply="$2"
  local operation="$3"
  local target_resolution_json="$4"
  local plan_json="$5"
  local error_code="$6"
  local error_message="$7"
  local report_json

  report_json="$(access_idp_report_json "${apply}" "${operation}" "${target_resolution_json}" "${plan_json}" "null" "null" "${error_code}" "${error_message}")"
  access_idp_write_report "${report_file}" "${report_json}"
  echo "${report_json}" | jq '{summary, target_resolution: (.target_resolution | {ok, selector, match_count, error_code}), mutation_response}'
  cf_print_log_footer
  echo "${report_file}"
  exit 1
}

main() {
  cf_load_cloudflare_env
  cf_require_tools curl jq
  cf_require_api_auth
  cf_require_account_id
  cf_require_backend_dispatch "cfctl apply access.idp <operation> ..."
  cf_setup_log_pipe "operations" "build"

  local operation="${OPERATION:-}"
  local apply="${APPLY:-0}"
  local idp_id="${IDP_ID:-}"
  local idp_type="${IDP_TYPE:-}"
  local idp_name="${IDP_NAME:-}"
  local report_file
  local providers_response
  local providers_json
  local target_resolution_json='{"ok":true,"selector":{},"selector_count":0,"match_count":0,"provider":null,"matches":[],"error_code":null,"error_message":null}'
  local raw_body_json=""
  local body_build_json
  local body_redacted_json="null"
  local plan_json='{"ok":false,"summary":{"operation":null,"status":null,"update_count":null,"noop_count":null,"failure_count":1},"change":{"request":null}}'
  local mutation_response_json="null"
  local verification_response_json="null"
  local target_id=""
  local desired_type=""
  local desired_name=""
  local report_json
  local response
  local verify_response

  report_file="$(cf_inventory_file "operations" "access-idp-mutation")"

  case "${operation}" in
    create|update|delete) ;;
    *)
      access_idp_fail "${report_file}" "${apply}" "${operation}" "${target_resolution_json}" "${plan_json}" "unsupported_operation" "Unsupported access.idp operation: ${operation:-<empty>}"
      ;;
  esac

  providers_response="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/identity_providers")"
  if [[ "$(jq -r '.success == true' <<< "${providers_response}")" != "true" ]]; then
    access_idp_fail "${report_file}" "${apply}" "${operation}" "${target_resolution_json}" "${plan_json}" "providers_read_failed" "Unable to read Access identity providers."
  fi
  providers_json="$(jq -c '(.result // []) | map({id, name: (.name // null), type: (.type // null)})' <<< "${providers_response}")"

  if [[ -n "${BODY_JSON:-}" || -n "${BODY_FILE:-}" ]]; then
    raw_body_json="$(cf_resolve_json_payload "${BODY_JSON:-}" "${BODY_FILE:-}")"
  fi

  if [[ "${operation}" == "update" || "${operation}" == "delete" ]]; then
    target_resolution_json="$(access_idp_resolve_target_json "${providers_json}" "${idp_id}" "${idp_type}" "${idp_name}")"
    if [[ "$(jq -r '.ok == true' <<< "${target_resolution_json}")" != "true" ]]; then
      access_idp_fail "${report_file}" "${apply}" "${operation}" "${target_resolution_json}" "${plan_json}" "$(jq -r '.error_code' <<< "${target_resolution_json}")" "$(jq -r '.error_message' <<< "${target_resolution_json}")"
    fi
    target_id="$(jq -r '.provider.id' <<< "${target_resolution_json}")"
  fi

  case "${operation}" in
    create)
      body_build_json="$(access_idp_build_create_body_json "${idp_type}" "${idp_name}" "${raw_body_json}")"
      if [[ "$(jq -r '.ok == true' <<< "${body_build_json}")" != "true" ]]; then
        access_idp_fail "${report_file}" "${apply}" "${operation}" "${target_resolution_json}" "${plan_json}" "$(jq -r '.error_code' <<< "${body_build_json}")" "$(jq -r '.error_message' <<< "${body_build_json}")"
      fi
      raw_body_json="$(jq -c '.body' <<< "${body_build_json}")"
      ;;
    update)
      if [[ -z "${raw_body_json}" ]]; then
        access_idp_fail "${report_file}" "${apply}" "${operation}" "${target_resolution_json}" "${plan_json}" "body_required" "update requires --body/--body-file: the live GET omits provider config secrets, so cfctl cannot build a safe read-modify-write body."
      fi
      raw_body_json="$(
        jq -c \
          --argjson target "$(jq -c '.provider' <<< "${target_resolution_json}")" \
          '.type = (.type // $target.type) | .name = (.name // $target.name)' \
          <<< "${raw_body_json}"
      )"
      ;;
    delete)
      raw_body_json=""
      ;;
  esac

  if [[ -n "${raw_body_json}" ]]; then
    body_redacted_json="$(access_idp_redact_body_json "${raw_body_json}")"
  fi

  plan_json="$(access_idp_plan_json "${operation}" "${providers_json}" "$(jq -c '.provider' <<< "${target_resolution_json}")" "${body_redacted_json}" "${CLOUDFLARE_ACCOUNT_ID}")"
  desired_type="$(jq -r '.desired.type // ""' <<< "${plan_json}")"
  desired_name="$(jq -r '.desired.name // ""' <<< "${plan_json}")"

  echo "Prepared Access identity-provider mutation."
  echo "${plan_json}" | jq '{operation, target, desired, change, summary}'

  if [[ "${apply}" != "1" ]]; then
    report_json="$(access_idp_report_json "${apply}" "${operation}" "${target_resolution_json}" "${plan_json}" "null" "null" "" "")"
    access_idp_write_report "${report_file}" "${report_json}"
    echo "Dry run only. Re-run through cfctl with --ack-plan <operation-id> to apply."
    cf_print_log_footer
    echo "${report_file}"
    exit 0
  fi

  if [[ "$(jq -r '.change.status' <<< "${plan_json}")" == "noop" ]]; then
    verification_response_json="$(access_idp_verify_json "${operation}" "${providers_json}" "${target_id}" "${desired_type}" "${desired_name}")"
    report_json="$(access_idp_report_json "${apply}" "${operation}" "${target_resolution_json}" "${plan_json}" '{"success":true,"errors":[],"messages":["noop: desired state already present"],"result":null}' "${verification_response_json}" "" "")"
    access_idp_write_report "${report_file}" "${report_json}"
    echo "${report_json}" | jq '{summary, verification}'
    cf_print_log_footer
    echo "${report_file}"
    exit 0
  fi

  if [[ -n "${raw_body_json}" ]]; then
    response="$(
      cf_api_capture "$(jq -r '.change.request.method' <<< "${plan_json}")" "$(jq -r '.change.request.path' <<< "${plan_json}")" \
        -H "Content-Type: application/json" \
        --data "${raw_body_json}"
    )"
  else
    response="$(cf_api_capture "$(jq -r '.change.request.method' <<< "${plan_json}")" "$(jq -r '.change.request.path' <<< "${plan_json}")")"
  fi
  mutation_response_json="$(
    jq -c '
      .result = (
        if (.result | type) == "object" then
          {id: .result.id, name: (.result.name // null), type: (.result.type // null)}
        else null
        end
      )
    ' <<< "${response}"
  )"

  if [[ "$(jq -r '.success == true' <<< "${mutation_response_json}")" != "true" ]]; then
    report_json="$(access_idp_report_json "${apply}" "${operation}" "${target_resolution_json}" "${plan_json}" "${mutation_response_json}" "null" "" "")"
    access_idp_write_report "${report_file}" "${report_json}"
    echo "${report_json}" | jq '{summary, mutation_response}'
    cf_print_log_footer
    echo "${report_file}"
    exit 1
  fi

  verify_response="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/identity_providers")"
  if [[ "$(jq -r '.success == true' <<< "${verify_response}")" == "true" ]]; then
    verification_response_json="$(access_idp_verify_json "${operation}" "$(jq -c '.result // []' <<< "${verify_response}")" "${target_id}" "${desired_type}" "${desired_name}")"
  else
    verification_response_json="${verify_response}"
  fi

  report_json="$(access_idp_report_json "${apply}" "${operation}" "${target_resolution_json}" "${plan_json}" "${mutation_response_json}" "${verification_response_json}" "" "")"
  access_idp_write_report "${report_file}" "${report_json}"
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
