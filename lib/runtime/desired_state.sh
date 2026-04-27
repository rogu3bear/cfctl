#!/usr/bin/env bash

set -euo pipefail

cfctl_state_specs_dir() {
  local surface="$1"
  local configured_dir="${CFCTL_STATE_DIR:-}"

  if [[ -n "${configured_dir}" ]]; then
    printf '%s\n' "${configured_dir}"
    return
  fi

  local relative_dir
  relative_dir="$(cfctl_surface_state_dir "${surface}")"
  if [[ -z "${relative_dir}" ]]; then
    echo ""
    return
  fi

  printf '%s/%s\n' "${CF_REPO_ROOT}" "${relative_dir}"
}

cfctl_load_state_specs() {
  local surface="$1"
  local spec_dir
  local specs='[]'
  local spec_file

  spec_dir="$(cfctl_state_specs_dir "${surface}")"
  if [[ -z "${spec_dir}" || ! -d "${spec_dir}" ]]; then
    printf '[]\n'
    return
  fi

  while IFS= read -r spec_file; do
    local raw_spec
    raw_spec="$(jq -c '.' "${spec_file}")"
    specs="$(
      jq \
        --arg surface "${surface}" \
        --arg spec_path "${spec_file}" \
        --argjson spec "${raw_spec}" \
        '
          . + [
            {
              surface: $surface,
              spec_path: $spec_path,
              match: ($spec.match // {}),
              body: ($spec.body // null),
              delete: ($spec.delete // false),
              spec: $spec
            }
          ]
        ' \
        <<< "${specs}"
    )"
  done < <(find "${spec_dir}" -type f -name '*.json' | sort)

  printf '%s\n' "${specs}"
}

cfctl_filter_specs_by_current_selectors() {
  local surface="$1"
  local specs_json="$2"
  local filtered="${specs_json}"
  local target_json
  local selector
  local value

  target_json="$(cfctl_target_json)"
  while IFS= read -r selector; do
    value="$(jq -c --arg key "${selector}" '.[$key] // empty' <<< "${target_json}")"
    if [[ -z "${value}" ]]; then
      continue
    fi

    filtered="$(
      jq \
        --arg selector "${selector}" \
        --argjson expected "${value}" \
        '
          [
            .[]
            | select(
                if (.match | has($selector)) then
                  .match[$selector] == $expected
                else
                  true
                end
              )
          ]
        ' \
        <<< "${filtered}"
    )"
  done < <(jq -r 'keys[]' <<< "${target_json}")

  printf '%s\n' "${filtered}"
}

cfctl_filter_items_by_match() {
  local surface="$1"
  local items_json="$2"
  local match_json="$3"
  local filtered="${items_json}"
  local row

  while IFS= read -r row; do
    local selector
    local field
    local expected
    selector="$(jq -r '.key' <<< "${row}")"
    field="$(cfctl_selector_to_item_field "${surface}" "${selector}")"
    expected="$(jq -c '.value' <<< "${row}")"

    filtered="$(
      jq \
        --arg field "${field}" \
        --argjson expected "${expected}" \
        '
          [
            .[]
            | select(.[$field] == $expected)
          ]
        ' \
        <<< "${filtered}"
    )"
  done < <(jq -c 'to_entries[]' <<< "${match_json}")

  printf '%s\n' "${filtered}"
}

cfctl_pick_actual_subset_for_desired() {
  local actual_json="$1"
  local desired_json="$2"

  jq -n \
    --argjson actual "${actual_json}" \
    --argjson desired "${desired_json}" \
    '
      reduce ($desired | keys_unsorted[]) as $key
        ({};
          . + {
            ($key): ($actual[$key] // null)
          }
        )
    '
}

cfctl_diff_surface_json() {
  local surface="$1"
  local actual_items_json="$2"
  local specs_json="$3"
  local diffs='[]'
  local spec_row

  while IFS= read -r spec_row; do
    local match_json
    local matched_items
    local match_count
    local delete_requested
    local desired_body
    local actual_item
    local actual_subset
    local differing_fields
    local status
    local proposed_operation

    match_json="$(jq -c '.match // {}' <<< "${spec_row}")"
    delete_requested="$(jq -r '.delete == true' <<< "${spec_row}")"

    if [[ "${match_json}" == "{}" ]]; then
      diffs="$(
        jq \
          --argjson spec "${spec_row}" \
          '. + [{
            spec_path: $spec.spec_path,
            match: $spec.match,
            status: "invalid_spec",
            proposed_operation: "invalid",
            delete: ($spec.delete // false),
            actual_count: 0,
            differing_fields: [],
            desired_body: ($spec.body // null),
            actual_item: null,
            actual_subset: null
          }]' \
          <<< "${diffs}"
      )"
      continue
    fi

    matched_items="$(cfctl_filter_items_by_match "${surface}" "${actual_items_json}" "${match_json}")"
    match_count="$(jq 'length' <<< "${matched_items}")"

    if [[ "${match_count}" == "0" ]]; then
      if [[ "${delete_requested}" == "true" ]]; then
        status="absent"
        proposed_operation="noop"
      else
        status="missing_actual"
        proposed_operation="create"
      fi
      desired_body="$(cfctl_prepare_sync_body "${surface}" "${spec_row}")"
      actual_subset="null"
      differing_fields='[]'
    elif [[ "${match_count}" != "1" ]]; then
      status="ambiguous_actual"
      proposed_operation="review"
      desired_body="$(cfctl_prepare_sync_body "${surface}" "${spec_row}")"
      actual_subset="null"
      differing_fields='[]'
    else
      actual_item="$(jq '.[0]' <<< "${matched_items}")"

      if [[ "${delete_requested}" == "true" ]]; then
        status="delete_requested"
        proposed_operation="delete"
        desired_body="null"
        actual_subset="${actual_item}"
        differing_fields='[]'
      else
        desired_body="$(cfctl_prepare_sync_body "${surface}" "${spec_row}")"
        actual_subset="$(cfctl_pick_actual_subset_for_desired "${actual_item}" "${desired_body}")"
        differing_fields="$(
          jq -n \
            --argjson desired "${desired_body}" \
            --argjson actual "${actual_subset}" \
            '
              [
                ($desired | keys_unsorted[]) as $key
                | select($desired[$key] != $actual[$key])
                | $key
              ]
            '
        )"
        if [[ "$(jq 'length == 0' <<< "${differing_fields}")" == "true" ]]; then
          status="in_sync"
          proposed_operation="noop"
        else
          status="drift"
          proposed_operation="update"
        fi
      fi
    fi

    diffs="$(
      jq \
        --argjson spec "${spec_row}" \
        --arg status "${status}" \
        --arg proposed_operation "${proposed_operation}" \
        --argjson actual_count "${match_count}" \
        --argjson desired_body "${desired_body}" \
        --argjson actual_item "${actual_item:-null}" \
        --argjson actual_subset "${actual_subset}" \
        --argjson differing_fields "${differing_fields}" \
        '
          . + [{
            spec_path: $spec.spec_path,
            match: $spec.match,
            status: $status,
            proposed_operation: $proposed_operation,
            delete: ($spec.delete // false),
            actual_count: $actual_count,
            desired_body: $desired_body,
            actual_item: $actual_item,
            actual_subset: $actual_subset,
            differing_fields: $differing_fields
          }]
        ' \
        <<< "${diffs}"
    )"
  done < <(jq -c '.[]' <<< "${specs_json}")

  local unmanaged='[]'
  local actual_row
  while IFS= read -r actual_row; do
    local matched="false"
    while IFS= read -r spec_row; do
      local match_json
      local hit_count
      match_json="$(jq -c '.match // {}' <<< "${spec_row}")"
      if [[ "${match_json}" == "{}" ]]; then
        continue
      fi
      hit_count="$(jq 'length' <<< "$(cfctl_filter_items_by_match "${surface}" "[${actual_row}]" "${match_json}")")"
      if [[ "${hit_count}" == "1" ]]; then
        matched="true"
        break
      fi
    done < <(jq -c '.[]' <<< "${specs_json}")

    if [[ "${matched}" != "true" ]]; then
      unmanaged="$(
        jq --argjson item "${actual_row}" '. + [$item]' <<< "${unmanaged}"
      )"
    fi
  done < <(jq -c '.[]' <<< "${actual_items_json}")

  jq -n \
    --arg surface "${surface}" \
    --argjson diffs "${diffs}" \
    --argjson unmanaged "${unmanaged}" \
    --argjson spec_count "$(jq 'length' <<< "${specs_json}")" \
    '
      {
        surface: $surface,
        desired_specs: $diffs,
        unmanaged_actual: $unmanaged,
        summary: {
          spec_count: $spec_count,
          in_sync_count: ($diffs | map(select(.status == "in_sync")) | length),
          drift_count: ($diffs | map(select(.status == "drift")) | length),
          create_count: ($diffs | map(select(.proposed_operation == "create")) | length),
          update_count: ($diffs | map(select(.proposed_operation == "update")) | length),
          delete_count: ($diffs | map(select(.proposed_operation == "delete")) | length),
          invalid_spec_count: ($diffs | map(select(.status == "invalid_spec")) | length),
          ambiguous_count: ($diffs | map(select(.status == "ambiguous_actual")) | length),
          unmanaged_actual_count: ($unmanaged | length)
        }
      }
    '
}

cfctl_execute_sync_action() {
  local surface="$1"
  local diff_entry_json="$2"
  local script_path
  local actual_item
  local body_json
  local operation

  script_path="$(cfctl_apply_script_path "${surface}")"
  if [[ -z "${script_path}" ]]; then
    echo "No apply backend registered for ${surface}" >&2
    return 1
  fi
  script_path="${CF_REPO_ROOT}/${script_path}"

  operation="$(jq -r '.proposed_operation' <<< "${diff_entry_json}")"
  actual_item="$(jq -c '.actual_item // null' <<< "${diff_entry_json}")"
  body_json="$(jq -c '.desired_body // null' <<< "${diff_entry_json}")"
  if [[ "${body_json}" == "null" ]]; then
    body_json=""
  fi

  case "${surface}" in
    access.app)
      if [[ "${operation}" == "create" ]]; then
        cfctl_run_backend_script "${script_path}" "APPLY=1" "OPERATION=create" "BODY_JSON=${body_json}"
      elif [[ "${operation}" == "update" ]]; then
        cfctl_run_backend_script "${script_path}" "APPLY=1" "OPERATION=update" "APP_ID=$(jq -r '.id' <<< "${actual_item}")" "BODY_JSON=${body_json}"
      elif [[ "${operation}" == "delete" ]]; then
        cfctl_run_backend_script "${script_path}" "APPLY=1" "OPERATION=delete" "APP_ID=$(jq -r '.id' <<< "${actual_item}")"
      fi
      ;;
    access.policy)
      if [[ "${operation}" == "create" ]]; then
        cfctl_run_backend_script "${script_path}" "APPLY=1" "OPERATION=create" "APP_ID=$(jq -r '.match.app_id' <<< "${diff_entry_json}")" "BODY_JSON=${body_json}"
      elif [[ "${operation}" == "update" ]]; then
        cfctl_run_backend_script "${script_path}" "APPLY=1" "OPERATION=update" "APP_ID=$(jq -r '.app_id' <<< "${actual_item}")" "POLICY_ID=$(jq -r '.id' <<< "${actual_item}")" "BODY_JSON=${body_json}"
      elif [[ "${operation}" == "delete" ]]; then
        cfctl_run_backend_script "${script_path}" "APPLY=1" "OPERATION=delete" "APP_ID=$(jq -r '.app_id' <<< "${actual_item}")" "POLICY_ID=$(jq -r '.id' <<< "${actual_item}")"
      fi
      ;;
    dns.record)
      if [[ "${operation}" == "delete" ]]; then
        cfctl_run_backend_script "${script_path}" "APPLY=1" "OPERATION=delete" "ZONE_NAME=$(jq -r '.match.zone' <<< "${diff_entry_json}")" "RECORD_ID=$(jq -r '.id' <<< "${actual_item}")"
      else
        cfctl_run_backend_script "${script_path}" "APPLY=1" "OPERATION=upsert" "ZONE_NAME=$(jq -r '.match.zone' <<< "${diff_entry_json}")" "BODY_JSON=${body_json}"
      fi
      ;;
    tunnel)
      if [[ "${operation}" == "create" ]]; then
        cfctl_run_backend_script "${script_path}" "APPLY=1" "OPERATION=create" "BODY_JSON=${body_json}"
      elif [[ "${operation}" == "update" ]]; then
        cfctl_run_backend_script "${script_path}" "APPLY=1" "OPERATION=update" "TUNNEL_ID=$(jq -r '.id' <<< "${actual_item}")" "BODY_JSON=${body_json}"
      elif [[ "${operation}" == "delete" ]]; then
        cfctl_run_backend_script "${script_path}" "APPLY=1" "OPERATION=delete" "TUNNEL_ID=$(jq -r '.id' <<< "${actual_item}")"
      fi
      ;;
    *)
      echo "No sync dispatcher registered for ${surface}" >&2
      return 1
      ;;
  esac
}
