#!/usr/bin/env bash

set -euo pipefail

cfctl_surface_access_policy_permission_spec_json() {
  local permission_family="$1"

  if [[ -n "${CFCTL_APP_ID:-}" ]]; then
    jq -n \
      --arg method "GET" \
      --arg path "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps/${CFCTL_APP_ID}/policies" \
      --arg permission_family "${permission_family}" \
      '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
    return
  fi

  jq -n \
    --arg method "GET" \
    --arg path "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps" \
    --arg permission_family "${permission_family}" \
    '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
}

cfctl_surface_access_policy_selector_to_item_field() {
  local selector="$1"

  case "${selector}" in
    policy_id) printf 'id\n' ;;
    *) printf '%s\n' "${selector}" ;;
  esac
}

cfctl_surface_access_policy_discovery_command() {
  if [[ -n "${CFCTL_APP_ID:-}" ]]; then
    printf 'cfctl list access.policy --app-id %q\n' "${CFCTL_APP_ID}"
  else
    printf 'cfctl list access.policy --app-id <app-id>\n'
  fi
}

cfctl_surface_access_policy_verify_command() {
  if [[ -n "${CFCTL_POLICY_ID:-}" ]]; then
    printf 'cfctl verify access.policy --policy-id %q\n' "${CFCTL_POLICY_ID}"
  elif [[ -n "${CFCTL_APP_ID:-}" && -n "${CFCTL_NAME:-}" ]]; then
    printf 'cfctl verify access.policy --app-id %q --name %q\n' "${CFCTL_APP_ID}" "${CFCTL_NAME}"
  else
    printf 'cfctl verify access.policy --policy-id <policy-id>\n'
  fi
}
