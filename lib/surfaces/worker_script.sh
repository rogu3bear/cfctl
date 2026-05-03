#!/usr/bin/env bash

set -euo pipefail

cfctl_surface_worker_script_permission_spec_json() {
  local permission_family="$1"

  jq -n \
    --arg method "GET" \
    --arg path "/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts" \
    --arg permission_family "${permission_family}" \
    '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
}

cfctl_surface_worker_script_selector_to_item_field() {
  local selector="$1"

  case "${selector}" in
    name) printf 'id\n' ;;
    *) printf '%s\n' "${selector}" ;;
  esac
}

cfctl_surface_worker_script_discovery_command() {
  printf 'cfctl list worker.script\n'
}

cfctl_surface_worker_script_verify_command() {
  if [[ -n "${CFCTL_NAME:-}" ]]; then
    printf 'cfctl verify worker.script --name %q\n' "${CFCTL_NAME}"
  else
    printf 'cfctl verify worker.script --name <script-name>\n'
  fi
}
