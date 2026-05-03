#!/usr/bin/env bash

set -euo pipefail

cfctl_surface_worker_secret_permission_spec_json() {
  local permission_family="$1"
  local script_name="${CFCTL_SCRIPT:-}"

  jq -n \
    --arg method "GET" \
    --arg path "/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${script_name}/secrets" \
    --arg permission_family "${permission_family}" \
    '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
}

cfctl_surface_worker_secret_selector_to_item_field() {
  local selector="$1"

  case "${selector}" in
    script) printf 'script\n' ;;
    *) printf '%s\n' "${selector}" ;;
  esac
}

cfctl_surface_worker_secret_discovery_command() {
  if [[ -n "${CFCTL_SCRIPT:-}" ]]; then
    printf 'cfctl list worker.secret --script %q\n' "${CFCTL_SCRIPT}"
  else
    printf 'cfctl list worker.secret --script <script-name>\n'
  fi
}

cfctl_surface_worker_secret_verify_command() {
  if [[ -n "${CFCTL_SCRIPT:-}" && -n "${CFCTL_NAME:-}" ]]; then
    printf 'cfctl verify worker.secret --script %q --name %q\n' "${CFCTL_SCRIPT}" "${CFCTL_NAME}"
  else
    printf 'cfctl verify worker.secret --script <script-name> --name <secret-name>\n'
  fi
}
