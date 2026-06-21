#!/usr/bin/env bash

set -euo pipefail

cfctl_surface_access_login_method_permission_spec_json() {
  local permission_family="$1"

  jq -n \
    --arg method "GET" \
    --arg path "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps" \
    --arg permission_family "${permission_family}" \
    '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
}

cfctl_surface_access_login_method_discovery_command() {
  printf 'cfctl list access.login_method\n'
}

cfctl_surface_access_login_method_verify_command() {
  if [[ -n "${CFCTL_ID:-}" ]]; then
    printf 'cfctl verify access.login_method --id %q\n' "${CFCTL_ID}"
  elif [[ -n "${CFCTL_DOMAIN:-}" ]]; then
    printf 'cfctl verify access.login_method --domain %q\n' "${CFCTL_DOMAIN}"
  elif [[ -n "${CFCTL_NAME:-}" ]]; then
    printf 'cfctl verify access.login_method --name %q\n' "${CFCTL_NAME}"
  else
    printf 'cfctl list access.login_method\n'
  fi
}
