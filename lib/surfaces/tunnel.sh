#!/usr/bin/env bash

set -euo pipefail

cfctl_surface_tunnel_permission_spec_json() {
  local permission_family="$1"

  jq -n \
    --arg method "GET" \
    --arg path "/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel" \
    --arg permission_family "${permission_family}" \
    '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
}

cfctl_surface_tunnel_discovery_command() {
  printf 'cfctl list tunnel\n'
}

cfctl_surface_tunnel_verify_command() {
  if [[ -n "${CFCTL_ID:-}" ]]; then
    printf 'cfctl verify tunnel --id %q\n' "${CFCTL_ID}"
  elif [[ -n "${CFCTL_NAME:-}" ]]; then
    printf 'cfctl verify tunnel --name %q\n' "${CFCTL_NAME}"
  else
    printf 'cfctl verify tunnel --id <tunnel-id>\n'
  fi
}
