#!/usr/bin/env bash

set -euo pipefail

cfctl_surface_worker_route_permission_spec_json() {
  local permission_family="$1"

  jq -n \
    --arg method "GET" \
    --arg path "/zones/${CFCTL_ZONE_ID}/workers/routes" \
    --arg permission_family "${permission_family}" \
    '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
}

cfctl_surface_worker_route_discovery_command() {
  if [[ -n "${CFCTL_ZONE_NAME:-}" ]]; then
    printf 'cfctl list worker.route --zone %q\n' "${CFCTL_ZONE_NAME}"
  else
    printf 'cfctl list worker.route --zone <zone>\n'
  fi
}

cfctl_surface_worker_route_verify_command() {
  if [[ -n "${CFCTL_ZONE_NAME:-}" && -n "${CFCTL_ID:-}" ]]; then
    printf 'cfctl verify worker.route --zone %q --id %q\n' "${CFCTL_ZONE_NAME}" "${CFCTL_ID}"
  elif [[ -n "${CFCTL_ZONE_NAME:-}" && -n "${CFCTL_PATTERN:-}" ]]; then
    printf 'cfctl verify worker.route --zone %q --pattern %q\n' "${CFCTL_ZONE_NAME}" "${CFCTL_PATTERN}"
  else
    printf 'cfctl verify worker.route --zone <zone> --pattern <route-pattern>\n'
  fi
}
