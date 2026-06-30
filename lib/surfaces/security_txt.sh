#!/usr/bin/env bash

set -euo pipefail

cfctl_surface_security_txt_permission_spec_json() {
  local permission_family="$1"
  local path="/zones/${CFCTL_ZONE_ID}/security-center/securitytxt"

  jq -n \
    --arg method "GET" \
    --arg path "${path}" \
    --arg permission_family "${permission_family}" \
    '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
}

cfctl_surface_security_txt_selector_to_item_field() {
  local selector="$1"

  case "${selector}" in
    zone) printf 'zone_name\n' ;;
    zone_id) printf 'zone_id\n' ;;
    *) printf '%s\n' "${selector}" ;;
  esac
}

cfctl_surface_security_txt_prepare_sync_body() {
  local spec_json="$1"

  jq '(.body // {})' <<< "${spec_json}"
}

cfctl_surface_security_txt_discovery_command() {
  if [[ -n "${CFCTL_ZONE_NAME:-}" ]]; then
    printf 'cfctl get security.txt --zone %q\n' "${CFCTL_ZONE_NAME}"
  else
    printf 'cfctl get security.txt --zone <zone>\n'
  fi
}

cfctl_surface_security_txt_verify_command() {
  if [[ -n "${CFCTL_ZONE_NAME:-}" ]]; then
    printf 'cfctl verify security.txt --zone %q\n' "${CFCTL_ZONE_NAME}"
  else
    printf 'cfctl verify security.txt --zone <zone>\n'
  fi
}
