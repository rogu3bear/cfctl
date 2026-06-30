#!/usr/bin/env bash

set -euo pipefail

cfctl_surface_zone_setting_permission_spec_json() {
  local permission_family="$1"
  local path="/zones/${CFCTL_ZONE_ID}/settings"

  if [[ -n "${CFCTL_NAME:-}" ]]; then
    path="/zones/${CFCTL_ZONE_ID}/settings/${CFCTL_NAME}"
  fi

  jq -n \
    --arg method "GET" \
    --arg path "${path}" \
    --arg permission_family "${permission_family}" \
    '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
}

cfctl_surface_zone_setting_selector_to_item_field() {
  local selector="$1"

  case "${selector}" in
    zone) printf 'zone_name\n' ;;
    zone_id) printf 'zone_id\n' ;;
    name) printf 'id\n' ;;
    *) printf '%s\n' "${selector}" ;;
  esac
}

cfctl_surface_zone_setting_prepare_sync_body() {
  local spec_json="$1"

  jq '(.body // {})' <<< "${spec_json}"
}

cfctl_surface_zone_setting_discovery_command() {
  if [[ -n "${CFCTL_ZONE_NAME:-}" ]]; then
    printf 'cfctl list zone.setting --zone %q\n' "${CFCTL_ZONE_NAME}"
  else
    printf 'cfctl list zone.setting --zone <zone>\n'
  fi
}

cfctl_surface_zone_setting_verify_command() {
  if [[ -n "${CFCTL_ZONE_NAME:-}" && -n "${CFCTL_NAME:-}" ]]; then
    printf 'cfctl verify zone.setting --zone %q --name %q\n' "${CFCTL_ZONE_NAME}" "${CFCTL_NAME}"
  else
    printf 'cfctl verify zone.setting --zone <zone> --name <setting-id>\n'
  fi
}
