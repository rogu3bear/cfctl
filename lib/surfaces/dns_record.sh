#!/usr/bin/env bash

set -euo pipefail

cfctl_surface_dns_record_permission_spec_json() {
  local permission_family="$1"

  jq -n \
    --arg method "GET" \
    --arg path "/zones/${CFCTL_ZONE_ID}/dns_records?per_page=1" \
    --arg permission_family "${permission_family}" \
    '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
}

cfctl_surface_dns_record_selector_to_item_field() {
  local selector="$1"

  case "${selector}" in
    zone) printf 'zone_name\n' ;;
    zone_id) printf 'zone_id\n' ;;
    *) printf '%s\n' "${selector}" ;;
  esac
}

cfctl_surface_dns_record_prepare_sync_body() {
  local spec_json="$1"

  jq '
    (.body // {})
    + (if (.match.name // "") != "" then {name: .match.name} else {} end)
    + (if (.match.type // "") != "" then {type: .match.type} else {} end)
  ' <<< "${spec_json}"
}

cfctl_surface_dns_record_discovery_command() {
  if [[ -n "${CFCTL_ZONE_NAME:-}" ]]; then
    printf 'cfctl list dns.record --zone %q\n' "${CFCTL_ZONE_NAME}"
  else
    printf 'cfctl list dns.record --zone <zone>\n'
  fi
}

cfctl_surface_dns_record_verify_command() {
  if [[ -n "${CFCTL_ZONE_NAME:-}" && -n "${CFCTL_ID:-}" ]]; then
    printf 'cfctl verify dns.record --zone %q --id %q\n' "${CFCTL_ZONE_NAME}" "${CFCTL_ID}"
  elif [[ -n "${CFCTL_ZONE_NAME:-}" && -n "${CFCTL_NAME:-}" && -n "${CFCTL_TYPE:-}" ]]; then
    printf 'cfctl verify dns.record --zone %q --name %q --type %q\n' "${CFCTL_ZONE_NAME}" "${CFCTL_NAME}" "${CFCTL_TYPE}"
  else
    printf 'cfctl verify dns.record --zone <zone> --name <name> --type <type>\n'
  fi
}
