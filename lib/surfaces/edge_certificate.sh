#!/usr/bin/env bash

set -euo pipefail

cfctl_surface_edge_certificate_permission_spec_json() {
  local permission_family="$1"

  jq -n \
    --arg method "GET" \
    --arg path "/zones/${CFCTL_ZONE_ID}/ssl/certificate_packs?status=all&per_page=1" \
    --arg permission_family "${permission_family}" \
    '{method: $method, path: $path, permission_family: $permission_family, inference: "surface_read_probe"}'
}

cfctl_surface_edge_certificate_discovery_command() {
  if [[ -n "${CFCTL_ZONE_NAME:-}" ]]; then
    printf 'cfctl list edge.certificate --zone %q\n' "${CFCTL_ZONE_NAME}"
  else
    printf 'cfctl list edge.certificate --zone <zone>\n'
  fi
}

cfctl_surface_edge_certificate_verify_command() {
  if [[ -n "${CFCTL_ZONE_NAME:-}" && -n "${CFCTL_ID:-}" ]]; then
    printf 'cfctl verify edge.certificate --zone %q --id %q\n' "${CFCTL_ZONE_NAME}" "${CFCTL_ID}"
  elif [[ -n "${CFCTL_ZONE_NAME:-}" && "$(jq 'length' <<< "${CFCTL_HOSTS_JSON:-[]}")" != "0" ]]; then
    local args=()
    local host
    while IFS= read -r host; do
      [[ -n "${host}" ]] && args+=(--host "${host}")
    done < <(jq -r '.[]?' <<< "${CFCTL_HOSTS_JSON}")
    printf 'cfctl verify edge.certificate --zone %q' "${CFCTL_ZONE_NAME}"
    printf ' %q' "${args[@]}"
    printf '\n'
  else
    printf 'cfctl verify edge.certificate --zone <zone> --id <certificate-pack-id>\n'
  fi
}
