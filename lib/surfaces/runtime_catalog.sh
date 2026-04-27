#!/usr/bin/env bash

set -euo pipefail

CF_SURFACE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFCTL_RUNTIME_CATALOG_PATH="${CFCTL_RUNTIME_CATALOG_PATH:-${CF_REPO_ROOT}/catalog/runtime.json}"

cfctl_runtime_catalog_json() {
  cat "${CFCTL_RUNTIME_CATALOG_PATH}"
}

cfctl_runtime_public_verbs_json() {
  jq -c '.public_verbs // []' "${CFCTL_RUNTIME_CATALOG_PATH}"
}

cfctl_runtime_landing_flow_json() {
  jq -c '.landing_flow // []' "${CFCTL_RUNTIME_CATALOG_PATH}"
}

cfctl_runtime_policy_json() {
  jq -c '.policy // {}' "${CFCTL_RUNTIME_CATALOG_PATH}"
}

cfctl_supported_lanes_json() {
  jq -c '(.lanes | keys | sort)' "${CFCTL_RUNTIME_CATALOG_PATH}"
}

cfctl_lane_meta() {
  local lane="$1"
  jq -c --arg lane "${lane}" '.lanes[$lane] // null' "${CFCTL_RUNTIME_CATALOG_PATH}"
}

cfctl_surface_state_meta() {
  local surface="$1"
  jq -c --arg surface "${surface}" '.desired_state[$surface] // {"supported": false}' "${CFCTL_RUNTIME_CATALOG_PATH}"
}

cfctl_surface_has_desired_state() {
  local surface="$1"
  jq -e --arg surface "${surface}" '.desired_state[$surface].supported == true' "${CFCTL_RUNTIME_CATALOG_PATH}" >/dev/null
}

cfctl_surface_sync_supported() {
  local surface="$1"
  jq -e --arg surface "${surface}" '.desired_state[$surface].sync_supported == true' "${CFCTL_RUNTIME_CATALOG_PATH}" >/dev/null
}

cfctl_surface_state_dir() {
  local surface="$1"
  jq -r --arg surface "${surface}" '.desired_state[$surface].state_dir // empty' "${CFCTL_RUNTIME_CATALOG_PATH}"
}

cfctl_surface_state_match_selectors_json() {
  local surface="$1"
  jq -c --arg surface "${surface}" '.desired_state[$surface].match_selectors // []' "${CFCTL_RUNTIME_CATALOG_PATH}"
}
