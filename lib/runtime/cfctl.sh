#!/usr/bin/env bash

set -euo pipefail

CFCTL_RUNTIME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${CFCTL_RUNTIME_DIR}/cloudflare.sh"
# shellcheck disable=SC1091
source "${CFCTL_RUNTIME_DIR}/../backends/legacy.sh"
# shellcheck disable=SC1091
source "${CFCTL_RUNTIME_DIR}/../surfaces/runtime_catalog.sh"
# shellcheck disable=SC1091
for surface_lib in "${CFCTL_RUNTIME_DIR}"/../surfaces/*.sh; do
  [[ "${surface_lib}" == *"/runtime_catalog.sh" ]] && continue
  source "${surface_lib}"
done
# shellcheck disable=SC1091
source "${CFCTL_RUNTIME_DIR}/result.sh"
# shellcheck disable=SC1091
source "${CFCTL_RUNTIME_DIR}/lanes.sh"
# shellcheck disable=SC1091
source "${CFCTL_RUNTIME_DIR}/desired_state.sh"
