#!/usr/bin/env bash

set -euo pipefail

CF_LEGACY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${CF_LEGACY_DIR}/../../scripts/lib/cfctl.sh"
