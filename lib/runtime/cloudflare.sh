#!/usr/bin/env bash

set -euo pipefail

CF_RUNTIME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${CF_RUNTIME_DIR}/../../scripts/lib/cloudflare.sh"
