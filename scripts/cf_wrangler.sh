#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools wrangler
cf_require_api_auth
cf_prepare_wrangler_env

if [[ "$#" -eq 0 ]]; then
  set -- whoami
fi

exec wrangler "$@"
