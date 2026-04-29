#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_require_tools wrangler

if [[ "$#" -eq 0 ]]; then
  set -- whoami
fi

cf_load_cloudflare_env_files
case "${1:-}" in
  version|--version|-v|help|--help|-h)
    ;;
  *)
    cf_select_active_token
    cf_require_api_auth
    cf_prepare_wrangler_env
    ;;
esac

exec wrangler "$@"
