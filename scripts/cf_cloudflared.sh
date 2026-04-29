#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_require_tools cloudflared

CF_CLOUDFLARED_HOME="${CF_CLOUDFLARED_HOME:-${ROOT_DIR}/var/cloudflared-home}"
mkdir -p "${CF_CLOUDFLARED_HOME}"
export HOME="${CF_CLOUDFLARED_HOME}"

if [[ "$#" -eq 0 ]]; then
  set -- version
fi

cf_load_cloudflare_env_files
case "${1:-}" in
  version|--version|-v|help|--help|-h)
    ;;
  *)
    cf_select_active_token
    ;;
esac

exec cloudflared "$@"
