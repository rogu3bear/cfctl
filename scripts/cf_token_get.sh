#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id

usage() {
  cat <<'EOF'
Usage:
  cfctl token get --id <token-id>

Reads a single account API token's live status and metadata (read-only).
Returns id, name, status, issued/expires timestamps, and policies — never the
token secret (Cloudflare only returns the secret at mint time). Use it to
confirm a scoped child is still active and to check its expiry.

Examples:
  cfctl token get --id 0123456789abcdef0123456789abcdef
EOF
}

TOKEN_ID=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --id)
      TOKEN_ID="${2:-}"
      shift 2
      ;;
    --id=*)
      TOKEN_ID="${1#*=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${TOKEN_ID}" ]]; then
  echo "Error: --id <token-id> is required." >&2
  usage >&2
  exit 1
fi

# Defensive: a Cloudflare account API token id is 32 hex chars. Reject anything
# else so a mis-pasted token *secret* is never placed in the request URL or the
# evidence artifact. (Secrets are longer and use a different alphabet.)
if ! [[ "${TOKEN_ID}" =~ ^[0-9a-fA-F]{32}$ ]]; then
  echo "Error: --id must be a 32-character token id, not a token value." >&2
  exit 1
fi

capture_json="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/${TOKEN_ID}")"
artifact_path="$(cf_inventory_file "auth" "token-get")"

result_json="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg scheme "${CF_ACTIVE_AUTH_SCHEME:-unknown}" \
    --arg credential_env "${CF_ACTIVE_TOKEN_ENV:-unknown}" \
    --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" \
    --arg token_id "${TOKEN_ID}" \
    --arg artifact_path "${artifact_path}" \
    --argjson capture "${capture_json}" \
    '
      ($capture.result // null) as $r
      | {
          generated_at: $generated_at,
          ok: ($capture.success // false),
          action: "token.get",
          auth: {
            lane: $lane,
            scheme: $scheme,
            credential_env: $credential_env
          },
          account_id: $account_id,
          token_id: $token_id,
          artifact_path: $artifact_path,
          result: (
            if ($r | type) == "object" then
              {
                id: $r.id,
                name: $r.name,
                status: $r.status,
                issued_on: $r.issued_on,
                modified_on: $r.modified_on,
                expires_on: $r.expires_on,
                not_before: $r.not_before,
                policies: ($r.policies // []),
                condition: $r.condition
              }
            else
              null
            end
          ),
          error: (
            if ($capture.success // false) then
              null
            else
              {
                status_code: ($capture.status_code // null),
                errors: ($capture.errors // []),
                request: ($capture.request // null)
              }
            end
          )
        }
    '
)"

cf_write_json_file "${artifact_path}" "${result_json}"
jq '.' <<< "${result_json}"

if [[ "$(jq -r '.ok' <<< "${result_json}")" != "true" ]]; then
  exit 1
fi
