#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/token_state.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id

usage() {
  cat <<'EOF'
Usage:
  cfctl token revoke-pending --consumer <name> [--commit] [--quiet]

Sweeps a consumer's pending_revoke queue — the scoped children already rotated
out of active use — DELETE-ing each at Cloudflare and clearing it from state.
Fail-safe: previews by default; pass --commit to actually revoke.

Revocation needs Account API Tokens Write, so run on the global lane
(CF_TOKEN_LANE=global); the least-privilege dev token yields token_write_denied.

Examples:
  cfctl token revoke-pending --consumer mln-web              # preview
  CF_TOKEN_LANE=global cfctl token revoke-pending --consumer mln-web --commit
EOF
}

CONSUMER=""
STATE_FILE=""
COMMIT=false
QUIET=false

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --consumer) CONSUMER="${2:-}"; shift 2 ;;
    --consumer=*) CONSUMER="${1#*=}"; shift ;;
    --state-file) STATE_FILE="${2:-}"; shift 2 ;;
    --state-file=*) STATE_FILE="${1#*=}"; shift ;;
    --commit) COMMIT=true; shift ;;
    --quiet) QUIET=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Allow an explicit --state-file by pointing the consumer-keyed store at it.
if [[ -n "${STATE_FILE}" ]]; then
  CF_TOKEN_STATE_DIR="$(cd "$(dirname "${STATE_FILE}")" && pwd)"
  export CF_TOKEN_STATE_DIR
  CONSUMER="$(basename "${STATE_FILE}" .json)"
fi

if [[ -z "${CONSUMER}" ]]; then
  echo "Error: provide --consumer <name> or --state-file <path>." >&2
  usage >&2
  exit 1
fi
if ! [[ "${CONSUMER}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Error: --consumer must be a simple name ([A-Za-z0-9._-])." >&2
  exit 1
fi

state_path="$(cf_token_state_path "${CONSUMER}")"
if [[ ! -f "${state_path}" ]]; then
  echo "Error: token state file not found: ${state_path}" >&2
  exit 2
fi

pending="$(cf_token_state_list_pending "${CONSUMER}")"

revocations_json="[]"
total=0
revoked=0
failed=0
auth_denied=0
would=0

while IFS=$'\t' read -r purpose token_id; do
  [[ -n "${purpose}" && -n "${token_id}" ]] || continue
  total=$((total + 1))

  outcome="would-revoke"
  if [[ "${COMMIT}" != "true" ]]; then
    would=$((would + 1))
  else
    capture="$(cf_api_capture DELETE "/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/${token_id}")"
    success="$(jq -r '.success // false' <<< "${capture}")"
    status_code="$(jq -r '.status_code // empty' <<< "${capture}")"
    if [[ "${success}" == "true" ]]; then
      cf_token_state_clear_pending "${CONSUMER}" "${purpose}" "${token_id}"
      revoked=$((revoked + 1))
      outcome="revoked"
    elif [[ "${status_code}" == "404" ]]; then
      # Already gone (expired or hand-revoked) — clear state anyway.
      cf_token_state_clear_pending "${CONSUMER}" "${purpose}" "${token_id}"
      revoked=$((revoked + 1))
      outcome="already-gone-cleared"
    elif [[ "${status_code}" == "401" || "${status_code}" == "403" ]]; then
      auth_denied=$((auth_denied + 1))
      outcome="write-denied"
    else
      failed=$((failed + 1))
      outcome="failed"
    fi
  fi

  row="$(jq -n --arg p "${purpose}" --arg id "${token_id}" --arg o "${outcome}" \
    '{purpose: $p, token_id: $id, outcome: $o}')"
  revocations_json="$(jq -c --argjson row "${row}" '. + [$row]' <<< "${revocations_json}")"
done <<< "${pending}"

artifact_path="$(cf_inventory_file "auth" "token-revoke-pending")"

result_json="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg scheme "${CF_ACTIVE_AUTH_SCHEME:-unknown}" \
    --arg credential_env "${CF_ACTIVE_TOKEN_ENV:-unknown}" \
    --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" \
    --arg consumer "${CONSUMER}" \
    --arg state_file "${state_path}" \
    --arg artifact_path "${artifact_path}" \
    --argjson committed "${COMMIT}" \
    --argjson total "${total}" \
    --argjson revoked "${revoked}" \
    --argjson failed "${failed}" \
    --argjson auth_denied "${auth_denied}" \
    --argjson would "${would}" \
    --argjson revocations "${revocations_json}" \
    '
      ($failed == 0 and $auth_denied == 0) as $ok
      | {
          generated_at: $generated_at,
          ok: $ok,
          action: "token.revoke-pending",
          dry_run: ($committed | not),
          auth: {lane: $lane, scheme: $scheme, credential_env: $credential_env},
          account_id: $account_id,
          consumer: $consumer,
          state_file: $state_file,
          artifact_path: $artifact_path,
          summary: {pending: $total, revoked: $revoked, failed: $failed, write_denied: $auth_denied, would_revoke: $would},
          result: {revocations: $revocations},
          error: (
            if $auth_denied > 0 then
              {code: "token_write_denied", write_denied: $auth_denied, hint: "revocation needs Account API Tokens Write — rerun on the global lane (CF_TOKEN_LANE=global)"}
            elif $failed > 0 then
              {code: "revoke_failed", failed: $failed}
            else
              null
            end
          )
        }
    '
)"

cf_write_json_file "${artifact_path}" "${result_json}"
if [[ "${QUIET}" == "true" ]]; then
  jq -c '{ok, dry_run, summary, error}' <<< "${result_json}"
else
  jq '.' <<< "${result_json}"
fi

if [[ "$(jq -r '.ok' <<< "${result_json}")" != "true" ]]; then
  exit 1
fi
