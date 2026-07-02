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
  cfctl token verify-state (--consumer <name> | --state-file <path>) [--quiet]

Read-only drift watchdog over a consumer's scoped-child token state. For each
purpose it confirms the recorded active token is live (status:active) and any
pending_revoke tokens are dead. Exit 0 healthy, exit 1 on drift.

State lives at ${CF_TOKEN_STATE_DIR:-~/dev/.secrets-state}/<consumer>.json — the
same per-consumer store the app's rotator writes. Token reads need Account API
Tokens Read, so run on the global lane (CF_TOKEN_LANE=global); the least-
privilege dev token yields token_read_denied, not false drift.

Examples:
  CF_TOKEN_LANE=global cfctl token verify-state --consumer mln-web
EOF
}

CONSUMER=""
STATE_FILE=""
QUIET=false

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --consumer) CONSUMER="${2:-}"; shift 2 ;;
    --consumer=*) CONSUMER="${1#*=}"; shift ;;
    --state-file) STATE_FILE="${2:-}"; shift 2 ;;
    --state-file=*) STATE_FILE="${1#*=}"; shift ;;
    --quiet) QUIET=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

state_dir="${CF_TOKEN_STATE_DIR:-${HOME}/dev/.secrets-state}"
if [[ -z "${STATE_FILE}" ]]; then
  if [[ -z "${CONSUMER}" ]]; then
    echo "Error: provide --consumer <name> or --state-file <path>." >&2
    usage >&2
    exit 1
  fi
  # Guard against path traversal — a consumer is a simple registry name.
  if ! [[ "${CONSUMER}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "Error: --consumer must be a simple name ([A-Za-z0-9._-])." >&2
    exit 1
  fi
  STATE_FILE="${state_dir}/${CONSUMER}.json"
fi

if [[ ! -f "${STATE_FILE}" ]]; then
  echo "Error: token state file not found: ${STATE_FILE}" >&2
  exit 2
fi

# purpose<TAB>kind<TAB>token_id rows for every active + pending child.
rows="$(
  jq -r '
    .children // {}
    | to_entries[] as $e
    | (
        ($e.value.active.id // "")
        | select(. != "")
        | "\($e.key)\tactive\t\(.)"
      ),
      (
        ($e.value.pending_revoke // [])[]?
        | (.id // "")
        | select(. != "")
        | "\($e.key)\tpending\t\(.)"
      )
  ' "${STATE_FILE}" 2>/dev/null || true
)"

checks_json="[]"
drift=0
auth_denied=0
active_total=0
pending_total=0

while IFS=$'\t' read -r purpose kind token_id; do
  [[ -n "${purpose}" && -n "${kind}" && -n "${token_id}" ]] || continue

  capture="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/${token_id}")"
  success="$(jq -r '.success // false' <<< "${capture}")"
  live_status="$(jq -r '.result.status // "missing"' <<< "${capture}")"
  live_id="$(jq -r '.result.id // empty' <<< "${capture}")"
  status_code="$(jq -r '.status_code // empty' <<< "${capture}")"

  ok_row=true
  reason="ok"

  if [[ "${success}" != "true" && ( "${status_code}" == "401" || "${status_code}" == "403" ) ]]; then
    # Permission problem, not drift — the active lane cannot read tokens.
    ok_row=false
    reason="read-denied"
    auth_denied=$((auth_denied + 1))
  elif [[ "${kind}" == "active" ]]; then
    active_total=$((active_total + 1))
    if [[ "${success}" == "true" && "${live_status}" == "active" && "${live_id}" == "${token_id}" ]]; then
      ok_row=true
      reason="active-live"
    else
      ok_row=false
      reason="active-not-live"
      drift=$((drift + 1))
    fi
  else
    pending_total=$((pending_total + 1))
    if [[ "${success}" == "true" && "${live_status}" == "active" ]]; then
      ok_row=false
      reason="pending-still-alive"
      drift=$((drift + 1))
    else
      ok_row=true
      reason="pending-cleared"
    fi
  fi

  row="$(
    jq -n \
      --arg purpose "${purpose}" \
      --arg kind "${kind}" \
      --arg token_id "${token_id}" \
      --arg live_status "${live_status}" \
      --argjson ok "${ok_row}" \
      --arg reason "${reason}" \
      '{purpose: $purpose, kind: $kind, token_id: $token_id, live_status: $live_status, ok: $ok, reason: $reason}'
  )"
  checks_json="$(jq -c --argjson row "${row}" '. + [$row]' <<< "${checks_json}")"
done <<< "${rows}"

artifact_path="$(cf_inventory_file "auth" "token-verify-state")"

result_json="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg scheme "${CF_ACTIVE_AUTH_SCHEME:-unknown}" \
    --arg credential_env "${CF_ACTIVE_TOKEN_ENV:-unknown}" \
    --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" \
    --arg consumer "${CONSUMER}" \
    --arg state_file "${STATE_FILE}" \
    --arg artifact_path "${artifact_path}" \
    --argjson active_total "${active_total}" \
    --argjson pending_total "${pending_total}" \
    --argjson drift "${drift}" \
    --argjson auth_denied "${auth_denied}" \
    --argjson checks "${checks_json}" \
    '
      ($drift == 0 and $auth_denied == 0) as $ok
      | {
          generated_at: $generated_at,
          ok: $ok,
          action: "token.verify-state",
          auth: {lane: $lane, scheme: $scheme, credential_env: $credential_env},
          account_id: $account_id,
          consumer: (if $consumer == "" then null else $consumer end),
          state_file: $state_file,
          artifact_path: $artifact_path,
          summary: {active: $active_total, pending: $pending_total, drift: $drift, read_denied: $auth_denied},
          result: {checks: $checks},
          error: (
            if $auth_denied > 0 then
              {code: "token_read_denied", read_denied: $auth_denied, hint: "token reads need Account API Tokens Read — rerun on the global lane (CF_TOKEN_LANE=global)"}
            elif $drift > 0 then
              {code: "state_drift", drift: $drift}
            else
              null
            end
          )
        }
    '
)"

cf_write_json_file "${artifact_path}" "${result_json}"
if [[ "${QUIET}" == "true" ]]; then
  jq -c '{ok, summary, error}' <<< "${result_json}"
else
  jq '.' <<< "${result_json}"
fi

if [[ "$(jq -r '.ok' <<< "${result_json}")" != "true" ]]; then
  exit 1
fi
