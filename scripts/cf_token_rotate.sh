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
  cfctl token rotate --consumer <name> --purposes-file <path> --sink-dir <dir>
                     [--purpose <name>] [--force] [--dry-run] [--quiet]

Rotates a consumer's scoped-child tokens that are past half their TTL. For each
stale purpose it mints a fresh child through the gated `cfctl token mint`,
writes the new value to <sink-dir>/<purpose>.token (mode 600), records it as
active, and demotes the prior active onto pending_revoke. cfctl never reads the
secret — it returns a manifest of {purpose, token_id, value_path, expires_on}
for the caller to deliver.

Ordering contract: rotate -> deliver each value_path -> `token revoke-pending`
(only after successful delivery, so the prior token stays valid until then).

The purposes file is consumer-owned:
  { "purposes": [
      { "purpose": "cf-x", "name_prefix": "cf-x", "ttl_days": 7,
        "policies": [ { ...Cloudflare token policy... } ] } ] }

Minting needs Account API Tokens Write, so run on the global lane
(CF_TOKEN_LANE=global).

Examples:
  cfctl token rotate --consumer mln-web --purposes-file mln-web.purposes.json \
    --sink-dir /tmp/cf-rotate --dry-run
  CF_TOKEN_LANE=global cfctl token rotate --consumer mln-web \
    --purposes-file mln-web.purposes.json --sink-dir /run/user/501/cf-rotate
EOF
}

CONSUMER=""
PURPOSES_FILE=""
SINK_DIR=""
ONLY_PURPOSE=""
FORCE=false
DRY_RUN=false
QUIET=false

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --consumer) CONSUMER="${2:-}"; shift 2 ;;
    --consumer=*) CONSUMER="${1#*=}"; shift ;;
    --purposes-file) PURPOSES_FILE="${2:-}"; shift 2 ;;
    --purposes-file=*) PURPOSES_FILE="${1#*=}"; shift ;;
    --sink-dir) SINK_DIR="${2:-}"; shift 2 ;;
    --sink-dir=*) SINK_DIR="${1#*=}"; shift ;;
    --purpose) ONLY_PURPOSE="${2:-}"; shift 2 ;;
    --purpose=*) ONLY_PURPOSE="${1#*=}"; shift ;;
    --force) FORCE=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --quiet) QUIET=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ -z "${CONSUMER}" ]]; then
  echo "Error: --consumer <name> is required." >&2; usage >&2; exit 1
fi
if ! [[ "${CONSUMER}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Error: --consumer must be a simple name ([A-Za-z0-9._-])." >&2; exit 1
fi
if [[ -z "${PURPOSES_FILE}" || ! -f "${PURPOSES_FILE}" ]]; then
  echo "Error: --purposes-file <path> is required and must exist." >&2; exit 1
fi
if ! jq -e '.purposes | type == "array"' "${PURPOSES_FILE}" >/dev/null 2>&1; then
  echo "Error: purposes file must contain a .purposes array." >&2; exit 1
fi

# The secret sink dir is only needed for a real rotation.
if [[ "${DRY_RUN}" != "true" ]]; then
  if [[ -z "${SINK_DIR}" ]]; then
    echo "Error: --sink-dir <dir> is required for a real rotation (omit only with --dry-run)." >&2; exit 1
  fi
  if [[ "${SINK_DIR}" != /* ]]; then
    echo "Error: --sink-dir must be an absolute path." >&2; exit 1
  fi
  case "${SINK_DIR}" in
    "${ROOT_DIR}"|"${ROOT_DIR}/"*)
      echo "Error: --sink-dir must be outside the cfctl repo." >&2; exit 1 ;;
  esac
  mkdir -p "${SINK_DIR}"
  chmod 700 "${SINK_DIR}" 2>/dev/null || true
fi

cf_token_state_init "${CONSUMER}" "${CLOUDFLARE_ACCOUNT_ID}" >/dev/null

ROTATE_TMP_FILES=()
cleanup_tmp() {
  local f
  (( ${#ROTATE_TMP_FILES[@]} > 0 )) || return 0
  for f in "${ROTATE_TMP_FILES[@]}"; do
    [[ -f "${f}" ]] && rm -f "${f}"
  done
}
trap cleanup_tmp EXIT

now_epoch="$(cf_now_epoch)"

rotated_json="[]"
skipped_json="[]"
total=0
rotated=0
skipped=0
would=0
failed=0

# Mint one child through the gated cfctl entrypoint. Echoes "token_id<TAB>expires_on".
mint_child() {
  local name="$1" policy_file="$2" ttl_hours="$3" value_file="$4"
  local plan_json operation_id mint_json

  plan_json="$("${ROOT_DIR}/cfctl" token mint --name "${name}" --policy-file "${policy_file}" --ttl-hours "${ttl_hours}" --plan 2>&1)" || true
  if ! jq -e '.ok == true' >/dev/null 2>&1 <<< "${plan_json}"; then
    return 1
  fi
  operation_id="$(jq -r '.operation_id // empty' <<< "${plan_json}")"
  [[ -n "${operation_id}" ]] || return 1

  : > "${value_file}"
  chmod 600 "${value_file}" 2>/dev/null || true
  mint_json="$("${ROOT_DIR}/cfctl" token mint --name "${name}" --policy-file "${policy_file}" --ttl-hours "${ttl_hours}" --ack-plan "${operation_id}" --value-out "${value_file}" 2>&1)" || true
  if ! jq -e '.ok == true' >/dev/null 2>&1 <<< "${mint_json}"; then
    return 1
  fi
  jq -r '"\(.result.token_id // "")\t\(.result.expires_on // "")"' <<< "${mint_json}"
}

while IFS=$'\t' read -r purpose name_prefix ttl_days; do
  [[ -n "${purpose}" ]] || continue
  if [[ -n "${ONLY_PURPOSE}" && "${purpose}" != "${ONLY_PURPOSE}" ]]; then
    continue
  fi
  total=$((total + 1))

  active_id="$(cf_token_state_active_id "${CONSUMER}" "${purpose}")"
  active_expires="$(cf_token_state_active_expires "${CONSUMER}" "${purpose}")"
  half_ttl=$(( ttl_days * 86400 / 2 ))

  stale=false
  reason="fresh"
  remaining=""
  if [[ -z "${active_id}" ]]; then
    stale=true; reason="no-active"
  elif [[ "${FORCE}" == "true" ]]; then
    stale=true; reason="forced"
  else
    expires_epoch="$(cf_token_state_iso_to_epoch "${active_expires}")"
    if [[ -z "${expires_epoch}" ]]; then
      stale=true; reason="unparseable-expiry"
    else
      remaining=$(( expires_epoch - now_epoch ))
      if (( remaining < half_ttl )); then
        stale=true; reason="past-half-ttl"
      else
        stale=false; reason="fresh"
      fi
    fi
  fi

  if [[ "${stale}" != "true" ]]; then
    skipped=$((skipped + 1))
    row="$(jq -n --arg p "${purpose}" --arg r "${reason}" --argjson rem "$( [[ -n "${remaining}" ]] && echo "${remaining}" || echo null )" \
      '{purpose: $p, reason: $r, remaining_seconds: $rem}')"
    skipped_json="$(jq -c --argjson row "${row}" '. + [$row]' <<< "${skipped_json}")"
    continue
  fi

  if [[ "${DRY_RUN}" == "true" ]]; then
    would=$((would + 1))
    row="$(jq -n --arg p "${purpose}" --arg r "${reason}" '{purpose: $p, reason: $r, action: "would-rotate"}')"
    rotated_json="$(jq -c --argjson row "${row}" '. + [$row]' <<< "${rotated_json}")"
    continue
  fi

  # Real rotation: mint a fresh child for this purpose.
  policy_file="$(mktemp "${TMPDIR:-/tmp}/cfctl-rotate-policy.XXXXXX")"
  ROTATE_TMP_FILES+=("${policy_file}")
  jq -c --arg p "${purpose}" '(.purposes[] | select(.purpose == $p) | .policies)' "${PURPOSES_FILE}" > "${policy_file}"

  token_name="${name_prefix}-$(date -u +%Y%m%dT%H%M%SZ)"
  ttl_hours=$(( ttl_days * 24 ))
  value_file="${SINK_DIR}/${purpose}.token"

  if mint_out="$(mint_child "${token_name}" "${policy_file}" "${ttl_hours}" "${value_file}")"; then
    token_id="${mint_out%%$'\t'*}"
    expires_on="${mint_out#*$'\t'}"
    if [[ -n "${token_id}" ]]; then
      cf_token_state_rotate_child "${CONSUMER}" "${purpose}" "${token_id}" "${expires_on}"
      rotated=$((rotated + 1))
      row="$(jq -n --arg p "${purpose}" --arg id "${token_id}" --arg vp "${value_file}" --arg exp "${expires_on}" --arg r "${reason}" \
        '{purpose: $p, token_id: $id, value_path: $vp, expires_on: $exp, reason: $r, action: "rotated"}')"
      rotated_json="$(jq -c --argjson row "${row}" '. + [$row]' <<< "${rotated_json}")"
    else
      failed=$((failed + 1))
      row="$(jq -n --arg p "${purpose}" '{purpose: $p, action: "failed", reason: "mint-returned-no-id"}')"
      rotated_json="$(jq -c --argjson row "${row}" '. + [$row]' <<< "${rotated_json}")"
    fi
  else
    failed=$((failed + 1))
    row="$(jq -n --arg p "${purpose}" '{purpose: $p, action: "failed", reason: "mint-failed"}')"
    rotated_json="$(jq -c --argjson row "${row}" '. + [$row]' <<< "${rotated_json}")"
  fi
done < <(jq -r '.purposes[] | "\(.purpose)\t\(.name_prefix // .purpose)\t\(.ttl_days // 7)"' "${PURPOSES_FILE}")

pending_json="$(
  cf_token_state_list_pending "${CONSUMER}" \
    | jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {purpose: .[0], token_id: .[1]})'
)"

artifact_path="$(cf_inventory_file "auth" "token-rotate")"

result_json="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg lane "${CF_ACTIVE_TOKEN_LANE:-unknown}" \
    --arg scheme "${CF_ACTIVE_AUTH_SCHEME:-unknown}" \
    --arg credential_env "${CF_ACTIVE_TOKEN_ENV:-unknown}" \
    --arg account_id "${CLOUDFLARE_ACCOUNT_ID}" \
    --arg consumer "${CONSUMER}" \
    --arg sink_dir "${SINK_DIR}" \
    --arg artifact_path "${artifact_path}" \
    --argjson committed "$( [[ "${DRY_RUN}" == "true" ]] && echo false || echo true )" \
    --argjson total "${total}" \
    --argjson rotated "${rotated}" \
    --argjson skipped "${skipped}" \
    --argjson would "${would}" \
    --argjson failed "${failed}" \
    --argjson rotations "${rotated_json}" \
    --argjson skips "${skipped_json}" \
    --argjson pending "${pending_json}" \
    '
      ($failed == 0) as $ok
      | {
          generated_at: $generated_at,
          ok: $ok,
          action: "token.rotate",
          dry_run: ($committed | not),
          auth: {lane: $lane, scheme: $scheme, credential_env: $credential_env},
          account_id: $account_id,
          consumer: $consumer,
          sink_dir: (if $sink_dir == "" then null else $sink_dir end),
          artifact_path: $artifact_path,
          summary: {purposes: $total, rotated: $rotated, skipped: $skipped, would_rotate: $would, failed: $failed},
          result: {manifest: $rotations, skipped: $skips, pending_revoke: $pending},
          error: (if $failed > 0 then {code: "rotate_failed", failed: $failed, hint: "minting needs Account API Tokens Write — rerun on the global lane (CF_TOKEN_LANE=global)"} else null end)
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
