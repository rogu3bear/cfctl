#!/usr/bin/env bash
#
# cfctl token-lifecycle state store — per-consumer scoped-child tracking.
#
# This is the write side of what `cfctl token verify-state` reads. It owns the
# same on-disk schema the app rotators use, so cfctl becomes the brain and the
# app collapses to a thin delivery caller.
#
#   ${CF_TOKEN_STATE_DIR:-~/dev/.secrets-state}/<consumer>.json
#   {
#     consumer, account_id, created_at, updated_at,
#     children: {
#       "<purpose>": {
#         active: { id, minted_at, expires_on },
#         pending_revoke: [ { id, minted_at, expires_on } ]
#       }
#     }
#   }
#
# Sourced as a library — defines functions only, runs nothing at source time.
# Requires: jq, date, mkdir, mktemp (provided by the backend's cf_require_tools).

cf_token_state_dir() {
  printf '%s' "${CF_TOKEN_STATE_DIR:-${HOME}/dev/.secrets-state}"
}

cf_token_state_path() {
  local consumer="$1"
  printf '%s/%s.json' "$(cf_token_state_dir)" "${consumer}"
}

cf_token_state_now() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# Epoch seconds for an ISO8601 UTC timestamp (portable across BSD/GNU date).
# Emits nothing on parse failure so callers can treat it as "unknown".
cf_token_state_iso_to_epoch() {
  local iso="$1"
  [[ -n "${iso}" ]] || return 0
  if date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "${iso}" +%s 2>/dev/null; then
    return 0
  fi
  date -u -d "${iso}" +%s 2>/dev/null || true
}

# Create the state file if missing. Echoes the resolved path.
cf_token_state_init() {
  local consumer="$1" account_id="$2"
  local dir path
  dir="$(cf_token_state_dir)"
  path="$(cf_token_state_path "${consumer}")"
  mkdir -p "${dir}"
  chmod 700 "${dir}" 2>/dev/null || true
  if [[ ! -f "${path}" ]]; then
    jq -n \
      --arg consumer "${consumer}" \
      --arg account_id "${account_id}" \
      --arg now "$(cf_token_state_now)" \
      '{consumer: $consumer, account_id: $account_id, created_at: $now, updated_at: $now, children: {}}' \
      > "${path}"
    chmod 600 "${path}" 2>/dev/null || true
  fi
  printf '%s' "${path}"
}

# Atomically rewrite the state file through a temp sibling, preserving mode 600.
_cf_token_state_write() {
  local path="$1" jq_program="$2"
  shift 2
  local tmp
  tmp="$(mktemp "${path}.XXXXXX")"
  if jq "$@" "${jq_program}" "${path}" > "${tmp}"; then
    mv "${tmp}" "${path}"
    chmod 600 "${path}" 2>/dev/null || true
  else
    rm -f "${tmp}"
    return 1
  fi
}

# Record a freshly minted child as active, demoting any prior active for the
# same purpose onto the pending_revoke queue.
cf_token_state_rotate_child() {
  local consumer="$1" purpose="$2" token_id="$3" expires_on="$4"
  local path
  path="$(cf_token_state_path "${consumer}")"
  _cf_token_state_write "${path}" '
    .updated_at = $now
    | .children[$purpose] = {
        active: { id: $id, minted_at: $now, expires_on: $expires_on },
        pending_revoke: (
          ((.children[$purpose].pending_revoke // []))
          + (if (.children[$purpose].active // null) == null then [] else [.children[$purpose].active] end)
        )
      }
  ' \
    --arg purpose "${purpose}" \
    --arg id "${token_id}" \
    --arg expires_on "${expires_on}" \
    --arg now "$(cf_token_state_now)"
}

# Emit "purpose<TAB>id" rows for every child queued for revocation.
cf_token_state_list_pending() {
  local consumer="$1" path
  path="$(cf_token_state_path "${consumer}")"
  [[ -f "${path}" ]] || return 0
  jq -r '
    .children // {}
    | to_entries[]
    | .key as $k
    | (.value.pending_revoke // [])[]?
    | "\($k)\t\(.id)"
  ' "${path}"
}

# Drop one id from a purpose's pending_revoke queue after a successful revoke.
cf_token_state_clear_pending() {
  local consumer="$1" purpose="$2" token_id="$3" path
  path="$(cf_token_state_path "${consumer}")"
  [[ -f "${path}" ]] || return 0
  _cf_token_state_write "${path}" '
    .updated_at = $now
    | .children[$purpose].pending_revoke = (
        (.children[$purpose].pending_revoke // []) | map(select(.id != $id))
      )
  ' \
    --arg purpose "${purpose}" \
    --arg id "${token_id}" \
    --arg now "$(cf_token_state_now)"
}

cf_token_state_active_id() {
  local consumer="$1" purpose="$2" path
  path="$(cf_token_state_path "${consumer}")"
  [[ -f "${path}" ]] || { printf ''; return 0; }
  jq -r --arg p "${purpose}" '.children[$p].active.id // ""' "${path}"
}

cf_token_state_active_expires() {
  local consumer="$1" purpose="$2" path
  path="$(cf_token_state_path "${consumer}")"
  [[ -f "${path}" ]] || { printf ''; return 0; }
  jq -r --arg p "${purpose}" '.children[$p].active.expires_on // ""' "${path}"
}
