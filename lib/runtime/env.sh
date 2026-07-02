#!/usr/bin/env bash

set -euo pipefail

cfctl_env_file_mode() {
  local file="${1:-}"
  local mode

  if [[ -z "${file}" || ! -e "${file}" ]]; then
    printf 'absent\n'
    return
  fi

  if mode="$(stat -f '%Lp' "${file}" 2>/dev/null)"; then
    printf '%s\n' "${mode}"
    return
  fi

  if mode="$(stat -c '%a' "${file}" 2>/dev/null)"; then
    printf '%s\n' "${mode}"
    return
  fi

  printf 'unknown\n'
}

cfctl_env_sources_json() {
  local shared_env_file="${CF_SHARED_ENV_FILE:-${CF_SHARED_ENV_FILE_DEFAULT}}"
  local repo_env_file="${CF_REPO_ENV_FILE:-${CF_REPO_ENV_FILE_DEFAULT}}"
  local workspace_env_file

  workspace_env_file="$(cf_workspace_env_file)"

  jq -n \
    --arg shared_path "${shared_env_file}" \
    --arg repo_path "${repo_env_file}" \
    --arg workspace_path "${workspace_env_file}" \
    --arg shared_mode "$(cfctl_env_file_mode "${shared_env_file}")" \
    --arg repo_mode "$(cfctl_env_file_mode "${repo_env_file}")" \
    --arg workspace_mode "$(cfctl_env_file_mode "${workspace_env_file}")" \
    --argjson shared_present "$([[ -f "${shared_env_file}" ]] && echo true || echo false)" \
    --argjson repo_present "$([[ -f "${repo_env_file}" ]] && echo true || echo false)" \
    --argjson workspace_present "$([[ -n "${workspace_env_file}" && -f "${workspace_env_file}" ]] && echo true || echo false)" \
    --argjson workspace_enabled "$([[ -n "${workspace_env_file}" ]] && echo true || echo false)" \
    '
      [
        {
          id: "repo",
          path: $repo_path,
          present: $repo_present,
          mode: $repo_mode,
          loader: "shell_source",
          precedence: 1
        },
        {
          id: "shared",
          path: $shared_path,
          present: $shared_present,
          mode: $shared_mode,
          loader: "shell_source",
          precedence: 2
        },
        {
          id: "workspace",
          path: $workspace_path,
          present: $workspace_present,
          mode: $workspace_mode,
          loader: "strict_allowlisted_import",
          fill_gaps_only: true,
          enabled: $workspace_enabled,
          precedence: 3
        }
      ]
    '
}

cfctl_env_provenance_json() {
  local sources_json
  local vars_json='[]'
  local name
  local live_fingerprint
  local source_rows
  local source_id
  local source_path
  local source_present
  local fingerprint
  local row

  sources_json="$(cfctl_env_sources_json)"

  while IFS= read -r name; do
    [[ -n "${name}" ]] || continue

    live_fingerprint=""
    if [[ -n "${!name:-}" ]]; then
      live_fingerprint="$(cf_env_value_fingerprint "${!name}")"
    fi

    source_rows='[]'
    while IFS=$'\t' read -r source_id source_path source_present; do
      [[ -n "${source_id}" ]] || continue
      fingerprint=""
      if [[ "${source_present}" == "true" ]]; then
        fingerprint="$(cf_env_value_fingerprint_from_file "${source_path}" "${name}" 2>/dev/null || true)"
      fi
      source_rows="$(
        jq -c \
          --arg source_id "${source_id}" \
          --arg fingerprint "${fingerprint}" \
          --arg live_fingerprint "${live_fingerprint}" \
          '
            . + [{
              source: $source_id,
              fingerprint: (if $fingerprint == "" then null else $fingerprint end),
              matches_live: (
                if $fingerprint == "" or $live_fingerprint == "" then false
                else $fingerprint == $live_fingerprint
                end
              )
            }]
          ' <<< "${source_rows}"
      )"
    done < <(jq -r '.[] | [.id, .path, (.present | tostring)] | @tsv' <<< "${sources_json}")

    row="$(
      jq -n \
        --arg name "${name}" \
        --arg live_fingerprint "${live_fingerprint}" \
        --argjson sources "${source_rows}" \
        '
          ($sources | map(select(.fingerprint != null)) | map(.fingerprint) | unique) as $distinct
          | {
              var: $name,
              set: ($live_fingerprint != ""),
              live_fingerprint: (if $live_fingerprint == "" then null else $live_fingerprint end),
              sources: $sources,
              winner_source: (
                ($sources | map(select(.matches_live == true)) | first | .source) // null
              ),
              drift: (($distinct | length) > 1)
            }
        '
    )"
    vars_json="$(jq -c --argjson row "${row}" '. + [$row]' <<< "${vars_json}")"
  done < <(cf_env_import_allowlist_json | jq -r '.[]?')

  jq -n \
    --argjson sources "${sources_json}" \
    --argjson vars "${vars_json}" \
    '
      {
        sources: $sources,
        vars: $vars,
        summary: {
          tracked_var_count: ($vars | length),
          set_var_count: ($vars | map(select(.set == true)) | length),
          drift_count: ($vars | map(select(.drift == true)) | length),
          drift_vars: ($vars | map(select(.drift == true)) | map(.var))
        }
      }
    '
}

cfctl_env_hygiene_json() {
  local stray_repo_env="${CF_REPO_ROOT}/.env"
  local repo_env_file="${CF_REPO_ENV_FILE:-${CF_REPO_ENV_FILE_DEFAULT}}"

  jq -n \
    --arg stray_path "${stray_repo_env}" \
    --arg stray_mode "$(cfctl_env_file_mode "${stray_repo_env}")" \
    --arg repo_env_file "${repo_env_file}" \
    --argjson stray_present "$([[ -f "${stray_repo_env}" ]] && echo true || echo false)" \
    --argjson repo_env_present "$([[ -f "${repo_env_file}" ]] && echo true || echo false)" \
    '
      {
        stray_repo_env: {
          path: $stray_path,
          present: $stray_present,
          mode: $stray_mode,
          loaded_by_cfctl: false,
          note: "cfctl loads the repo override from .env.local, never .env; secrets in repo-root .env have no consumer."
        },
        repo_env_local: {
          path: $repo_env_file,
          present: $repo_env_present,
          optional: true
        },
        issues: (
          []
          + (if $stray_present then ["stray_repo_env_present"] else [] end)
        )
      }
    '
}

cfctl_env_health_json() {
  jq -n \
    --argjson provenance "$(cfctl_env_provenance_json)" \
    --argjson hygiene "$(cfctl_env_hygiene_json)" \
    '{provenance: $provenance, hygiene: $hygiene}'
}
