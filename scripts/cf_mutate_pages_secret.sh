#!/usr/bin/env bash

# Mutates Cloudflare Pages project secrets (deployment_configs env_vars of type
# secret_text) via PATCH /accounts/:id/pages/projects/:project.
#
#   upsert: GET the project, then PATCH a MERGED env_vars map that re-sends every
#           existing entry (existing secret_text re-sent type-only, which
#           Cloudflare preserves — the same mechanism `wrangler pages secret put`
#           relies on) plus {NAME: {type: secret_text, value: <file>}}. Re-sending
#           the full map avoids any risk of a partial PATCH replacing env_vars.
#   delete: re-send the merged map with {NAME: null}.
#
# A Pages secret only binds on the project's NEXT deployment.
#
# Inputs (env from cfctl apply dispatch):
#   OPERATION         upsert | delete
#   PAGES_PROJECT     project name                       (--project)
#   SECRET_NAME       env-var name                       (--name)
#   VALUE_FILE        path whose contents are the value  (upsert; --file)
#   PAGES_ENVIRONMENT production | preview (default production)
#
# Preview/ack gating is enforced centrally by cfctl_handle_apply.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_require_backend_dispatch "cfctl apply pages.secret <operation> ..."

OPERATION="${OPERATION:-upsert}"
PAGES_PROJECT="${PAGES_PROJECT:-}"
SECRET_NAME="${SECRET_NAME:-}"
VALUE_FILE="${VALUE_FILE:-}"
ENVIRONMENT="${PAGES_ENVIRONMENT:-production}"

[[ -n "${PAGES_PROJECT}" ]] || { echo "PAGES_PROJECT (--project) required" >&2; exit 1; }
[[ -n "${SECRET_NAME}" ]] || { echo "SECRET_NAME (--name) required" >&2; exit 1; }

# Snapshot the current env_vars for the target environment so the PATCH carries
# a complete, merged map. Existing secret_text entries are re-sent WITHOUT a
# value (Cloudflare keeps their stored value); plain_text entries keep their
# value. We never transmit a secret value we cannot read.
existing_env_vars="{}"
project_capture="$(cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/pages/projects/${PAGES_PROJECT}")"
existing_env_vars="$(
  jq -c --arg env "${ENVIRONMENT}" '
    (.result.deployment_configs[$env].env_vars // {})
    | with_entries(
        if (.value.type // "plain_text") == "secret_text"
        then .value = {type: "secret_text"}
        else . end)
  ' <<< "${project_capture}"
)"
[[ -n "${existing_env_vars}" && "${existing_env_vars}" != "null" ]] || existing_env_vars="{}"

case "${OPERATION}" in
  upsert)
    [[ -r "${VALUE_FILE}" ]] || { echo "VALUE_FILE (--file <path>) unreadable: ${VALUE_FILE}" >&2; exit 1; }
    merged_env_vars="$(
      jq -n --argjson existing "${existing_env_vars}" --arg name "${SECRET_NAME}" --rawfile val "${VALUE_FILE}" \
        '$existing + {($name): {type: "secret_text", value: $val}}'
    )"
    ;;
  delete)
    merged_env_vars="$(
      jq -n --argjson existing "${existing_env_vars}" --arg name "${SECRET_NAME}" \
        '$existing + {($name): null}'
    )"
    ;;
  *)
    echo "Unsupported OPERATION: ${OPERATION}" >&2
    exit 1
    ;;
esac

export SURFACE="pages-secret"
export OUTPUT_STEM="pages-secret-mutation"
export APPLY="${APPLY:-0}"
export SECRET_BODY="1"
export REQUEST_METHOD="PATCH"
export REQUEST_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/pages/projects/${PAGES_PROJECT}"
export BODY_JSON="$(jq -n --arg env "${ENVIRONMENT}" --argjson env_vars "${merged_env_vars}" '{deployment_configs: {($env): {env_vars: $env_vars}}}')"
export VERIFY_PATH="/accounts/${CLOUDFLARE_ACCOUNT_ID}/pages/projects/${PAGES_PROJECT}"
unset BODY_FILE

exec "${ROOT_DIR}/scripts/cf_api_apply.sh"
