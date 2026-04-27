#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "accounts-fanout" "build"

ZONE_NAME="${ZONE_NAME:-example.com}"
RULE_EMAIL="${RULE_EMAIL:-accounts@example.com}"
WORKER_NAME="${WORKER_NAME:-accounts-fanout}"
WORKER_ENTRY="${WORKER_ENTRY:-${ROOT_DIR}/workers/accounts-fanout/index.js}"
COMPATIBILITY_DATE="${COMPATIBILITY_DATE:-2026-04-15}"

echo "Resolving zone for ${ZONE_NAME}"
ZONE_ID="$(
  cf_api GET "/zones?name=${ZONE_NAME}" \
  | jq -r '.result[0].id'
)"

if [[ -z "${ZONE_ID}" || "${ZONE_ID}" == "null" ]]; then
  echo "Zone not found for ${ZONE_NAME}" >&2
  exit 1
fi

echo "Zone ID: ${ZONE_ID}"

echo "Checking Email Routing status"
ROUTING_STATE="$(
  cf_api GET "/zones/${ZONE_ID}/email/routing"
)"

echo "${ROUTING_STATE}" | jq '{enabled: .result.enabled, status: .result.status, errors: .result.errors}'

echo "Uploading Worker ${WORKER_NAME} from ${WORKER_ENTRY}"
METADATA_FILE="$(mktemp)"
trap 'rm -f "${METADATA_FILE}"' EXIT

jq -n \
  --arg main_module "$(basename "${WORKER_ENTRY}")" \
  --arg compatibility_date "${COMPATIBILITY_DATE}" \
  '{main_module: $main_module, compatibility_date: $compatibility_date}' \
  > "${METADATA_FILE}"

UPLOAD_RESPONSE="$(
  cf_api PUT "/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${WORKER_NAME}" \
    -F "metadata=@${METADATA_FILE};type=application/json" \
    -F "$(basename "${WORKER_ENTRY}")=@${WORKER_ENTRY};type=application/javascript+module"
)"

echo "${UPLOAD_RESPONSE}" | jq '{success, errors, messages, result: {id: .result.id, tag: .result.etag}}'

EXISTING_RULE_ID="$(
  cf_api GET "/zones/${ZONE_ID}/email/routing/rules" \
  | jq -r --arg rule_email "${RULE_EMAIL}" '
      .result[]
      | select(any(.matchers[]?; .field == "to" and (.value | ascii_downcase) == ($rule_email | ascii_downcase)))
      | .id
    ' \
  | head -n 1
)"

if [[ -n "${EXISTING_RULE_ID}" ]]; then
  echo "Rule for ${RULE_EMAIL} already exists: ${EXISTING_RULE_ID}"
else
  echo "Creating Email Routing rule for ${RULE_EMAIL}"
  CREATE_RULE_PAYLOAD="$(jq -n \
    --arg worker_name "${WORKER_NAME}" \
    --arg rule_email "${RULE_EMAIL}" '
      {
        name: "Accounts fanout",
        matchers: [
          {
            type: "literal",
            field: "to",
            value: $rule_email
          }
        ],
        actions: [
          {
            type: "worker",
            value: [$worker_name]
          }
        ],
        enabled: true,
        priority: 1
      }
    '
  )"

  CREATE_RULE_RESPONSE="$(
    cf_api POST "/zones/${ZONE_ID}/email/routing/rules" \
      -H "Content-Type: application/json" \
      --data "${CREATE_RULE_PAYLOAD}"
  )"

  echo "${CREATE_RULE_RESPONSE}" | jq '{success, errors, result: {id: .result.id, name: .result.name, enabled: .result.enabled}}'
fi

echo "Current Email Routing rules"
cf_api GET "/zones/${ZONE_ID}/email/routing/rules" \
  | jq '{success, result: [.result[] | {id, name, enabled, matchers, actions}]}'

cf_print_log_footer
