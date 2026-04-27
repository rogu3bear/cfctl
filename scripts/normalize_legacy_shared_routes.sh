#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "shared-aliases" "build-normalize-legacy-shared"

APPLY="${APPLY:-0}"
WORKER_NAME="${WORKER_NAME:-shared-collab-fanout}"
COMPATIBILITY_DATE="${COMPATIBILITY_DATE:-2026-04-16}"
DESTINATION_ADDRESSES_JSON="${DESTINATION_ADDRESSES_JSON:-[\"primary@example.com\",\"backup@example.com\"]}"
# ROUTES_JSON is operator-supplied. Provide either as an env var or by editing this file
# for your own deployment. The example below shows the expected shape; do not commit
# real addresses or zones to a public fork.
DEFAULT_ROUTES_JSON="$(cat <<'JSON'
[
  {"zone":"example.com","address":"hello@example.com"},
  {"zone":"example.org","address":"hello@example.org"}
]
JSON
)"
ROUTES_JSON="${ROUTES_JSON:-$DEFAULT_ROUTES_JSON}"

echo "Checking destination addresses"
DESTINATION_STATE="$(
  cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/email/routing/addresses"
)"

echo "${DESTINATION_STATE}" | jq '{success, result: [.result[] | {email, verified, created}]}'

missing_or_unverified="$(
  echo "${DESTINATION_STATE}" \
  | jq -r \
      --argjson destinations "${DESTINATION_ADDRESSES_JSON}" '
        . as $state |
        [
          $destinations[]
          | . as $target
          | select(
              ([$state.result[]
                | select((.email | ascii_downcase) == ($target | ascii_downcase))
                | select(.verified != null)
              ] | length) == 0
            )
        ] | .[]?
      '
)"

if [[ -n "${missing_or_unverified}" ]]; then
  echo "Destination addresses must exist and be verified before shared routing can be applied." >&2
  echo "${missing_or_unverified}" >&2
  exit 1
fi

echo "Resolving zones for configured routes"
ZONES_JSON="$(
  cf_api GET "/zones?per_page=100&page=1" \
  | jq --argjson routes "${ROUTES_JSON}" '
      [
        .result[]
        | . as $zone
        | select(any($routes[]; .zone == $zone.name))
        | {id: .id, name: .name}
      ]
    '
)"

TEMP_WORKER="$(mktemp)"
TEMP_METADATA="$(mktemp)"
TEMP_CONFIG="$(mktemp)"
trap 'rm -f "${TEMP_WORKER}" "${TEMP_METADATA}" "${TEMP_CONFIG}"' EXIT

jq -n \
  --arg main_module "index.js" \
  --arg compatibility_date "${COMPATIBILITY_DATE}" \
  '{main_module: $main_module, compatibility_date: $compatibility_date}' \
  > "${TEMP_METADATA}"

jq -n \
  --argjson destinations "${DESTINATION_ADDRESSES_JSON}" \
  --argjson routes "${ROUTES_JSON}" \
  '
    {
      destinations: $destinations,
      routes: $routes
    }
  ' > "${TEMP_CONFIG}"

jq -r '
  . as $cfg |
  "const DESTINATIONS = \($cfg.destinations | tojson);\n" +
  "const ROUTES = new Set(\($cfg.routes | map(.address | ascii_downcase) | tojson));\n\n" +
  "export default {\n" +
  "  async email(message) {\n" +
  "    const recipient = String(message.to || \"\").trim().toLowerCase();\n" +
  "    if (!ROUTES.has(recipient)) {\n" +
  "      message.setReject(`unexpected recipient: ${message.to}`);\n" +
  "      return;\n" +
  "    }\n" +
  "    for (const destination of DESTINATIONS) {\n" +
  "      await message.forward(\n" +
  "        destination,\n" +
  "        new Headers({\n" +
  "          \"X-Original-Envelope-To\": message.to,\n" +
  "          \"X-Forwarded-By-Worker\": \"shared-collab-fanout\",\n" +
  "        }),\n" +
  "      );\n" +
  "    }\n" +
  "  },\n" +
  "};\n"
' "${TEMP_CONFIG}" > "${TEMP_WORKER}"

echo "Plan summary"
jq -n \
  --arg worker_name "${WORKER_NAME}" \
  --argjson destinations "${DESTINATION_ADDRESSES_JSON}" \
  --argjson routes "${ROUTES_JSON}" \
  '{
    apply: env.APPLY,
    worker_name: $worker_name,
    destination_count: ($destinations | length),
    route_count: ($routes | length),
    destinations: $destinations,
    routes: $routes
  }'

if [[ "${APPLY}" != "1" ]]; then
  echo "Dry run only. Set APPLY=1 to upload the Worker and normalize routes."
  echo "Build log written to ${LOG_FILE}"
  exit 0
fi

echo "Uploading Worker ${WORKER_NAME}"
UPLOAD_RESPONSE="$(
  cf_api PUT "/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${WORKER_NAME}" \
    -F "metadata=@${TEMP_METADATA};type=application/json" \
    -F "index.js=@${TEMP_WORKER};filename=index.js;type=application/javascript+module"
)"

echo "${UPLOAD_RESPONSE}" | jq '{success, errors, messages, result: {id: .result.id, tag: .result.etag}}'

if ! echo "${UPLOAD_RESPONSE}" | jq -e '.success == true' >/dev/null; then
  echo "Worker upload failed; aborting without updating routes." >&2
  exit 1
fi

echo "${ROUTES_JSON}" | jq -r '.[] | @base64' | while read -r route_row; do
  zone_name="$(echo "${route_row}" | base64 --decode | jq -r '.zone')"
  address="$(echo "${route_row}" | base64 --decode | jq -r '.address')"
  local_part="${address%@*}"
  zone_id="$(
    echo "${ZONES_JSON}" \
    | jq -r --arg zone_name "${zone_name}" '.[] | select(.name == $zone_name) | .id' \
    | head -n 1
  )"

  if [[ -z "${zone_id}" ]]; then
    echo "Unable to resolve zone id for ${zone_name}" >&2
    exit 1
  fi

  current_rules="$(
    cf_api GET "/zones/${zone_id}/email/routing/rules"
  )"

  existing_rule_id="$(
    echo "${current_rules}" \
    | jq -r --arg address "${address}" '
        .result[]
        | select(any(.matchers[]?; .field == "to" and (.value | ascii_downcase) == ($address | ascii_downcase)))
        | .id
      ' \
    | head -n 1
  )"

  payload="$(
    jq -n \
      --arg worker_name "${WORKER_NAME}" \
      --arg address "${address}" \
      --arg local_part "${local_part}" '
        {
          name: ("Shared legacy " + $local_part),
          matchers: [
            {
              type: "literal",
              field: "to",
              value: $address
            }
          ],
          actions: [
            {
              type: "worker",
              value: [$worker_name]
            }
          ],
          enabled: true,
          priority: 0
        }
      '
  )"

  if [[ -n "${existing_rule_id}" ]]; then
    echo "Updating route ${address}: ${existing_rule_id}"
    update_response="$(
      cf_api PUT "/zones/${zone_id}/email/routing/rules/${existing_rule_id}" \
        -H "Content-Type: application/json" \
        --data "${payload}"
    )"

    echo "${update_response}" | jq '{success, errors, result: {id: .result.id, name: .result.name, enabled: .result.enabled}}'

    if ! echo "${update_response}" | jq -e '.success == true' >/dev/null; then
      echo "Failed to update ${address}" >&2
      exit 1
    fi
  else
    echo "Creating route ${address}"
    create_response="$(
      cf_api POST "/zones/${zone_id}/email/routing/rules" \
        -H "Content-Type: application/json" \
        --data "${payload}"
    )"

    echo "${create_response}" | jq '{success, errors, result: {id: .result.id, name: .result.name, enabled: .result.enabled}}'

    if ! echo "${create_response}" | jq -e '.success == true' >/dev/null; then
      echo "Failed to create ${address}" >&2
      exit 1
    fi
  fi
done

cf_print_log_footer
