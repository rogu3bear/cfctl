#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_require_var DESTINATION_ADDRESSES_JSON
cf_setup_log_pipe "shared-aliases" "build"

APPLY="${APPLY:-0}"
EXCLUDE_REGEX="${EXCLUDE_REGEX:-^$}"
WORKER_NAME="${WORKER_NAME:-shared-aliases-fanout}"
COMPATIBILITY_DATE="${COMPATIBILITY_DATE:-2026-04-15}"
ALIASES_JSON="${ALIASES_JSON:-[\"noreply\",\"info\",\"hello\",\"security\",\"privacy\",\"founders\"]}"
ZONE_NAMES_JSON="${ZONE_NAMES_JSON:-}"

echo "Loading target zones"
ZONES_JSON="$(
  cf_api GET "/zones?per_page=100&page=1" \
  | jq \
      --arg exclude_regex "${EXCLUDE_REGEX}" \
      --argjson zone_names "${ZONE_NAMES_JSON:-[]}" '
        [
          .result[]
          | . as $zone
          | select(
              if ($zone_names | length) > 0 then
                ($zone_names | index($zone.name)) != null
              else
                ($zone.name | test($exclude_regex; "i") | not)
              end
            )
          | {id: $zone.id, name: $zone.name}
        ]
      '
)"

echo "Checking destination addresses"
DESTINATION_STATE="$(
  cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/email/routing/addresses"
)"

echo "${DESTINATION_STATE}" | jq '{success, result: [.result[] | {email, verified, created}]}'

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
  --argjson aliases "${ALIASES_JSON}" \
  --argjson zones "${ZONES_JSON}" \
  '
    {
      destinations: $destinations,
      aliases: $aliases,
      domains: ($zones | map(.name))
    }
  ' > "${TEMP_CONFIG}"

jq -r '
  . as $cfg |
  "const DESTINATIONS = \($cfg.destinations | tojson);\n" +
  "const ALIASES = \($cfg.aliases | tojson);\n" +
  "const DOMAINS = \($cfg.domains | tojson);\n\n" +
  "function parseAddress(address) {\n" +
  "  const normalized = String(address || \"\").trim().toLowerCase();\n" +
  "  const atIndex = normalized.lastIndexOf(\"@\");\n\n" +
  "  if (atIndex === -1) {\n" +
  "    return { local: normalized, domain: \"\" };\n" +
  "  }\n\n" +
  "  return {\n" +
  "    local: normalized.slice(0, atIndex),\n" +
  "    domain: normalized.slice(atIndex + 1),\n" +
  "  };\n" +
  "}\n\n" +
  "export default {\n" +
  "  async email(message) {\n" +
  "    const parsed = parseAddress(message.to);\n\n" +
  "    if (!ALIASES.includes(parsed.local) || !DOMAINS.includes(parsed.domain)) {\n" +
  "      message.setReject(`unexpected recipient: ${message.to}`);\n" +
  "      return;\n" +
  "    }\n\n" +
  "    for (const destination of DESTINATIONS) {\n" +
  "      await message.forward(\n" +
  "        destination,\n" +
  "        new Headers({\n" +
  "          \"X-Original-Envelope-To\": message.to,\n" +
  "          \"X-Forwarded-By-Worker\": \"shared-aliases-fanout\",\n" +
  "        }),\n" +
  "      );\n" +
  "    }\n" +
  "  },\n" +
  "};\n"
' "${TEMP_CONFIG}" > "${TEMP_WORKER}"

echo "Plan summary"
jq -n \
  --arg worker_name "${WORKER_NAME}" \
  --argjson aliases "${ALIASES_JSON}" \
  --argjson destinations "${DESTINATION_ADDRESSES_JSON}" \
  --argjson zones "${ZONES_JSON}" \
  '
    {
      apply: env.APPLY,
      worker_name: $worker_name,
      alias_count: ($aliases | length),
      destination_count: ($destinations | length),
      zone_count: ($zones | length),
      aliases: $aliases,
      destinations: $destinations,
      zones: ($zones | map(.name))
    }
  '

if [[ "${APPLY}" != "1" ]]; then
  echo "Dry run only. Set APPLY=1 to upload the Worker and create rules."
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
  echo "Worker upload failed; aborting without creating or updating rules." >&2
  exit 1
fi

echo "${ZONES_JSON}" | jq -r '.[] | @base64' | while read -r zone_row; do
  zone_id="$(echo "${zone_row}" | base64 --decode | jq -r '.id')"
  zone_name="$(echo "${zone_row}" | base64 --decode | jq -r '.name')"

  echo "Processing zone ${zone_name}"

  current_rules="$(
    cf_api GET "/zones/${zone_id}/email/routing/rules"
  )"

  echo "${ALIASES_JSON}" | jq -r '.[]' | while read -r alias; do
    address="${alias}@${zone_name}"
    existing_rule_id="$(
      echo "${current_rules}" \
      | jq -r --arg address "${address}" '
          .result[]
          | select(any(.matchers[]?; .field == "to" and (.value | ascii_downcase) == ($address | ascii_downcase)))
          | .id
        ' \
      | head -n 1
    )"

    if [[ -n "${existing_rule_id}" ]]; then
      echo "Rule exists for ${address}: ${existing_rule_id}"
      continue
    fi

    payload="$(
      jq -n \
        --arg worker_name "${WORKER_NAME}" \
        --arg address "${address}" \
        --arg alias "${alias}" '
          {
            name: ("Shared alias " + $alias),
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
            enabled: true
          }
        '
    )"

    echo "Creating rule for ${address}"
    create_response="$(
      cf_api POST "/zones/${zone_id}/email/routing/rules" \
        -H "Content-Type: application/json" \
        --data "${payload}"
    )"

    echo "${create_response}" | jq '{success, errors, result: {id: .result.id, name: .result.name, enabled: .result.enabled}}'

    if ! echo "${create_response}" | jq -e '.success == true' >/dev/null; then
      echo "Failed to create rule for ${address}" >&2
      exit 1
    fi
  done
done

cf_print_log_footer
