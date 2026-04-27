#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq awk sed
cf_require_api_auth
cf_setup_log_pipe "inventory-mtls-certs" "build"

RAW_OUTPUT="$("${ROOT_DIR}/scripts/cf_wrangler.sh" cert list 2>&1 || true)"
PARSED_JSON="$(
  printf '%s\n' "${RAW_OUTPUT}" \
    | sed $'s/\033\\[[0-9;]*[A-Za-z]//g' \
    | awk '
        /^ID: / {
          if (id != "") {
            printf "%s\t%s\t%s\t%s\t%s\t%s\n", id, name, issuer, created_on, expires_on, ca
          }
          id = substr($0, 5)
          name = issuer = created_on = expires_on = ca = ""
        }
        /^Name: / { name = substr($0, 7) }
        /^Issuer: / { issuer = substr($0, 9) }
        /^Created on: / { created_on = substr($0, 13) }
        /^Expires on: / { expires_on = substr($0, 13) }
        /^CA: / { ca = substr($0, 5) }
        END {
          if (id != "") {
            printf "%s\t%s\t%s\t%s\t%s\t%s\n", id, name, issuer, created_on, expires_on, ca
          }
        }
      ' \
    | jq -R -s '
        split("\n")
        | map(select(length > 0))
        | map(split("\t"))
        | map({
            id: .[0],
            name: .[1],
            issuer: .[2],
            created_on: .[3],
            expires_on: .[4],
            is_ca: (.[5] == "true")
          })
      '
)"

OUTPUT_FILE="$(cf_inventory_file "account" "mtls-certs")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg raw_output "${RAW_OUTPUT}" \
    --argjson certificates "${PARSED_JSON}" \
    '
      {
        generated_at: $generated_at,
        certificates: $certificates,
        raw_output: $raw_output,
        summary: {
          certificate_count: ($certificates | length),
          ca_certificate_count: ($certificates | map(select(.is_ca == true)) | length),
          names: ($certificates | map(.name) | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured mTLS certificate inventory."
echo "${REPORT_JSON}" | jq '{
  certificate_count: .summary.certificate_count,
  ca_certificate_count: .summary.ca_certificate_count,
  names: .summary.names
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
