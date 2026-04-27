#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools curl jq
cf_require_api_auth
cf_require_account_id
cf_require_var DESTINATION_EMAIL
cf_setup_log_pipe "destination-verification" "build"

echo "Checking existing destination addresses"
existing="$(
  cf_api GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/email/routing/addresses"
)"

existing_id="$(
  echo "${existing}" \
  | jq -r --arg email "${DESTINATION_EMAIL}" '
      .result[]
      | select((.email | ascii_downcase) == ($email | ascii_downcase))
      | .id
    ' \
  | head -n 1
)"

if [[ -n "${existing_id}" ]]; then
  echo "Destination already exists"
  echo "${existing}" \
    | jq --arg email "${DESTINATION_EMAIL}" '
        {
          success,
          result: [
            .result[]
            | select((.email | ascii_downcase) == ($email | ascii_downcase))
            | {id, email, verified, created, modified}
          ]
        }
      '
  echo "Cloudflare documents verification-email resend in the dashboard. I did not find a documented public resend endpoint."
  cf_print_log_footer
  exit 0
fi

echo "Creating destination address ${DESTINATION_EMAIL}"
create_response="$(
  cf_api POST "/accounts/${CLOUDFLARE_ACCOUNT_ID}/email/routing/addresses" \
    -H "Content-Type: application/json" \
    --data "$(jq -n --arg email "${DESTINATION_EMAIL}" '{email: $email}')"
)"

echo "${create_response}" | jq '{success, errors, messages, result: {id: .result.id, email: .result.email, verified: .result.verified, created: .result.created}}'
echo "If Cloudflare accepted the request, it sent a verification email to ${DESTINATION_EMAIL}. The recipient must click the link in that email."
cf_print_log_footer
