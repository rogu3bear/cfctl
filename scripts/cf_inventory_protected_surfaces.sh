#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-protected-surfaces" "build"

ZONE_NAME="${ZONE_NAME:-example.com}"
ZONE_ID="$(cf_resolve_zone_id "${ZONE_NAME}")"

if [[ -z "${ZONE_ID}" || "${ZONE_ID}" == "null" ]]; then
  echo "Unable to resolve zone id for ${ZONE_NAME}" >&2
  exit 1
fi

SSL_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/settings/ssl")"
MIN_TLS_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/settings/min_tls_version")"
TLS13_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/settings/tls_1_3")"
HTTPS_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/settings/always_use_https")"
CUSTOM_HOSTNAMES_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/custom_hostnames")"
WAITING_ROOMS_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/waiting_rooms")"
ZONE_LOGPUSH_JSON="$(cf_api_capture GET "/zones/${ZONE_ID}/logpush/jobs")"
ACCOUNT_LOGPUSH_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/logpush/jobs")"

OUTPUT_FILE="$(cf_inventory_file "account" "protected-surfaces")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg zone_name "${ZONE_NAME}" \
    --arg zone_id "${ZONE_ID}" \
    --argjson ssl "${SSL_JSON}" \
    --argjson min_tls "${MIN_TLS_JSON}" \
    --argjson tls13 "${TLS13_JSON}" \
    --argjson always_https "${HTTPS_JSON}" \
    --argjson custom_hostnames "${CUSTOM_HOSTNAMES_JSON}" \
    --argjson waiting_rooms "${WAITING_ROOMS_JSON}" \
    --argjson zone_logpush "${ZONE_LOGPUSH_JSON}" \
    --argjson account_logpush "${ACCOUNT_LOGPUSH_JSON}" \
    '
      {
        generated_at: $generated_at,
        zone: {
          name: $zone_name,
          id: $zone_id
        },
        ssl: $ssl,
        min_tls_version: $min_tls,
        tls_1_3: $tls13,
        always_use_https: $always_https,
        custom_hostnames: $custom_hostnames,
        waiting_rooms: $waiting_rooms,
        zone_logpush_jobs: $zone_logpush,
        account_logpush_jobs: $account_logpush,
        summary: {
          protected_surface_failures: [
            {surface:"ssl", status_code:$ssl.status_code, success:($ssl.success // false)},
            {surface:"min_tls_version", status_code:$min_tls.status_code, success:($min_tls.success // false)},
            {surface:"tls_1_3", status_code:$tls13.status_code, success:($tls13.success // false)},
            {surface:"always_use_https", status_code:$always_https.status_code, success:($always_https.success // false)},
            {surface:"custom_hostnames", status_code:$custom_hostnames.status_code, success:($custom_hostnames.success // false)},
            {surface:"waiting_rooms", status_code:$waiting_rooms.status_code, success:($waiting_rooms.success // false)},
            {surface:"zone_logpush_jobs", status_code:$zone_logpush.status_code, success:($zone_logpush.success // false)},
            {surface:"account_logpush_jobs", status_code:$account_logpush.status_code, success:($account_logpush.success // false)}
          ] | map(select(.success != true)),
          readable_surface_count: [
            ($ssl.success // false),
            ($min_tls.success // false),
            ($tls13.success // false),
            ($always_https.success // false),
            ($custom_hostnames.success // false),
            ($waiting_rooms.success // false),
            ($zone_logpush.success // false),
            ($account_logpush.success // false)
          ] | map(select(. == true)) | length
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured protected-surface posture for ${ZONE_NAME}."
echo "${REPORT_JSON}" | jq '{
  zone: .zone,
  readable_surface_count: .summary.readable_surface_count,
  protected_surface_failures: .summary.protected_surface_failures
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
