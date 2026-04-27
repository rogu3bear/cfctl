#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-stream" "build"

VIDEOS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/stream")"
LIVE_INPUTS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/stream/live_inputs")"

OUTPUT_FILE="$(cf_inventory_file "account" "stream")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson videos "${VIDEOS_JSON}" \
    --argjson live_inputs "${LIVE_INPUTS_JSON}" \
    '
      {
        generated_at: $generated_at,
        videos: $videos,
        live_inputs: $live_inputs,
        summary: {
          video_count: (($videos.result // []) | length),
          ready_video_count: (($videos.result // []) | map(select(.status.state == "ready" or .status == "ready")) | length),
          live_video_count: (($videos.result // []) | map(select(.status.state == "live-inprogress" or .status == "live-inprogress")) | length),
          live_input_count: (($live_inputs.result // []) | length),
          enabled_live_input_count: (($live_inputs.result // []) | map(select(.enabled == true)) | length),
          sample_video_ids: (($videos.result // []) | map(.uid) | map(select(. != null)) | .[:20]),
          sample_live_input_ids: (($live_inputs.result // []) | map(.uid) | map(select(. != null)) | .[:20])
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Stream inventory."
echo "${REPORT_JSON}" | jq '{
  video_count: .summary.video_count,
  ready_video_count: .summary.ready_video_count,
  live_video_count: .summary.live_video_count,
  live_input_count: .summary.live_input_count,
  enabled_live_input_count: .summary.enabled_live_input_count
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
