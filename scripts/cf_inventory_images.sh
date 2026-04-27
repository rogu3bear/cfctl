#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-images" "build"

IMAGES_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/images/v2")"
VARIANTS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/images/v1/variants")"

OUTPUT_FILE="$(cf_inventory_file "account" "images")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson images "${IMAGES_JSON}" \
    --argjson variants "${VARIANTS_JSON}" \
    '
      {
        generated_at: $generated_at,
        images: $images,
        variants: $variants,
        summary: {
          image_count: (($images.result.images // []) | length),
          variant_count: (($variants.result.variants // []) | length),
          continuation_token: ($images.result.continuation_token // null),
          signed_url_required_count: (($images.result.images // []) | map(select(.requireSignedURLs == true)) | length),
          sample_filenames: (($images.result.images // []) | map(.filename) | map(select(. != null)) | unique | sort | .[:20]),
          variant_names: (($variants.result.variants // []) | map(.id // .name) | map(select(. != null)) | unique | sort)
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Images inventory."
echo "${REPORT_JSON}" | jq '{
  image_count: .summary.image_count,
  variant_count: .summary.variant_count,
  signed_url_required_count: .summary.signed_url_required_count,
  variant_names: .summary.variant_names
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
