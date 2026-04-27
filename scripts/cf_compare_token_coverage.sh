#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_account_id

COMPARE_ZONE_NAME="${COMPARE_ZONE_NAME:-example.com}"
TOKEN_LANES_JSON="${TOKEN_LANES_JSON:-[\"dev\",\"global\"]}"

LANE_REPORTS='[]'

while IFS= read -r lane; do
  token_env=""
  if token_env="$(cf_token_env_name_for_lane "${lane}" 2>/dev/null)"; then
    :
  else
    LANE_REPORTS="$(
      jq \
        --arg lane "${lane}" \
        '. + [{lane: $lane, available: false, error: "unsupported_lane"}]' \
        <<< "${LANE_REPORTS}"
    )"
    continue
  fi

  if ! cf_token_available_for_lane "${lane}"; then
    LANE_REPORTS="$(
      jq \
        --arg lane "${lane}" \
        --arg token_env "${token_env}" \
        '. + [{lane: $lane, token_env: $token_env, available: false, error: "token_not_present"}]' \
        <<< "${LANE_REPORTS}"
    )"
    continue
  fi

  auth_output="$(CF_TOKEN_LANE="${lane}" "${ROOT_DIR}/scripts/cf_auth_check.sh")"
  auth_artifact="$(tail -n1 <<< "${auth_output}")"
  probe_output="$(CF_TOKEN_LANE="${lane}" ZONE_NAME="${COMPARE_ZONE_NAME}" "${ROOT_DIR}/scripts/cf_probe_token_permissions.sh")"
  probe_artifact="$(tail -n1 <<< "${probe_output}")"

  LANE_REPORTS="$(
    jq \
      --arg lane "${lane}" \
      --arg token_env "${token_env}" \
      --arg auth_artifact "${auth_artifact}" \
      --arg probe_artifact "${probe_artifact}" \
      --argjson auth_report "$(cat "${auth_artifact}")" \
      --argjson probe_report "$(cat "${probe_artifact}")" \
      '
        . + [
          {
            lane: $lane,
            token_env: $token_env,
            available: true,
            auth_artifact: $auth_artifact,
            probe_artifact: $probe_artifact,
            auth_report: $auth_report,
            probe_report: $probe_report
          }
        ]
      ' \
      <<< "${LANE_REPORTS}"
  )"
done < <(jq -r '.[]' <<< "${TOKEN_LANES_JSON}")

OUTPUT_FILE="$(cf_inventory_file "auth" "token-coverage-comparison")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg compare_zone_name "${COMPARE_ZONE_NAME}" \
    --argjson lanes "${LANE_REPORTS}" \
    '
      ($lanes | map(select(.available == true))) as $available
      | ($available | map(select(.lane == "dev")) | .[0] // null) as $dev
      | ($available | map(select(.lane == "global")) | .[0] // null) as $global
      | ($dev.probe_report.summary.failures // [] | map(.label) | unique | sort) as $dev_failures
      | ($global.probe_report.summary.failures // [] | map(.label) | unique | sort) as $global_failures
      | ($global_failures | map(select(startswith("auth.")))) as $global_scheme_failures
      | ($global_failures | map(select(startswith("auth.") | not))) as $global_product_failures
      | ($dev.probe_report.probes // [] | map(select(.success == true) | .label) | unique | sort) as $dev_successes
      | ($global.probe_report.probes // [] | map(select(.success == true) | .label) | unique | sort) as $global_successes
      | {
          generated_at: $generated_at,
          compare_zone_name: $compare_zone_name,
          lanes: $lanes,
          summary: {
            available_lanes: ($available | map(.lane)),
            missing_lanes: ($lanes | map(select(.available != true)) | map({lane, token_env, error})),
            lane_summaries: (
              $available
              | map({
                  lane,
                  token_env,
                  auth_scheme: (.auth_report.auth.auth_scheme // "unknown"),
                  success_count: (.probe_report.summary.success_count // 0),
                  failure_count: (.probe_report.summary.failure_count // 0),
                  failure_labels: ((.probe_report.summary.failures // []) | map(.label) | unique | sort)
                })
            ),
            comparison: (
              if ($dev != null and $global != null) then
                {
                  global_unlocks: ($dev_failures | map(. as $label | select(($global_successes | index($label)) != null))),
                  remaining_global_failures: $global_product_failures,
                  scheme_specific_global_failures: $global_scheme_failures,
                  unchanged_failures: ($dev_failures | map(. as $label | select(($global_product_failures | index($label)) != null))),
                  global_regressions: ($dev_successes | map(. as $label | select(($global_product_failures | index($label)) != null)))
                }
              else
                null
              end
            )
          }
        }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Compared Cloudflare token coverage across configured lanes."
echo "${REPORT_JSON}" | jq '{
  compare_zone_name,
  available_lanes: .summary.available_lanes,
  missing_lanes: .summary.missing_lanes,
  lane_summaries: .summary.lane_summaries,
  comparison: .summary.comparison
}'
echo "${OUTPUT_FILE}"
