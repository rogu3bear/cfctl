#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-zero-trust-fleet" "build"

PHYSICAL_DEVICES_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/devices/physical-devices?active_registrations=include")"
REGISTRATIONS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/devices/registrations")"
DEVICE_POLICY_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/devices/policy")"
IP_PROFILES_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/devices/ip-profiles")"
DEX_LIVE_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/dex/fleet-status/live?since_minutes=60")"
DEX_DEVICES_JSON="$(
  from_timestamp="$(date -u -v-1d +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d '1 day ago' +"%Y-%m-%dT%H:%M:%SZ")"
  to_timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/dex/fleet-status/devices?from=${from_timestamp}&to=${to_timestamp}&page=1&per_page=20"
)"
DEX_TESTS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/dex/devices/dex_tests")"
DLP_PROFILES_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/dlp/profiles")"
CASB_INTEGRATIONS_JSON="$(cf_api_capture GET "/accounts/${CLOUDFLARE_ACCOUNT_ID}/casb/integrations")"

OUTPUT_FILE="$(cf_inventory_file "account" "zero-trust-fleet")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson physical_devices "${PHYSICAL_DEVICES_JSON}" \
    --argjson registrations "${REGISTRATIONS_JSON}" \
    --argjson device_policy "${DEVICE_POLICY_JSON}" \
    --argjson ip_profiles "${IP_PROFILES_JSON}" \
    --argjson dex_live "${DEX_LIVE_JSON}" \
    --argjson dex_devices "${DEX_DEVICES_JSON}" \
    --argjson dex_tests "${DEX_TESTS_JSON}" \
    --argjson dlp_profiles "${DLP_PROFILES_JSON}" \
    --argjson casb_integrations "${CASB_INTEGRATIONS_JSON}" \
    '
      {
        generated_at: $generated_at,
        physical_devices: $physical_devices,
        registrations: $registrations,
        device_policy: $device_policy,
        ip_profiles: $ip_profiles,
        dex_live: $dex_live,
        dex_devices: $dex_devices,
        dex_tests: $dex_tests,
        dlp_profiles: $dlp_profiles,
        casb_integrations: $casb_integrations,
        summary: {
          physical_device_count: (($physical_devices.result // []) | length),
          registration_count: (($registrations.result // []) | length),
          device_policy_enabled: ($device_policy.result.enabled // null),
          default_service_mode: ($device_policy.result.service_mode_v2.mode // null),
          ip_profile_count: (($ip_profiles.result // []) | length),
          dex_live_device_total: ($dex_live.result.deviceStats.uniqueDevicesTotal // 0),
          dex_device_count: (($dex_devices.result // []) | length),
          dex_test_count: (($dex_tests.result.dex_tests // []) | length),
          dlp_profile_count: (($dlp_profiles.result // []) | length),
          dlp_enabled_entry_count: (
            ($dlp_profiles.result // [])
            | map((.entries // []) | map(select(.enabled == true)) | length)
            | add
          ),
          dlp_profile_names: (($dlp_profiles.result // []) | map(.name) | sort),
          casb_integration_count: (($casb_integrations.result // []) | length),
          casb_vendor_names: (($casb_integrations.result // []) | map(.vendor.display_name) | sort),
          healthy_casb_integration_count: (($casb_integrations.result // []) | map(select(.status == "Healthy")) | length),
          browser_isolation_rule_count: (
            0
          )
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured Zero Trust fleet, DLP, and CASB inventory."
echo "${REPORT_JSON}" | jq '{
  physical_device_count: .summary.physical_device_count,
  registration_count: .summary.registration_count,
  device_policy_enabled: .summary.device_policy_enabled,
  default_service_mode: .summary.default_service_mode,
  ip_profile_count: .summary.ip_profile_count,
  dex_live_device_total: .summary.dex_live_device_total,
  dex_device_count: .summary.dex_device_count,
  dex_test_count: .summary.dex_test_count,
  dlp_profile_count: .summary.dlp_profile_count,
  dlp_enabled_entry_count: .summary.dlp_enabled_entry_count,
  casb_integration_count: .summary.casb_integration_count,
  healthy_casb_integration_count: .summary.healthy_casb_integration_count,
  casb_vendor_names: .summary.casb_vendor_names
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
