#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools bash jq
cf_require_api_auth
cf_setup_log_pipe "agent-bootstrap" "build"

run_and_capture_path() {
  local output
  output="$("$@")"
  printf '%s\n' "${output}"
  printf '%s\n' "${output}" | tail -n 1
}

AUTH_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_auth_check.sh" | tail -n 1)"
ACCOUNT_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_account.sh" | tail -n 1)"
ZONES_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_zones.sh" | tail -n 1)"
WORKERS_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_workers.sh" | tail -n 1)"
WORKER_TOPOLOGY_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_worker_topology.sh" | tail -n 1)"
WORKERS_AI_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_workers_ai.sh" | tail -n 1)"
PAGES_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_pages.sh" | tail -n 1)"
D1_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_d1.sh" | tail -n 1)"
KV_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_kv.sh" | tail -n 1)"
R2_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_r2.sh" | tail -n 1)"
QUEUES_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_queues.sh" | tail -n 1)"
WORKFLOWS_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_workflows.sh" | tail -n 1)"
IMAGES_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_images.sh" | tail -n 1)"
STREAM_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_stream.sh" | tail -n 1)"
CALLS_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_calls.sh" | tail -n 1)"
HYPERDRIVE_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_hyperdrive.sh" | tail -n 1)"
VECTORIZE_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_vectorize.sh" | tail -n 1)"
AI_GATEWAY_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_ai_gateway.sh" | tail -n 1)"
ACCESS_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_access.sh" | tail -n 1)"
ACCESS_AUDIT_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_audit_access_apps.sh" | tail -n 1)"
ZERO_TRUST_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_zero_trust.sh" | tail -n 1)"
ZERO_TRUST_EXTENDED_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_zero_trust_extended.sh" | tail -n 1)"
ZERO_TRUST_FLEET_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_zero_trust_fleet.sh" | tail -n 1)"
TURNSTILE_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_turnstile.sh" | tail -n 1)"
LOAD_BALANCING_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_load_balancing.sh" | tail -n 1)"
ZONE_SECURITY_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_zone_security.sh" | tail -n 1)"
ZONE_SECURITY_MATRIX_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_zone_security_matrix.sh" | tail -n 1)"
WAF_BOT_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_waf_bot_management.sh" | tail -n 1)"
API_SHIELD_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_api_shield.sh" | tail -n 1)"
GRAPHQL_ANALYTICS_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_graphql_analytics.sh" | tail -n 1)"
REGISTRAR_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_registrar.sh" | tail -n 1)"
BROWSER_ISOLATION_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_browser_isolation.sh" | tail -n 1)"
PROTECTED_SURFACES_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_protected_surfaces.sh" | tail -n 1)"
SSL_POSTURE_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_ssl_posture.sh" | tail -n 1)"
WAITING_ROOMS_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_waiting_rooms.sh" | tail -n 1)"
LOGPUSH_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_logpush.sh" | tail -n 1)"
TOKEN_PERMISSIONS_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_probe_token_permissions.sh" | tail -n 1)"
OPEN_BETA_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_open_beta.sh" | tail -n 1)"
CONTAINERS_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_containers.sh" | tail -n 1)"
MTLS_CERTS_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_mtls_certs.sh" | tail -n 1)"
SECRETS_STORE_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_secrets_store.sh" | tail -n 1)"
VPC_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_vpc.sh" | tail -n 1)"
PIPELINES_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_pipelines.sh" | tail -n 1)"
TUNNELS_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_tunnels.sh" | tail -n 1)"
EMAIL_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/audit_email_routing.sh" | tail -n 1)"

WRANGLER_OUTPUT="$("${ROOT_DIR}/scripts/cf_wrangler.sh" whoami 2>&1 || true)"
WRANGLER_LOG_FILE="$(cf_inventory_file "auth" "wrangler-whoami" "txt")"
printf '%s\n' "${WRANGLER_OUTPUT}" > "${WRANGLER_LOG_FILE}"
CAPABILITY_AUDIT_FILE="$(run_and_capture_path "${ROOT_DIR}/scripts/cf_inventory_capability_audit.sh" | tail -n 1)"

OUTPUT_FILE="$(cf_inventory_file "account" "agent-bootstrap")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg auth_file "${AUTH_FILE}" \
    --arg account_file "${ACCOUNT_FILE}" \
    --arg zones_file "${ZONES_FILE}" \
    --arg workers_file "${WORKERS_FILE}" \
    --arg worker_topology_file "${WORKER_TOPOLOGY_FILE}" \
    --arg workers_ai_file "${WORKERS_AI_FILE}" \
    --arg pages_file "${PAGES_FILE}" \
    --arg d1_file "${D1_FILE}" \
    --arg kv_file "${KV_FILE}" \
    --arg r2_file "${R2_FILE}" \
    --arg queues_file "${QUEUES_FILE}" \
    --arg workflows_file "${WORKFLOWS_FILE}" \
    --arg images_file "${IMAGES_FILE}" \
    --arg stream_file "${STREAM_FILE}" \
    --arg calls_file "${CALLS_FILE}" \
    --arg hyperdrive_file "${HYPERDRIVE_FILE}" \
    --arg vectorize_file "${VECTORIZE_FILE}" \
    --arg ai_gateway_file "${AI_GATEWAY_FILE}" \
    --arg access_file "${ACCESS_FILE}" \
    --arg access_audit_file "${ACCESS_AUDIT_FILE}" \
    --arg zero_trust_file "${ZERO_TRUST_FILE}" \
    --arg zero_trust_extended_file "${ZERO_TRUST_EXTENDED_FILE}" \
    --arg zero_trust_fleet_file "${ZERO_TRUST_FLEET_FILE}" \
    --arg turnstile_file "${TURNSTILE_FILE}" \
    --arg load_balancing_file "${LOAD_BALANCING_FILE}" \
    --arg zone_security_file "${ZONE_SECURITY_FILE}" \
    --arg zone_security_matrix_file "${ZONE_SECURITY_MATRIX_FILE}" \
    --arg waf_bot_file "${WAF_BOT_FILE}" \
    --arg api_shield_file "${API_SHIELD_FILE}" \
    --arg graphql_analytics_file "${GRAPHQL_ANALYTICS_FILE}" \
    --arg registrar_file "${REGISTRAR_FILE}" \
    --arg browser_isolation_file "${BROWSER_ISOLATION_FILE}" \
    --arg protected_surfaces_file "${PROTECTED_SURFACES_FILE}" \
    --arg ssl_posture_file "${SSL_POSTURE_FILE}" \
    --arg waiting_rooms_file "${WAITING_ROOMS_FILE}" \
    --arg logpush_file "${LOGPUSH_FILE}" \
    --arg token_permissions_file "${TOKEN_PERMISSIONS_FILE}" \
    --arg open_beta_file "${OPEN_BETA_FILE}" \
    --arg containers_file "${CONTAINERS_FILE}" \
    --arg mtls_certs_file "${MTLS_CERTS_FILE}" \
    --arg secrets_store_file "${SECRETS_STORE_FILE}" \
    --arg vpc_file "${VPC_FILE}" \
    --arg pipelines_file "${PIPELINES_FILE}" \
    --arg tunnels_file "${TUNNELS_FILE}" \
    --arg email_file "${EMAIL_FILE}" \
    --arg capability_audit_file "${CAPABILITY_AUDIT_FILE}" \
    --arg wrangler_file "${WRANGLER_LOG_FILE}" \
    '
      {
        generated_at: $generated_at,
        bootstrap_outputs: {
          auth: $auth_file,
          account: $account_file,
          zones: $zones_file,
          workers: $workers_file,
          worker_topology: $worker_topology_file,
          workers_ai: $workers_ai_file,
          pages: $pages_file,
          d1: $d1_file,
          kv: $kv_file,
          r2: $r2_file,
          queues: $queues_file,
          workflows: $workflows_file,
          images: $images_file,
          stream: $stream_file,
          calls: $calls_file,
          hyperdrive: $hyperdrive_file,
          vectorize: $vectorize_file,
          ai_gateway: $ai_gateway_file,
          access: $access_file,
          access_audit: $access_audit_file,
          zero_trust: $zero_trust_file,
          zero_trust_extended: $zero_trust_extended_file,
          zero_trust_fleet: $zero_trust_fleet_file,
          turnstile: $turnstile_file,
          load_balancing: $load_balancing_file,
          zone_security: $zone_security_file,
          zone_security_matrix: $zone_security_matrix_file,
          waf_bot_management: $waf_bot_file,
          api_shield: $api_shield_file,
          graphql_analytics: $graphql_analytics_file,
          registrar: $registrar_file,
          browser_isolation: $browser_isolation_file,
          protected_surfaces: $protected_surfaces_file,
          ssl_posture: $ssl_posture_file,
          waiting_rooms: $waiting_rooms_file,
          logpush: $logpush_file,
          token_permissions: $token_permissions_file,
          open_beta: $open_beta_file,
          containers: $containers_file,
          mtls_certs: $mtls_certs_file,
          secrets_store: $secrets_store_file,
          vpc: $vpc_file,
          pipelines: $pipelines_file,
          tunnels: $tunnels_file,
          email_routing: $email_file,
          capability_audit: $capability_audit_file,
          wrangler_whoami: $wrangler_file
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Generated Cloudflare bootstrap inventory for agents."
echo "${REPORT_JSON}" | jq '.bootstrap_outputs'
cf_print_log_footer
echo "${OUTPUT_FILE}"
