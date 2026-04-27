#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_setup_log_pipe "inventory-capabilities" "build"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
NULL_JSON="${TMP_DIR}/null.json"
printf 'null\n' > "${NULL_JSON}"

latest_stem_file() {
  local stem="$1"
  find "${ROOT_DIR}/var/inventory" -type f \
    | grep -E "/${stem}-[0-9]{8}T[0-9]{6}Z\\.json$" \
    | sort \
    | tail -n 1
}

latest_stem_or_null_file() {
  local stem="$1"
  local path
  path="$(latest_stem_file "${stem}")"
  if [[ -n "${path}" && -f "${path}" ]]; then
    printf '%s\n' "${path}"
  else
    printf '%s\n' "${NULL_JSON}"
  fi
}

AUTH_FILE="$(latest_stem_or_null_file 'auth-check')"
ACCOUNT_FILE="$(latest_stem_or_null_file 'account')"
ZONES_FILE="$(latest_stem_or_null_file 'zones')"
WORKERS_FILE="$(latest_stem_or_null_file 'workers')"
WORKER_TOPOLOGY_FILE="$(latest_stem_or_null_file 'worker-topology')"
WORKERS_AI_FILE="$(latest_stem_or_null_file 'workers-ai')"
PAGES_FILE="$(latest_stem_or_null_file 'pages-projects')"
D1_FILE="$(latest_stem_or_null_file 'd1')"
KV_FILE="$(latest_stem_or_null_file 'kv-namespaces')"
R2_FILE="$(latest_stem_or_null_file 'r2-buckets')"
QUEUES_FILE="$(latest_stem_or_null_file 'queues')"
WORKFLOWS_FILE="$(latest_stem_or_null_file 'workflows')"
IMAGES_FILE="$(latest_stem_or_null_file 'images')"
STREAM_FILE="$(latest_stem_or_null_file 'stream')"
CALLS_FILE="$(latest_stem_or_null_file 'calls')"
HYPERDRIVE_FILE="$(latest_stem_or_null_file 'hyperdrive')"
VECTORIZE_FILE="$(latest_stem_or_null_file 'vectorize')"
AI_GATEWAY_FILE="$(latest_stem_or_null_file 'ai-gateway')"
ACCESS_FILE="$(latest_stem_or_null_file 'access-apps')"
ACCESS_AUDIT_FILE="$(latest_stem_or_null_file 'access-audit')"
ZERO_TRUST_FILE="$(latest_stem_or_null_file 'zero-trust')"
ZERO_TRUST_EXTENDED_FILE="$(latest_stem_or_null_file 'zero-trust-extended')"
ZERO_TRUST_FLEET_FILE="$(latest_stem_or_null_file 'zero-trust-fleet')"
TURNSTILE_FILE="$(latest_stem_or_null_file 'turnstile')"
LOAD_BALANCING_FILE="$(latest_stem_or_null_file 'load-balancing')"
ZONE_SECURITY_FILE="$(latest_stem_or_null_file 'zone-security')"
ZONE_SECURITY_MATRIX_FILE="$(latest_stem_or_null_file 'zone-security-matrix')"
WAF_BOT_FILE="$(latest_stem_or_null_file 'waf-bot-management')"
API_SHIELD_FILE="$(latest_stem_or_null_file 'api-shield')"
GRAPHQL_ANALYTICS_FILE="$(latest_stem_or_null_file 'graphql-analytics')"
REGISTRAR_FILE="$(latest_stem_or_null_file 'registrar')"
BROWSER_ISOLATION_FILE="$(latest_stem_or_null_file 'browser-isolation')"
PROTECTED_SURFACES_FILE="$(latest_stem_or_null_file 'protected-surfaces')"
SSL_POSTURE_FILE="$(latest_stem_or_null_file 'ssl-posture')"
WAITING_ROOMS_FILE="$(latest_stem_or_null_file 'waiting-rooms')"
LOGPUSH_FILE="$(latest_stem_or_null_file 'logpush')"
TOKEN_PERMISSIONS_FILE="$(latest_stem_or_null_file 'token-permissions')"
OPEN_BETA_FILE="$(latest_stem_or_null_file 'open-beta')"
CONTAINERS_FILE="$(latest_stem_or_null_file 'containers')"
MTLS_CERTS_FILE="$(latest_stem_or_null_file 'mtls-certs')"
SECRETS_STORE_FILE="$(latest_stem_or_null_file 'secrets-store')"
VPC_FILE="$(latest_stem_or_null_file 'vpc')"
PIPELINES_FILE="$(latest_stem_or_null_file 'pipelines')"
TUNNELS_FILE="$(latest_stem_or_null_file 'tunnels')"
DNS_FILE="$(latest_stem_or_null_file 'dns')"
EMAIL_FILE="$(latest_stem_or_null_file 'email-routing-audit')"

OUTPUT_FILE="$(cf_inventory_file "account" "capability-audit")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --slurpfile auth "${AUTH_FILE}" \
    --slurpfile account "${ACCOUNT_FILE}" \
    --slurpfile zones "${ZONES_FILE}" \
    --slurpfile workers "${WORKERS_FILE}" \
    --slurpfile worker_topology "${WORKER_TOPOLOGY_FILE}" \
    --slurpfile workers_ai "${WORKERS_AI_FILE}" \
    --slurpfile pages "${PAGES_FILE}" \
    --slurpfile d1 "${D1_FILE}" \
    --slurpfile kv "${KV_FILE}" \
    --slurpfile r2 "${R2_FILE}" \
    --slurpfile queues "${QUEUES_FILE}" \
    --slurpfile workflows "${WORKFLOWS_FILE}" \
    --slurpfile images "${IMAGES_FILE}" \
    --slurpfile stream "${STREAM_FILE}" \
    --slurpfile calls "${CALLS_FILE}" \
    --slurpfile hyperdrive "${HYPERDRIVE_FILE}" \
    --slurpfile vectorize "${VECTORIZE_FILE}" \
    --slurpfile ai_gateway "${AI_GATEWAY_FILE}" \
    --slurpfile access "${ACCESS_FILE}" \
    --slurpfile access_audit "${ACCESS_AUDIT_FILE}" \
    --slurpfile zero_trust "${ZERO_TRUST_FILE}" \
    --slurpfile zero_trust_extended "${ZERO_TRUST_EXTENDED_FILE}" \
    --slurpfile zero_trust_fleet "${ZERO_TRUST_FLEET_FILE}" \
    --slurpfile turnstile "${TURNSTILE_FILE}" \
    --slurpfile load_balancing "${LOAD_BALANCING_FILE}" \
    --slurpfile zone_security "${ZONE_SECURITY_FILE}" \
    --slurpfile zone_security_matrix "${ZONE_SECURITY_MATRIX_FILE}" \
    --slurpfile waf_bot "${WAF_BOT_FILE}" \
    --slurpfile api_shield "${API_SHIELD_FILE}" \
    --slurpfile graphql_analytics "${GRAPHQL_ANALYTICS_FILE}" \
    --slurpfile registrar "${REGISTRAR_FILE}" \
    --slurpfile browser_isolation "${BROWSER_ISOLATION_FILE}" \
    --slurpfile protected_surfaces "${PROTECTED_SURFACES_FILE}" \
    --slurpfile ssl_posture "${SSL_POSTURE_FILE}" \
    --slurpfile waiting_rooms "${WAITING_ROOMS_FILE}" \
    --slurpfile logpush "${LOGPUSH_FILE}" \
    --slurpfile token_permissions "${TOKEN_PERMISSIONS_FILE}" \
    --slurpfile open_beta "${OPEN_BETA_FILE}" \
    --slurpfile containers "${CONTAINERS_FILE}" \
    --slurpfile mtls_certs "${MTLS_CERTS_FILE}" \
    --slurpfile secrets_store "${SECRETS_STORE_FILE}" \
    --slurpfile vpc "${VPC_FILE}" \
    --slurpfile pipelines "${PIPELINES_FILE}" \
    --slurpfile tunnels "${TUNNELS_FILE}" \
    --slurpfile dns "${DNS_FILE}" \
    --slurpfile email "${EMAIL_FILE}" \
    '
      ($auth[0]) as $auth
      | ($account[0]) as $account
      | ($zones[0]) as $zones
      | ($workers[0]) as $workers
      | ($worker_topology[0]) as $worker_topology
      | ($workers_ai[0]) as $workers_ai
      | ($pages[0]) as $pages
      | ($d1[0]) as $d1
      | ($kv[0]) as $kv
      | ($r2[0]) as $r2
      | ($queues[0]) as $queues
      | ($workflows[0]) as $workflows
      | ($images[0]) as $images
      | ($stream[0]) as $stream
      | ($calls[0]) as $calls
      | ($hyperdrive[0]) as $hyperdrive
      | ($vectorize[0]) as $vectorize
      | ($ai_gateway[0]) as $ai_gateway
      | ($access[0]) as $access
      | ($access_audit[0]) as $access_audit
      | ($zero_trust[0]) as $zero_trust
      | ($zero_trust_extended[0]) as $zero_trust_extended
      | ($zero_trust_fleet[0]) as $zero_trust_fleet
      | ($turnstile[0]) as $turnstile
      | ($load_balancing[0]) as $load_balancing
      | ($zone_security[0]) as $zone_security
      | ($zone_security_matrix[0]) as $zone_security_matrix
      | ($waf_bot[0]) as $waf_bot
      | ($api_shield[0]) as $api_shield
      | ($graphql_analytics[0]) as $graphql_analytics
      | ($registrar[0]) as $registrar
      | ($browser_isolation[0]) as $browser_isolation
      | ($protected_surfaces[0]) as $protected_surfaces
      | ($ssl_posture[0]) as $ssl_posture
      | ($waiting_rooms[0]) as $waiting_rooms
      | ($logpush[0]) as $logpush
      | ($token_permissions[0]) as $token_permissions
      | ($open_beta[0]) as $open_beta
      | ($containers[0]) as $containers
      | ($mtls_certs[0]) as $mtls_certs
      | ($secrets_store[0]) as $secrets_store
      | ($vpc[0]) as $vpc
      | ($pipelines[0]) as $pipelines
      | ($tunnels[0]) as $tunnels
      | ($dns[0]) as $dns
      | ($email[0]) as $email
      | {
          generated_at: $generated_at,
          account_context: {
            auth_scheme: ($auth.auth.auth_scheme // null),
            account_id: ($account.account.id // null),
            account_name: ($account.account.name // null)
          },
          in_use_and_inventoried: [
            {capability: "Zones", evidence_count: ($zones.summary.zone_count // 0)},
            {capability: "Workers", evidence_count: ($workers.summary.script_count // 0)},
            {capability: "Durable Objects", evidence_count: (($worker_topology.summary.scripts_with_durable_objects // []) | length)},
            {capability: "Workers AI", evidence_count: ($workers_ai.summary.worker_ai_binding_script_count // 0)},
            {capability: "Containers", evidence_count: ($containers.summary.container_count // 0)},
            {capability: "Pages", evidence_count: ($pages.summary.project_count // 0)},
            {capability: "D1", evidence_count: ($d1.summary.database_count // 0)},
            {capability: "KV", evidence_count: ($kv.summary.namespace_count // 0)},
            {capability: "R2", evidence_count: ($r2.summary.bucket_count // 0)},
            {capability: "Queues", evidence_count: ($queues.summary.queue_count // 0)},
            {capability: "Workflows", evidence_count: ($workflows.summary.workflow_count // 0)},
            {capability: "Images", evidence_count: ($images.summary.image_count // 0)},
            {capability: "Calls", evidence_count: ($calls.summary.app_count // 0) + ($calls.summary.turn_key_count // 0)},
            {capability: "Access", evidence_count: ($access.summary.app_count // 0)},
            {capability: "Zero Trust", evidence_count: ($zero_trust.summary.gateway_rule_count // 0) + ($zero_trust.summary.identity_provider_count // 0) + ($zero_trust.summary.service_token_count // 0) + ($zero_trust_extended.summary.gateway_location_count // 0) + ($zero_trust_extended.summary.device_posture_rule_count // 0)},
            {capability: "CASB", evidence_count: ($zero_trust_fleet.summary.casb_integration_count // 0)},
            {capability: "DLP Profiles", evidence_count: ($zero_trust_fleet.summary.dlp_profile_count // 0)},
            {capability: "Registrar", evidence_count: ($registrar.summary.registration_count // 0)},
            {capability: "Browser Isolation", evidence_count: ($browser_isolation.summary.browser_isolation_signal_count // 0)},
            {capability: "Turnstile", evidence_count: ($turnstile.summary.widget_count // 0)},
            {capability: "mTLS Certificates", evidence_count: ($mtls_certs.summary.certificate_count // 0)},
            {capability: "Secrets Store", evidence_count: ($secrets_store.summary.store_count // 0)},
            {capability: "Email Routing Destinations", evidence_count: (($email.destination_addresses.result // []) | length)}
          ] | map(select(.evidence_count > 0)),
          present_but_unused_or_empty: [
            {capability: "Stream", evidence_count: ($stream.summary.video_count // 0) + ($stream.summary.live_input_count // 0)},
            {capability: "API Shield", evidence_count: ($api_shield.summary.managed_operation_count // 0) + ($api_shield.summary.discovered_operation_count // 0) + ($api_shield.summary.user_schema_count // 0) + ($api_shield.summary.schema_validation_count // 0)},
            {capability: "Hyperdrive", evidence_count: ($hyperdrive.summary.hyperdrive_count // 0)},
            {capability: "Vectorize", evidence_count: ($vectorize.summary.index_count // 0)},
            {capability: "AI Gateway", evidence_count: ($ai_gateway.summary.gateway_count // 0)},
            {capability: "Load Balancing", evidence_count: ($load_balancing.summary.load_balancer_count // 0) + ($load_balancing.summary.pool_count // 0) + ($load_balancing.summary.monitor_count // 0)},
            {capability: "Gateway Lists", evidence_count: ($zero_trust_extended.summary.gateway_list_count // 0)},
            {capability: "Gateway Proxy Endpoints", evidence_count: ($zero_trust_extended.summary.proxy_endpoint_count // 0)},
            {capability: "WARP Devices", evidence_count: ($zero_trust_fleet.summary.physical_device_count // 0)},
            {capability: "WARP Registrations", evidence_count: ($zero_trust_fleet.summary.registration_count // 0)},
            {capability: "DEX Live Devices", evidence_count: ($zero_trust_fleet.summary.dex_live_device_total // 0)},
            {capability: "IP Profiles", evidence_count: ($zero_trust_fleet.summary.ip_profile_count // 0)},
            {capability: "Waiting Rooms", evidence_count: ($waiting_rooms.summary.waiting_room_count // 0)},
            {capability: "Logpush Jobs", evidence_count: ($logpush.summary.account_job_count // 0) + ($logpush.summary.zone_job_count // 0)},
            {capability: "VPC Services", evidence_count: ($vpc.summary.service_count // 0)},
            {capability: "Pipelines", evidence_count: ($pipelines.summary.pipeline_count // 0)},
            {capability: "Tunnels", evidence_count: ($tunnels.summary.tunnel_count // 0)}
          ],
          partially_covered_or_permission_limited: [
            {
              capability: "DNS",
              dns_success_count: (($dns.zones // []) | map(select(.dns.success == true)) | length),
              dns_error_count: (($dns.zones // []) | map(select((.dns.errors // []) | length > 0)) | length)
            },
            {
              capability: "Email Routing Zone Reads",
              zone_permission_error_count: (
                ($email.zones // [])
                | map(select(((.rule_errors // []) | length) > 0 or (.email_routing.success == false)))
                | length
              )
            },
            {
              capability: "Access IdP Hygiene",
              empty_allowed_idps: (($access_audit.findings.empty_allowed_idps // []) | length)
            },
            {
              capability: "Zone Security Surface Permissions",
              permission_limited_surface_count: (
                (($zone_security.summary.permission_limited_surfaces // []) | map(select((.status_code // 0) == 401 or (.status_code // 0) == 403)) | length)
                + ($zone_security_matrix.summary.firewall_access_permission_failure_count // 0)
                + ($zone_security_matrix.summary.rate_limit_permission_failure_count // 0)
              )
            },
            {
              capability: "Bot Management Permissions",
              permission_limited_zone_count: ($waf_bot.summary.bot_management_permission_failure_count // 0)
            },
            {
              capability: "GraphQL Analytics Permissions",
              failure_count: ($graphql_analytics.summary.zone_http_requests_permission_error // 0)
            },
            {
              capability: "GraphQL Analytics Schema Visibility",
              accessible_dataset_field_count: (
                ($graphql_analytics.summary.account_analytics_field_count // 0)
                + ($graphql_analytics.summary.zone_analytics_field_count // 0)
              )
            },
            {
              capability: "SSL And Certificate Permissions",
              permission_limited_surface_count: (
                ($ssl_posture.summary.zone_count // 0)
                - ($ssl_posture.summary.certificate_packs_readable_zone_count // 0)
                + (($protected_surfaces.summary.protected_surface_failures // []) | length)
              )
            },
            {
              capability: "Waiting Room Permissions",
              permission_limited_zone_count: ($waiting_rooms.summary.permission_error_count // 0)
            },
            {
              capability: "Logpush Permissions",
              failure_count: (
                (if ($logpush.account_jobs.success // false) then 0 else 1 end)
                + ($logpush.summary.permission_error_count // 0)
              )
            },
            {
              capability: "Token Permission Failures",
              failure_count: (
                ($token_permissions.summary.failures // [])
                | map(select((.label // "") | startswith("auth.") | not))
                | length
              )
            },
            {
              capability: "Protected Surface Failures",
              failure_count: (($protected_surfaces.summary.protected_surface_failures // []) | length)
            }
          ],
          high_level_cloudflare_areas_not_yet_inventoried: [
            "Analytics dataset query coverage beyond the current sample probes",
            "Mutation wrappers for API Shield and zone security"
          ],
          next_best_expansions: [
            "Add dedicated mutation wrappers for API Shield operations and zone security lifecycle changes.",
            "Add Browser Isolation-specific mutation paths, including clientless isolation and isolate-rule policy posture.",
            "Add more GraphQL analytics probes for specific datasets such as firewall events, load balancing, Workers, and email routing.",
            "Add permission introspection that maps failing probe endpoints to likely missing token scopes.",
            "Promote readable beta surfaces into structured mutation workflows where the command output has stabilized."
          ]
        }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Generated Cloudflare capability audit."
echo "${REPORT_JSON}" | jq '{
  account_context,
  in_use_and_inventoried,
  present_but_unused_or_empty,
  partially_covered_or_permission_limited,
  high_level_cloudflare_areas_not_yet_inventoried
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
