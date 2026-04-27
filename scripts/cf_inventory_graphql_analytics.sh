#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/lib/cloudflare.sh"

cf_load_cloudflare_env
cf_require_tools jq
cf_require_api_auth
cf_require_account_id
cf_setup_log_pipe "inventory-graphql-analytics" "build"

ZONE_NAME="${ZONE_NAME:-example.com}"
ZONE_ID="$(cf_resolve_zone_id "${ZONE_NAME}")"

SCHEMA_PAYLOAD="$(jq -n '{query:"query { __schema { queryType { name } } }"}')"
ACCOUNT_FIELDS_PAYLOAD="$(jq -n '{query:"query { __type(name: \"account\") { fields { name } } }"}')"
ZONE_FIELDS_PAYLOAD="$(jq -n '{query:"query { __type(name: \"zone\") { fields { name } } }"}')"

SCHEMA_JSON="$(cf_api_capture POST "/graphql" -H "Content-Type: application/json" --data "${SCHEMA_PAYLOAD}")"
ACCOUNT_FIELDS_JSON="$(cf_api_capture POST "/graphql" -H "Content-Type: application/json" --data "${ACCOUNT_FIELDS_PAYLOAD}")"
ZONE_FIELDS_JSON="$(cf_api_capture POST "/graphql" -H "Content-Type: application/json" --data "${ZONE_FIELDS_PAYLOAD}")"
ACCOUNT_SAMPLE_PAYLOAD="$(
  jq -n \
    --arg accountTag "${CLOUDFLARE_ACCOUNT_ID}" \
    '{
      query:"query($accountTag: String!){ viewer { accounts(filter: {accountTag: $accountTag}) { gatewayResolverQueriesAdaptiveGroups(limit: 1, filter: {datetime_geq: \"2026-04-20T00:00:00Z\"}) { count dimensions { datetimeHour } } } } }",
      variables:{accountTag:$accountTag}
    }'
)"
ACCOUNT_SAMPLE_JSON="$(cf_api_capture POST "/graphql" -H "Content-Type: application/json" --data "${ACCOUNT_SAMPLE_PAYLOAD}")"
ZONE_SAMPLE_JSON="$(
  if [[ -n "${ZONE_ID}" && "${ZONE_ID}" != "null" ]]; then
    zone_sample_payload="$(
      jq -n \
        --arg zoneTag "${ZONE_ID}" \
        '{
          query:"query($zoneTag: String!){ viewer { zones(filter: {zoneTag: $zoneTag}) { httpRequests1dGroups(limit: 1, filter: {date_gt: \"2026-04-19\"}) { dimensions { date } sum { requests bytes cachedBytes threats pageViews } } } } }",
          variables:{zoneTag:$zoneTag}
        }'
    )"
    cf_api_capture POST "/graphql" -H "Content-Type: application/json" --data "${zone_sample_payload}"
  else
    printf 'null\n'
  fi
)"

OUTPUT_FILE="$(cf_inventory_file "account" "graphql-analytics")"
REPORT_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg zone_name "${ZONE_NAME}" \
    --arg zone_id "${ZONE_ID}" \
    --argjson schema "${SCHEMA_JSON}" \
    --argjson account_fields "${ACCOUNT_FIELDS_JSON}" \
    --argjson zone_fields "${ZONE_FIELDS_JSON}" \
    --argjson account_sample "${ACCOUNT_SAMPLE_JSON}" \
    --argjson zone_sample "${ZONE_SAMPLE_JSON}" \
    '
      def analytics_field_names(fields):
        (fields // [])
        | map(.name)
        | map(select(test("Adaptive|Groups|analytics|firewall|workers|workflow|gateway|loadBal|http|requests|browserIsolation|dns|emailRouting|images|kv|d1|durableObjects|calls|pipelines|containers"; "i")));
      {
        generated_at: $generated_at,
        preferred_zone: {
          name: $zone_name,
          id: $zone_id
        },
        schema_probe: $schema,
        account_type_fields: $account_fields,
        zone_type_fields: $zone_fields,
        account_gateway_resolver_probe: $account_sample,
        zone_http_requests_probe: $zone_sample,
        summary: {
          schema_accessible: ($schema.data.__schema.queryType.name != null),
          account_analytics_field_count: (analytics_field_names($account_fields.data.__type.fields) | length),
          zone_analytics_field_count: (analytics_field_names($zone_fields.data.__type.fields) | length),
          sample_account_analytics_fields: (analytics_field_names($account_fields.data.__type.fields) | .[:40]),
          sample_zone_analytics_fields: (analytics_field_names($zone_fields.data.__type.fields) | .[:40]),
          account_gateway_resolver_probe_success: ($account_sample.data.viewer.accounts[0].gatewayResolverQueriesAdaptiveGroups != null),
          account_gateway_resolver_probe_count: (($account_sample.data.viewer.accounts[0].gatewayResolverQueriesAdaptiveGroups // []) | length),
          zone_http_requests_probe_success: ($zone_sample.data.viewer.zones[0].httpRequests1dGroups != null),
          zone_http_requests_permission_error: (
            ($zone_sample.errors // [])
            | map(select(.extensions.code == "authz"))
            | length
          )
        }
      }
    '
)"

cf_write_json_file "${OUTPUT_FILE}" "${REPORT_JSON}"

echo "Captured GraphQL analytics capability inventory."
echo "${REPORT_JSON}" | jq '{
  schema_accessible: .summary.schema_accessible,
  account_analytics_field_count: .summary.account_analytics_field_count,
  zone_analytics_field_count: .summary.zone_analytics_field_count,
  account_gateway_resolver_probe_success: .summary.account_gateway_resolver_probe_success,
  account_gateway_resolver_probe_count: .summary.account_gateway_resolver_probe_count,
  zone_http_requests_probe_success: .summary.zone_http_requests_probe_success,
  zone_http_requests_permission_error: .summary.zone_http_requests_permission_error,
  sample_account_analytics_fields: (.summary.sample_account_analytics_fields[:12]),
  sample_zone_analytics_fields: (.summary.sample_zone_analytics_fields[:12])
}'
cf_print_log_footer
echo "${OUTPUT_FILE}"
