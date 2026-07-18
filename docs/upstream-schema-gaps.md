# Upstream Cloudflare OpenAPI gaps (root cause of the blocked-capability wall)

> **Provenance — snapshot 2026-07-17.** Every hard count in this document (242
> unannotated mutating operations, 1436 already annotated, 652 plan-availability
> operations, 1336 cost-blocked capabilities, and the "~50%" / "83%" ratios) is
> a point-in-time reading of `cloudflare/api-schemas@main` taken on 2026-07-17.
> The live catalog owns the current numbers: **`cfctl catalog coverage`
> supersedes anything here whenever they disagree** (per `LAYERS.md`, catalog
> outranks prose). These figures are frozen so the document can be filed
> upstream, not maintained as a live coverage source. Regenerate the raw counts
> with the script under [Reproduce](#reproduce) below.

`cfctl`'s catalog is generated from Cloudflare's official OpenAPI at
`cloudflare/api-schemas` (`openapi.json`). A capability is marked `blocked`
when the schema does not carry the metadata cfctl needs to govern a mutation
**fail-closed** — required permission scope, and a bounded/known incremental
cost. cfctl will **not fabricate** either (a guessed permission or price is
worse than an honest block), so these gaps are the dominant reason ~50% of the
catalog is blocked.

Of the currently-blocked capabilities, **83% are blocked on one of the two
upstream gaps below** — neither of which cfctl can safely close on its own.
This document is the basis for filing them against `cloudflare/api-schemas`.

---

## Gap 1 — 242 mutating operations carry no permission annotation

Across the schema, **1436 mutating operations declare `x-api-token-group`**
(the API-token permission group required to call them). But **242
mutating operations (POST/PUT/PATCH/DELETE) declare neither `x-api-token-group`
nor `x-cfPermissionsRequired`** — no permission signal at all. A programmatic
client cannot determine what token scope these operations require, so it cannot
mint a least-privilege token or fail closed correctly.

**Ask:** add `x-api-token-group` to the operations below, consistent with the
other 1436 mutating operations that already declare it.

<details><summary>All 242 operations, grouped by product (95 products)</summary>


**Origin Cloud Regions** (9)
- `origin-cloud-regions-batch-delete` — DELETE `/zones/{zone_id}/cache/origin_cloud_regions/batch`
- `origin-cloud-regions-batch-upsert` — PATCH `/zones/{zone_id}/cache/origin_cloud_regions/batch`
- `origin-cloud-regions-create` — POST `/zones/{zone_id}/cache/origin_cloud_regions`
- `origin-cloud-regions-delete` — DELETE `/zones/{zone_id}/cache/origin_cloud_regions/{origin_ip}`
- `origin-cloud-regions-upsert` — PATCH `/zones/{zone_id}/cache/origin_cloud_regions`
- `origin-cloud-regions-v2-batch-delete` — DELETE `/zones/{zone_id}/origin/cloud_regions/batch`
- `origin-cloud-regions-v2-batch-upsert` — PUT `/zones/{zone_id}/origin/cloud_regions/batch`
- `origin-cloud-regions-v2-delete` — DELETE `/zones/{zone_id}/origin/cloud_regions/{origin_ip}`
- `origin-cloud-regions-v2-upsert` — PUT `/zones/{zone_id}/origin/cloud_regions/{origin_ip}`

**R2 Super Slurper** (8)
- `slurper-abort-all-jobs` — PUT `/accounts/{account_id}/slurper/jobs/abortAll`
- `slurper-abort-job` — PUT `/accounts/{account_id}/slurper/jobs/{job_id}/abort`
- `slurper-check-source-connectivity` — PUT `/accounts/{account_id}/slurper/source/connectivity-precheck`
- `slurper-check-target-connectivity` — PUT `/accounts/{account_id}/slurper/target/connectivity-precheck`
- `slurper-create-job` — POST `/accounts/{account_id}/slurper/jobs`
- `slurper-delete-job` — DELETE `/accounts/{account_id}/slurper/jobs/{job_id}`
- `slurper-pause-job` — PUT `/accounts/{account_id}/slurper/jobs/{job_id}/pause`
- `slurper-resume-job` — PUT `/accounts/{account_id}/slurper/jobs/{job_id}/resume`

**Email Sending suppressions** (7)
- `delete_publicDeleteSendingSuppression` — DELETE `/accounts/{account_id}/email/sending/suppressions/{suppression_id}`
- `delete_publicDeleteSuppressionSending` — DELETE `/accounts/{account_id}/email/sending/suppression/{suppression_id}`
- `delete_publicDeleteSuppressionZoneSending` — DELETE `/zones/{zone_id}/email/sending/suppression/{suppression_id}`
- `post_publicBulkCreateSendingSuppressions` — POST `/accounts/{account_id}/email/sending/suppressions/bulk`
- `post_publicCreateSendingSuppression` — POST `/accounts/{account_id}/email/sending/suppressions`
- `post_publicNewSuppressionSending` — POST `/accounts/{account_id}/email/sending/suppression`
- `post_publicNewSuppressionZoneSending` — POST `/zones/{zone_id}/email/sending/suppression`

**Secrets Store** (7)
- `secrets-store-system-create` — POST `/system/accounts/{account_tag}/stores`
- `secrets-store-system-delete-bulk` — DELETE `/system/accounts/{account_tag}/stores/{store_id}/secrets`
- `secrets-store-system-delete-by-id` — DELETE `/system/accounts/{account_tag}/stores/{store_id}`
- `secrets-store-system-duplicate-by-id` — POST `/system/accounts/{account_tag}/stores/{store_id}/secrets/{secret_id}/duplicate`
- `secrets-store-system-patch-by-id` — PATCH `/system/accounts/{account_tag}/stores/{store_id}/secrets/{secret_id}`
- `secrets-store-system-secret-create` — POST `/system/accounts/{account_tag}/stores/{store_id}/secrets`
- `secrets-store-system-secret-delete-by-id` — DELETE `/system/accounts/{account_tag}/stores/{store_id}/secrets/{secret_id}`

**Custom Indicator Feeds** (6)
- `custom-indicator-feeds-add-permission` — PUT `/accounts/{account_id}/intel/indicator-feeds/permissions/add`
- `custom-indicator-feeds-create-indicator-feeds` — POST `/accounts/{account_id}/intel/indicator-feeds`
- `custom-indicator-feeds-create-provider` — PUT `/accounts/{account_id}/intel/indicator-feeds/permissions/createProvider`
- `custom-indicator-feeds-remove-permission` — PUT `/accounts/{account_id}/intel/indicator-feeds/permissions/remove`
- `custom-indicator-feeds-update-indicator-feed-data` — PUT `/accounts/{account_id}/intel/indicator-feeds/{feed_id}/snapshot`
- `custom-indicator-feeds-update-indicator-feed-metadata` — PUT `/accounts/{account_id}/intel/indicator-feeds/{feed_id}`

**Infrastructure Access Targets** (6)
- `infra-targets-delete` — DELETE `/accounts/{account_id}/infrastructure/targets/{target_id}`
- `infra-targets-delete-batch` — DELETE `/accounts/{account_id}/infrastructure/targets/batch`
- `infra-targets-delete-batch-post` — POST `/accounts/{account_id}/infrastructure/targets/batch_delete`
- `infra-targets-post` — POST `/accounts/{account_id}/infrastructure/targets`
- `infra-targets-put` — PUT `/accounts/{account_id}/infrastructure/targets/{target_id}`
- `infra-targets-put-batch` — PUT `/accounts/{account_id}/infrastructure/targets/batch`

**Zero Trust Gateway rules** (6)
- `zero-trust-gateway-rules-create-zero-trust-gateway-rule` — POST `/accounts/{account_id}/gateway/rules`
- `zero-trust-gateway-rules-delete-zero-trust-gateway-rule` — DELETE `/accounts/{account_id}/gateway/rules/{rule_id}`
- `zero-trust-gateway-rules-patch-multiple-zero-trust-gateway-rules` — PATCH `/accounts/{account_id}/gateway/rules`
- `zero-trust-gateway-rules-patch-zero-trust-gateway-rule` — PATCH `/accounts/{account_id}/gateway/rules/{rule_id}`
- `zero-trust-gateway-rules-reset-expiration-zero-trust-gateway-rule` — POST `/accounts/{account_id}/gateway/rules/{rule_id}/reset_expiration`
- `zero-trust-gateway-rules-update-zero-trust-gateway-rule` — PUT `/accounts/{account_id}/gateway/rules/{rule_id}`

**Applications** (5)
- `containerInstanceExec` — POST `/accounts/{account_id}/containers/applications/{application_id}/instances/{instance_id}/exec`
- `containerInstanceFetch` — POST `/accounts/{account_id}/containers/applications/{application_id}/instances/{instance_id}/fetch`
- `createApplication` — POST `/accounts/{account_id}/containers/applications`
- `createApplicationRollout` — POST `/accounts/{account_id}/containers/applications/{application_id}/rollouts`
- `createContainerInstance` — POST `/accounts/{account_id}/containers/applications/{application_id}/instances`

**Integrations** (5)
- `create_integration_v2` — POST `/accounts/{account_id}/one/integrations`
- `delete_integration_v2` — DELETE `/accounts/{account_id}/one/integrations/{id}`
- `pause_integration_v2` — POST `/accounts/{account_id}/one/integrations/{id}/pause`
- `resume_integration_v2` — POST `/accounts/{account_id}/one/integrations/{id}/resume`
- `update_integration_v2` — PATCH `/accounts/{account_id}/one/integrations/{id}`

**MoQ Relays** (5)
- `moq-relays-create` — POST `/accounts/{account_id}/moq/relays`
- `moq-relays-delete` — DELETE `/accounts/{account_id}/moq/relays/{relay_id}`
- `moq-relays-tokens-create` — POST `/accounts/{account_id}/moq/relays/{relay_id}/tokens`
- `moq-relays-tokens-delete` — DELETE `/accounts/{account_id}/moq/relays/{relay_id}/tokens/{jti}`
- `moq-relays-update` — PUT `/accounts/{account_id}/moq/relays/{relay_id}`

**R2 Bucket** (5)
- `r2-create-temp-access-credentials` — POST `/accounts/{account_id}/r2/temp-access-credentials`
- `r2-delete-bucket-cors-policy` — DELETE `/accounts/{account_id}/r2/buckets/{bucket_name}/cors`
- `r2-put-bucket-cors-policy` — PUT `/accounts/{account_id}/r2/buckets/{bucket_name}/cors`
- `r2-put-bucket-lifecycle-configuration` — PUT `/accounts/{account_id}/r2/buckets/{bucket_name}/lifecycle`
- `r2-put-bucket-lock-configuration` — PUT `/accounts/{account_id}/r2/buckets/{bucket_name}/lock`

**Rules** (5)
- `cloudforce-one-create-rule` — POST `/accounts/{account_id}/cloudforce-one/rules`
- `cloudforce-one-delete-all-rules` — DELETE `/accounts/{account_id}/cloudforce-one/rules`
- `cloudforce-one-delete-rule` — DELETE `/accounts/{account_id}/cloudforce-one/rules/{id}`
- `cloudforce-one-update-rule` — PUT `/accounts/{account_id}/cloudforce-one/rules/{id}`
- `cloudforce-one-validate-rule` — POST `/accounts/{account_id}/cloudforce-one/rules/validate`

**Zero Trust lists** (5)
- `zero-trust-lists-create-zero-trust-list` — POST `/accounts/{account_id}/gateway/lists`
- `zero-trust-lists-create-zero-trust-list-from-csv` — POST `/accounts/{account_id}/gateway/lists/upload`
- `zero-trust-lists-delete-zero-trust-list` — DELETE `/accounts/{account_id}/gateway/lists/{list_id}`
- `zero-trust-lists-patch-zero-trust-list` — PATCH `/accounts/{account_id}/gateway/lists/{list_id}`
- `zero-trust-lists-update-zero-trust-list` — PUT `/accounts/{account_id}/gateway/lists/{list_id}`

**Account Load Balancer Monitor Groups** (4)
- `account-load-balancer-monitor-groups-create-monitor-group` — POST `/accounts/{account_id}/load_balancers/monitor_groups`
- `account-load-balancer-monitor-groups-delete-monitor-group` — DELETE `/accounts/{account_id}/load_balancers/monitor_groups/{monitor_group_id}`
- `account-load-balancer-monitor-groups-patch-monitor-group` — PATCH `/accounts/{account_id}/load_balancers/monitor_groups/{monitor_group_id}`
- `account-load-balancer-monitor-groups-update-monitor-group` — PUT `/accounts/{account_id}/load_balancers/monitor_groups/{monitor_group_id}`

**Credential Sets** (4)
- `create-credential-set` — POST `/accounts/{account_id}/vuln_scanner/credential_sets`
- `delete-credential-set` — DELETE `/accounts/{account_id}/vuln_scanner/credential_sets/{credential_set_id}`
- `edit-credential-set` — PATCH `/accounts/{account_id}/vuln_scanner/credential_sets/{credential_set_id}`
- `update-credential-set` — PUT `/accounts/{account_id}/vuln_scanner/credential_sets/{credential_set_id}`

**Credentials** (4)
- `create-credential` — POST `/accounts/{account_id}/vuln_scanner/credential_sets/{credential_set_id}/credentials`
- `delete-credential` — DELETE `/accounts/{account_id}/vuln_scanner/credential_sets/{credential_set_id}/credentials/{credential_id}`
- `edit-credential` — PATCH `/accounts/{account_id}/vuln_scanner/credential_sets/{credential_set_id}/credentials/{credential_id}`
- `update-credential` — PUT `/accounts/{account_id}/vuln_scanner/credential_sets/{credential_set_id}/credentials/{credential_id}`

**Email Routing suppressions** (4)
- `delete_publicDeleteSuppressionRouting` — DELETE `/accounts/{account_id}/email/routing/suppression/{suppression_id}`
- `delete_publicDeleteSuppressionZoneRouting` — DELETE `/zones/{zone_id}/email/routing/suppression/{suppression_id}`
- `post_publicNewSuppressionRouting` — POST `/accounts/{account_id}/email/routing/suppression`
- `post_publicNewSuppressionZoneRouting` — POST `/zones/{zone_id}/email/routing/suppression`

**Origin TLS** (4)
- `ssl-detector-auto-origin-tls-kex-patch-enrollment` — PATCH `/zones/{zone_id}/settings/auto_origin_tls_kex`
- `zone-cache-settings-change-origin-tls-compliance-modes-setting` — PATCH `/zones/{zone_id}/settings/origin_tls_compliance_modes`
- `zone-cache-settings-delete-origin-tls-compliance-modes-setting` — DELETE `/zones/{zone_id}/settings/origin_tls_compliance_modes`
- `zone-cache-settings-replace-origin-tls-compliance-modes-setting` — PUT `/zones/{zone_id}/settings/origin_tls_compliance_modes`

**Registrar Registration** (4)
- `registrar-domain-registration-create` — POST `/accounts/{account_id}/registrar/registrations`
- `registrar-domain-registration-update` — PATCH `/accounts/{account_id}/registrar/registrations/{domain_name}`
- `sandbox-registrar-domain-registration-create` — POST `/accounts/{account_id}/registrar-sandbox/registrations`
- `sandbox-registrar-domain-registration-update` — PATCH `/accounts/{account_id}/registrar-sandbox/registrations/{domain_name}`

**Resource Tagging** (4)
- `tags-delete` — DELETE `/accounts/{account_id}/tags`
- `tags-set` — PUT `/accounts/{account_id}/tags`
- `tags-zone-delete` — DELETE `/zones/{zone_id}/tags`
- `tags-zone-set` — PUT `/zones/{zone_id}/tags`

**Security Center Insights** (4)
- `archive-security-center-insight` — PUT `/accounts/{account_id}/security-center/insights/{issue_id}/dismiss`
- `archive-security-center-insight-deprecated` — PUT `/accounts/{account_id}/intel/attack-surface-report/{issue_id}/dismiss`
- `update-security-center-insight-classification` — PATCH `/accounts/{account_id}/security-center/insights/{issue_id}/classification`
- `update-zone-security-center-insight-classification` — PATCH `/zones/{zone_id}/security-center/insights/{issue_id}/classification`

**Stream Live Inputs** (4)
- `stream-live-inputs-create-a-new-output,-connected-to-a-live-input` — POST `/accounts/{account_id}/stream/live_inputs/{live_input_identifier}/outputs`
- `stream-live-inputs-disable-a-live-input` — POST `/accounts/{account_id}/stream/live_inputs/{live_input_identifier}/disable`
- `stream-live-inputs-enable-a-live-input` — POST `/accounts/{account_id}/stream/live_inputs/{live_input_identifier}/enable`
- `stream-live-inputs-rotate-keys-for-a-live-input` — POST `/accounts/{account_id}/stream/live_inputs/{live_input_identifier}/rotate_keys`

**Target Environments** (4)
- `create-target-environment` — POST `/accounts/{account_id}/vuln_scanner/target_environments`
- `delete-target-environment` — DELETE `/accounts/{account_id}/vuln_scanner/target_environments/{target_environment_id}`
- `edit-target-environment` — PATCH `/accounts/{account_id}/vuln_scanner/target_environments/{target_environment_id}`
- `update-target-environment` — PUT `/accounts/{account_id}/vuln_scanner/target_environments/{target_environment_id}`

**Zero Trust certificates** (4)
- `zero-trust-certificates-activate-zero-trust-certificate` — POST `/accounts/{account_id}/gateway/certificates/{certificate_id}/activate`
- `zero-trust-certificates-create-zero-trust-certificate` — POST `/accounts/{account_id}/gateway/certificates`
- `zero-trust-certificates-deactivate-zero-trust-certificate` — POST `/accounts/{account_id}/gateway/certificates/{certificate_id}/deactivate`
- `zero-trust-certificates-delete-zero-trust-certificate` — DELETE `/accounts/{account_id}/gateway/certificates/{certificate_id}`

**workers_pipelines_other** (4)
- `deleteV4AccountsByAccount_idPipelinesV1PipelinesByPipeline_id` — DELETE `/accounts/{account_id}/pipelines/v1/pipelines/{pipeline_id}`
- `deleteV4AccountsByAccount_idPipelinesV1SinksBySink_id` — DELETE `/accounts/{account_id}/pipelines/v1/sinks/{sink_id}`
- `deleteV4AccountsByAccount_idPipelinesV1StreamsByStream_id` — DELETE `/accounts/{account_id}/pipelines/v1/streams/{stream_id}`
- `patchV4AccountsByAccount_idPipelinesV1StreamsByStream_id` — PATCH `/accounts/{account_id}/pipelines/v1/streams/{stream_id}`

**Access tags** (3)
- `access-tags-create-tag` — POST `/accounts/{account_id}/access/tags`
- `access-tags-delete-a-tag` — DELETE `/accounts/{account_id}/access/tags/{tag_name}`
- `access-tags-update-a-tag` — PUT `/accounts/{account_id}/access/tags/{tag_name}`

**Connectivity Services** (3)
- `connectivity-services-delete` — DELETE `/accounts/{account_id}/connectivity/directory/services/{service_id}`
- `connectivity-services-post` — POST `/accounts/{account_id}/connectivity/directory/services`
- `connectivity-services-put` — PUT `/accounts/{account_id}/connectivity/directory/services/{service_id}`

**D1** (3)
- `d1-export-database` — POST `/accounts/{account_id}/d1/database/{database_id}/export`
- `d1-import-database` — POST `/accounts/{account_id}/d1/database/{database_id}/import`
- `d1-time-travel-restore` — POST `/accounts/{account_id}/d1/database/{database_id}/time_travel/restore`

**Deployment Groups** (3)
- `create-deployment-group` — POST `/accounts/{account_id}/devices/deployment-groups`
- `delete-deployment-group` — DELETE `/accounts/{account_id}/devices/deployment-groups/{group_id}`
- `update-deployment-group` — PATCH `/accounts/{account_id}/devices/deployment-groups/{group_id}`

**Magic BGP Filter Profiles** (3)
- `magic-bgp-create-filter-profile` — POST `/accounts/{account_id}/magic/bgp/filter_profiles`
- `magic-bgp-delete-filter-profile` — DELETE `/accounts/{account_id}/magic/bgp/filter_profiles/{profile_id}`
- `magic-bgp-update-filter-profile` — PUT `/accounts/{account_id}/magic/bgp/filter_profiles/{profile_id}`

**Magic Redundancy Groups** (3)
- `magic-redundancy-groups-create-redundancy-group` — POST `/accounts/{account_id}/magic/redundancy_groups`
- `magic-redundancy-groups-delete-redundancy-group` — DELETE `/accounts/{account_id}/magic/redundancy_groups/{redundancy_group_id}`
- `magic-redundancy-groups-update-redundancy-group` — PUT `/accounts/{account_id}/magic/redundancy_groups/{redundancy_group_id}`

**OrganizationMembers** (3)
- `Members_batchCreate` — POST `/organizations/{organization_id}/members:batchCreate`
- `Members_create` — POST `/organizations/{organization_id}/members`
- `Members_delete` — DELETE `/organizations/{organization_id}/members/{member_id}`

**Organizations** (3)
- `Organizations_delete` — DELETE `/organizations/{organization_id}`
- `Organizations_modify` — PUT `/organizations/{organization_id}`
- `Organizations_modifyProfile` — PUT `/organizations/{organization_id}/profile`

**Pages Assets** (3)
- `pages-assets-check-missing` — POST `/pages/assets/check-missing`
- `pages-assets-upload` — POST `/pages/assets/upload`
- `pages-assets-upsert-hashes` — POST `/pages/assets/upsert-hashes`

**Resource Sharing** (3)
- `share-recipients-update` — PUT `/accounts/{account_id}/shares/{share_id}/recipients`
- `share-resource-update` — PUT `/accounts/{account_id}/shares/{share_id}/resources/{share_resource_id}`
- `share-update` — PUT `/accounts/{account_id}/shares/{share_id}`

**Web Analytics** (3)
- `web-analytics-create-rule` — POST `/accounts/{account_id}/rum/v2/{ruleset_id}/rule`
- `web-analytics-delete-rule` — DELETE `/accounts/{account_id}/rum/v2/{ruleset_id}/rule/{rule_id}`
- `web-analytics-update-rule` — PUT `/accounts/{account_id}/rum/v2/{ruleset_id}/rule/{rule_id}`

**Zero Trust Gateway proxy endpoints** (3)
- `zero-trust-gateway-proxy-endpoints-create-proxy-endpoint` — POST `/accounts/{account_id}/gateway/proxy_endpoints`
- `zero-trust-gateway-proxy-endpoints-delete-proxy-endpoint` — DELETE `/accounts/{account_id}/gateway/proxy_endpoints/{proxy_endpoint_id}`
- `zero-trust-gateway-proxy-endpoints-update-proxy-endpoint` — PATCH `/accounts/{account_id}/gateway/proxy_endpoints/{proxy_endpoint_id}`

**Zero Trust accounts** (3)
- `zero-trust-accounts-patch-zero-trust-account-configuration` — PATCH `/accounts/{account_id}/gateway/configuration`
- `zero-trust-accounts-update-logging-settings-for-the-zero-trust-account` — PUT `/accounts/{account_id}/gateway/logging`
- `zero-trust-accounts-update-zero-trust-account-configuration.` — PUT `/accounts/{account_id}/gateway/configuration`

**AI Security for Apps** (2)
- `ai-security-custom-topics-put` — PUT `/zones/{zone_id}/ai-security/custom-topics`
- `ai-security-settings-put` — PUT `/zones/{zone_id}/ai-security/settings`

**Access IdP federation grants** (2)
- `access-idp-federation-grants-create` — POST `/accounts/{account_id}/access/idp_federation_grants`
- `access-idp-federation-grants-delete` — DELETE `/accounts/{account_id}/access/idp_federation_grants/{grant_id}`

**Accounts** (2)
- `Accounts_batchMoveAccounts` — POST `/accounts/move`
- `account-creation` — POST `/accounts`

**Cloudflare Images Keys** (2)
- `cloudflare-images-keys-add-signing-key` — PUT `/accounts/{account_id}/images/v1/keys/{signing_key_name}`
- `cloudflare-images-keys-delete-signing-key` — DELETE `/accounts/{account_id}/images/v1/keys/{signing_key_name}`

**Domain Discovery** (2)
- `registrar-domain-discovery-check` — POST `/accounts/{account_id}/registrar/domain-check`
- `sandbox-registrar-domain-discovery-check` — POST `/accounts/{account_id}/registrar-sandbox/domain-check`

**Endpoint Health Checks** (2)
- `diagnostics-endpoint-healthcheck-delete` — DELETE `/accounts/{account_id}/diagnostics/endpoint-healthchecks/{id}`
- `diagnostics-endpoint-healthcheck-update` — PUT `/accounts/{account_id}/diagnostics/endpoint-healthchecks/{id}`

**Exemptions** (2)
- `cloudforce-one-add-account-exemptions` — POST `/accounts/{account_id}/cloudforce-one/exemptions`
- `cloudforce-one-remove-account-exemptions` — DELETE `/accounts/{account_id}/cloudforce-one/exemptions`

**IP Address Management Address Maps** (2)
- `ip-address-management-address-maps-add-a-zone-membership-to-an-address-map` — PUT `/accounts/{account_id}/addressing/address_maps/{address_map_id}/zones/{zone_id}`
- `ip-address-management-address-maps-add-an-account-membership-to-an-address-map` — PUT `/accounts/{account_id}/addressing/address_maps/{address_map_id}/accounts/{account_id}`

**IP Address Management BGP Prefixes** (2)
- `ip-address-management-prefixes-create-bgp-prefix` — POST `/accounts/{account_id}/addressing/prefixes/{prefix_id}/bgp/prefixes`
- `ip-address-management-prefixes-delete-bgp-prefix` — DELETE `/accounts/{account_id}/addressing/prefixes/{prefix_id}/bgp/prefixes/{bgp_prefix_id}`

**Origin CA** (2)
- `origin-ca-create-certificate` — POST `/certificates`
- `origin-ca-revoke-certificate` — DELETE `/certificates/{certificate_id}`

**Scans** (2)
- `create-scan` — POST `/accounts/{account_id}/vuln_scanner/scans`
- `delete-scan` — DELETE `/accounts/{account_id}/vuln_scanner/scans/{scan_id}`

**Stream MP4 Downloads** (2)
- `stream-downloads-create-type-specific-downloads` — POST `/accounts/{account_id}/stream/{identifier}/downloads/{download_type}`
- `stream-m-p-4-downloads-create-downloads` — POST `/accounts/{account_id}/stream/{identifier}/downloads`

**Stream Videos** (2)
- `stream-videos-create-signed-url-tokens-for-videos` — POST `/accounts/{account_id}/stream/{identifier}/token`
- `stream-videos-update-video-details` — POST `/accounts/{account_id}/stream/{identifier}`

**Tenant-Level Custom Nameservers** (2)
- `tenant-level-custom-nameservers-add-tenant-custom-nameserver` — POST `/tenants/{tenant_tag}/custom_ns`
- `tenant-level-custom-nameservers-delete-tenant-custom-nameserver` — DELETE `/tenants/{tenant_tag}/custom_ns/{custom_ns_id}`

**Versions** (2)
- `deleteWorkerVersion` — DELETE `/accounts/{account_id}/workers/workers/{worker_id}/versions/{version_id}`
- `patchLatestWorkerVersion` — PATCH `/accounts/{account_id}/workers/workers/{worker_id}/versions/latest`

**Waiting Room** (2)
- `waiting-room-create-event` — POST `/zones/{zone_id}/waiting_rooms/{waiting_room_id}/events`
- `waiting-room-create-waiting-room-rule` — POST `/zones/{zone_id}/waiting_rooms/{waiting_room_id}/rules`

**Worker Script** (2)
- `worker-assets-upload` — POST `/accounts/{account_id}/workers/assets/upload`
- `worker-patch-script-secrets-bulk` — PATCH `/accounts/{account_id}/workers/scripts/{script_name}/secrets-bulk`

**Workers for Platforms** (2)
- `namespace-worker-patch-script-secrets-bulk` — PATCH `/accounts/{account_id}/workers/dispatch/namespaces/{dispatch_namespace}/scripts/{script_name}/secrets-bulk`
- `namespace-worker-script-update-create-assets-upload-session` — POST `/accounts/{account_id}/workers/dispatch/namespaces/{dispatch_namespace}/scripts/{script_name}/assets-upload-session`

**Zero Trust SSH Settings** (2)
- `zero-trust-rotate-ssh-account-seed` — POST `/accounts/{account_id}/gateway/audit_ssh_settings/rotate_seed`
- `zero-trust-update-audit-ssh-settings` — PUT `/accounts/{account_id}/gateway/audit_ssh_settings`

**Access Bookmark applications (Deprecated)** (1)
- `access-bookmark-applications-(-deprecated)-create-a-bookmark-application` — POST `/accounts/{account_id}/access/bookmarks/{bookmark_id}`

**Access SAML encryption certificates** (1)
- `access-saml-certificates-rotate-certificate` — POST `/accounts/{account_id}/access/saml_certificates/{saml_cert_set_id}/rotate`

**Access applications** (1)
- `access-applications-patch-update-access-application-settings` — PATCH `/accounts/{account_id}/access/apps/{app_id}/settings`

**Access identity providers** (1)
- `access-identity-providers-create-saml-certificate-for-identity-provider` — POST `/accounts/{account_id}/access/identity_providers/{identity_provider_id}/saml_certificate`

**Access service tokens** (1)
- `access-service-tokens-rotate-a-service-token` — POST `/accounts/{account_id}/access/service_tokens/{service_token_id}/rotate`

**Account Load Balancer Monitors** (1)
- `account-load-balancer-monitors-preview-monitor` — POST `/accounts/{account_id}/load_balancers/monitors/{monitor_id}/preview`

**Account Load Balancer Pools** (1)
- `account-load-balancer-pools-preview-pool` — POST `/accounts/{account_id}/load_balancers/pools/{pool_id}/preview`

**Account-Level Custom Nameservers** (1)
- `account-level-custom-nameservers-delete-account-custom-nameserver` — DELETE `/accounts/{account_id}/custom_ns/{custom_ns_id}`

**Cloud Integrations** (1)
- `providers-discover` — POST `/accounts/{account_id}/magic/cloud/providers/{provider_id}/discover`

**Deploy Hooks** (1)
- `triggerDeployHook` — POST `/workers/builds/deploy_hooks/{deploy_hook_uuid}`

**Email Auth** (1)
- `configure_dmarc_reports` — PATCH `/zones/{zone_id}/email/auth/dmarc-reports`

**Email Security** (1)
- `email_security_delete_bulk_job` — DELETE `/accounts/{account_id}/email-security/investigate/bulk/{job_id}`

**Email Security Settings** (1)
- `email_security_replace_domain` — PUT `/accounts/{account_id}/email-security/settings/domains/{domain_id}`

**Image Registries** (1)
- `generateImageRegistryCredentials` — POST `/accounts/{account_id}/containers/registries/{domain}/credentials`

**Load Balancer Monitors** (1)
- `load-balancer-monitors-preview-monitor` — POST `/user/load_balancers/monitors/{monitor_id}/preview`

**Load Balancer Pools** (1)
- `load-balancer-pools-preview-pool` — POST `/user/load_balancers/pools/{pool_id}/preview`

**Magic Account Apps** (1)
- `magic-account-apps-patch-app` — PATCH `/accounts/{account_id}/magic/apps/{account_app_id}`

**Magic BGP Settings** (1)
- `magic-bgp-update-settings` — PUT `/accounts/{account_id}/magic/bgp/settings`

**Magic CF1 Site Ramps** (1)
- `magic-cf1-sites-create-cf1-site-ramps` — POST `/accounts/{account_id}/magic/cf1_sites/{cf1_site_id}/ramps`

**Magic Connectors** (1)
- `mconn-connector-interrupts-create` — POST `/accounts/{account_id}/magic/connectors/{connector_id}/interrupts`

**Magic Site App Configs** (1)
- `magic-site-app-configs-patch-app-config` — PATCH `/accounts/{account_id}/magic/sites/{site_id}/app_configs/{app_config_id}`

**Magic Site NetFlow Config** (1)
- `magic-site-netflow-config-create-netflow-config` — POST `/accounts/{account_id}/magic/sites/{site_id}/netflow_config`

**Miscategorization** (1)
- `miscategorization-create-miscategorization` — POST `/accounts/{account_id}/intel/miscategorization`

**Notification policies** (1)
- `notification-policies-unsubscribe-email-from-notification-policy` — POST `/accounts/{account_id}/alerting/v3/policies/{policy_id}/email/unsubscribe`

**Precursor** (1)
- `precursor-for-a-zone-update-config` — PUT `/zones/{zone_id}/precursor`

**Resources** (1)
- `resources-catalog-policy-preview` — POST `/accounts/{account_id}/magic/cloud/resources/policy-preview`

**Security Center Scans** (1)
- `start-security-center-account-scan` — POST `/accounts/{account_id}/security-center/insights/scans`

**Stream Audio Tracks** (1)
- `add-audio-track` — POST `/accounts/{account_id}/stream/{identifier}/audio/copy`

**Stream Subtitles/Captions** (1)
- `stream-subtitles/-captions-generate-caption-or-subtitle-for-language` — POST `/accounts/{account_id}/stream/{identifier}/captions/{language}/generate`

**Tiered Caching** (1)
- `tiered-caching-patch-tiered-caching-setting` — PATCH `/zones/{zone_id}/argo/tiered_caching`

**User's Organizations** (1)
- `user'-s-organizations-leave-organization` — DELETE `/user/organizations/{organization_id}`

**Web3 Hostname** (1)
- `web3-hostname-create-ipfs-universal-path-gateway-content-list-entry` — POST `/zones/{zone_id}/web3/hostnames/{identifier}/ipfs_universal_path/content_list/entries`

**Worker Environment** (1)
- `worker-script-environment-patch-settings` — PATCH `/accounts/{account_id}/workers/services/{service_name}/environments/{environment_name}/settings`

**Workers** (1)
- `editWorker` — PATCH `/accounts/{account_id}/workers/workers/{worker_id}`

**Zero Trust applications review status** (1)
- `zero-trust-applications-review-status-update` — PUT `/accounts/{account_id}/gateway/apps/review_status`

**Zone-Level Access applications** (1)
- `zone-level-access-applications-patch-update-access-application-settings` — PATCH `/zones/{zone_id}/access/apps/{app_id}/settings`

**brand_protection** (1)
- `?` — POST `/internal/submit`

**tseng-abuse-complaint-processor_other** (1)
- `SubmitAbuseReport` — POST `/accounts/{account_id}/abuse-reports/{report_param}`

</details>

---

## Gap 2 — no machine-readable per-operation cost signal

The schema has **no operation-level pricing/cost extension** anywhere. The only
cost-adjacent metadata is `x-cfPlanAvailability` (652 mutating ops),
which states *which plans* may call an operation — not the **incremental cost**
of invoking it. As a result cfctl cannot bound the cost of a paid mutation, so
it blocks **1336 mutating capabilities** as cost-unknown/unbounded
rather than risk a governed approval that hides a real charge.

**Ask:** add a machine-readable per-operation cost signal (e.g.
`x-cf-pricing` with a model such as `free` | `flat` | `usage` and, where
known, a currency + unit) to paid operations — starting with the highest-volume
families below.

<details><summary>Cost-blocked capabilities by product (1336 total)</summary>

- Workers AI Text Generation: 59
- dos-flowtrackd-api_other: 23
- Event: 21
- Workers for Platforms: 15
- brapi: 14
- brand_protection: 13
- Brand Protection: 13
- R2 Bucket: 13
- API Shield Labels: 12
- Devices: 12
- Secrets Store: 12
- Waiting Room: 12
- Workers AI Text Embeddings: 12
- Queue: 11
- Workers AI Text To Image: 11
- Request for Information (RFI): 10
- Worker Script: 10
- workers_pipelines_other: 9
- On-ramps: 9
- AI Search Instances: 8
- Email Security Settings: 8
- IP Address Management Address Maps: 8
- Stream Live Inputs: 8
- Vectorize: 8
- Logpush jobs for an account: 7
- Email Security: 7
- Firewall rules: 7
- Health Checks: 7
- Origin Cloud Regions: 7
- Logpush jobs for a zone: 7
- R2 Super Slurper: 7
- Vectorize Beta (Deprecated): 7
- Zero Trust accounts: 7
- Zone Settings: 7
- findings: 6
- Meetings: 6
- API Shield Schema Validation 2.0: 6
- Cloudflare Images Sourcing Kit: 6
- Applications: 6
- Account Rulesets: 6
- Zone Rulesets: 6
- Custom Indicator Feeds: 6
- Collections: 6
- DLP Datasets: 6
- DLP Profiles: 6
- Email Routing settings: 6
- Magic IPsec tunnels: 6
- Magic Network Monitoring Rules: 6
- Pages Deployment: 6
- Resource Sharing: 6
- Web Analytics: 6
- Workflows: 6
- Workers AI Automatic Speech Recognition: 6
- Workers KV Namespace: 6
- Active session: 5
- webhooks: 5
- Access applications: 5
- Security Center Insights: 5
- Artifacts: 5
- Catalog Sync: 5
- Cloudflare Tunnel: 5
- Triggers: 5
- Workers: 5
- D1: 5
- domain_search: 5
- DNS Records for a Zone: 5
- Infrastructure Access Targets: 5
- Lists: 5
- Cloud Integrations: 5
- Secondary DNS (Primary Zone): 5
- Token Validation Token Rules: 5
- Tunnel Routing: 5
- Web3 Hostname: 5
- Zero Trust Gateway rules: 5
- Zone-Level Access applications: 5
- Zone Environments: 5
- Accounts: 4
- exports: 4
- Log Explorer Datasets: 4
- AI Search Instances Jobs: 4
- AI Gateway: 4
- AI Gateway Dynamic Routes: 4
- Cloudflare Images: 4
- Rules: 4
- Integrations: 4
- Custom Hostname for a Zone: 4
- Groups: 4
- DLP Email: 4
- DLP Entries: 4
- DLP Settings: 4
- Email Sending subdomains: 4
- Filters: 4
- IP Address Management Prefixes: 4
- Magic Account Apps: 4
- Magic GRE tunnels: 4
- Magic PCAP collection: 4
- Magic Static Routes: 4
- Magic Connectors: 4
- MoQ Relays: 4
- Notification policies: 4
- Pages Project: 4
- ppc_config: 4
- Zaraz: 4
- Email Sending suppressions: 4
- Registrar Registration: 4
- Schema Validation Settings: 4
- Sinkhole Config: 4
- Observatory: 4
- Origin TLS: 4
- Stream Videos: 4
- Resource Tagging: 4
- Content Scanning: 4
- Workers AI Text To Speech: 4
- Zero Trust lists: 4
- Zero Trust organization: 4
- Zone Cache Settings: 4
- OrganizationMembers: 3
- Organizations: 3
- Access mTLS authentication: 3
- Account Load Balancer Monitor Groups: 3
- Account Load Balancers: 3
- Stream Audio Tracks: 3
- Webhooks: 3
- AI Search Namespaces: 3
- AI Search Instances Items: 3
- AI Gateway Provider Configs: 3
- API Shield Endpoint Management: 3
- ART Analytics: 3
- SSO: 3
- API Shield Client Certificates for a Zone: 3
- Priority Intelligence Requirements (PIR): 3
- Credentials: 3
- Credential Sets: 3
- Hyperdrive: 3
- Scans: 3
- Target Environments: 3
- Deploy Hooks: 3
- Apps: 3
- Live streams: 3
- Custom SSL for a Zone: 3
- Data Security: 3
- Zone Snippets: 3
- Permissions: 3
- TagCategory: 3
- Tag: 3
- Destinations: 3
- DLP Document Fingerprints: 3
- DLP Integration Entries: 3
- DLP Sensitivity Groups: 3
- DNS Firewall: 3
- IP Access rules for a zone: 3
- Load Balancers: 3
- Magic Network Monitoring Configuration: 3
- Magic Site ACLs: 3
- Magic Site App Configs: 3
- Magic Site LANs: 3
- Magic Site NetFlow Config: 3
- Magic Site WANs: 3
- Magic Sites: 3
- MCP Portal Servers: 3
- Page Rules: 3
- Page Shield: 3
- Pages Assets: 3
- Presets: 3
- Category: 3
- Dataset: 3
- Indicator: 3
- Recordings: 3
- logo_match: 3
- Zone: 3
- SCIM Users: 3
- Secondary DNS (Secondary Zone): 3
- Stream MP4 Downloads: 3
- Token Validation Token Configuration: 3
- Leaked Credential Checks: 3
- Workers AI Translation: 3
- Workers AI Text Classification: 3
- Workers AI: 3
- Zero Trust certificates: 3
- Zero Trust Subnets: 3
- Zero Trust users: 3
- Zone-Level Access mTLS authentication: 3
- Zone-Level Zero Trust organization: 3
- Zone Holds: 3
- tseng-abuse-complaint-processor_other: 2
- Access Bookmark applications (Deprecated): 2
- Access custom pages: 2
- Access key configuration: 2
- Access tags: 2
- Account-Level Custom Nameservers: 2
- Account Load Balancer Pools: 2
- Account Members: 2
- Account Resource Groups: 2
- Account Subscriptions: 2
- Account User Groups: 2
- Account User Group Members: 2
- Log Explorer Queries: 2
- AI Search Tokens: 2
- AI Search Account Search: 2
- AI Security for Apps: 2
- AI Gateway Account Providers: 2
- AI Gateway Account Provider Costs: 2
- AI Gateway Datasets: 2
- AI Gateway Gateways: 2
- AI Gateway Logs: 2
- API Shield API Discovery: 2
- AutoRAG RAG Search: 2
- Calls Apps: 2
- Calls TURN Keys: 2
- Certificate Packs: 2
- Cloudflare Images Keys: 2
- Cloudflare Images Variants: 2
- Exemptions: 2
- Connectivity Services: 2
- Deployment Groups: 2
- DEX Rules: 2
- IP Profiles: 2
- Image Registries: 2
- Versions: 2
- CNIs: 2
- Custom assets for a zone: 2
- Custom assets for an account: 2
- Custom pages for a zone: 2
- Custom pages for an account: 2
- Physical Devices: 2
- security.txt: 2
- Environment Variables: 2
- Managed Transforms: 2
- Repository Connections: 2
- URL Normalization: 2
- DEX Synthetic Application Monitoring: 2
- Device Managed Networks: 2
- Device Posture Integrations: 2
- Device posture rules: 2
- Endpoint Health Checks: 2
- R2 Catalog Management: 2
- DLP Custom Prompt Topics: 2
- DLP Data Classes: 2
- DLP Data Tag Categories: 2
- DLP Data Tags: 2
- DLP Predefined Entries: 2
- Zero Trust Risk Scoring: 2
- DLP Sensitivity Levels: 2
- Zero Trust Risk Scoring Integrations: 2
- DLS Regional Services: 2
- DNS Internal Views for an Account: 2
- Email Sending: 2
- Flags: 2
- IP Access rules for a user: 2
- IP Access rules for an account: 2
- IP Address Management BGP Prefixes: 2
- Keyless SSL for a Zone: 2
- Load Balancer Pools: 2
- Magic BGP Filter Profiles: 2
- Magic CF1 Sites: 2
- Magic Interconnects: 2
- Magic Redundancy Groups: 2
- MCP Portal: 2
- Notification destinations with PagerDuty: 2
- Notification Silences: 2
- Notification webhooks: 2
- OAuth Clients: 2
- Pages Domains: 2
- ppc_stripe: 2
- Per-hostname Authenticated Origin Pull: 2
- Collections - Items: 2
- Email Routing suppressions: 2
- Prefix Bindings: 2
- Saved Queries: 2
- R2 Object: 2
- Rate limits for a zone: 2
- Domain Discovery: 2
- Registrations: 2
- Schema Validation: 2
- SCIM Groups: 2
- Secondary DNS (ACL): 2
- Secondary DNS (Peer): 2
- Secondary DNS (TSIG): 2
- Smart Tiered Cache: 2
- Spectrum Applications: 2
- Security Center Scans: 2
- Stream Subtitles/Captions: 2
- Live Tail: 2
- Tenant-Level Custom Nameservers: 2
- Tunnel Virtual Network: 2
- URL Scanner: 2
- User Agent Blocking rules: 2
- WAF overrides: 2
- Worker Environment: 2
- Worker Routes: 2
- Worker Tail Logs: 2
- Workers AI Finetune: 2
- Workers AI Summarization: 2
- Workers AI Image Classification: 2
- Zero Trust Gateway locations: 2
- Zero Trust Gateway PAC files: 2
- Zero Trust Gateway proxy endpoints: 2
- Zero Trust Hostname Route: 2
- Zero Trust SSH Settings: 2
- Zone-Level Authenticated Origin Pulls: 2
- Zone Lockdown: 2
- Zone Subscription: 2
- remediations: 1
- Gateway CA: 1
- Access identity providers: 1
- Access IdP federation grants: 1
- Access application-scoped policies: 1
- Access policy tester: 1
- Access SAML encryption certificates: 1
- Access service tokens: 1
- Access short-lived certificate CAs: 1
- Account Owned API Tokens: 1
- Account-Level Custom Nameservers Usage for a Zone: 1
- Account Load Balancer Monitors: 1
- Account Request Tracer: 1
- AI Gateway Evaluations: 1
- Analytics Engine: 1
- Analyze Certificate: 1
- API Shield WAF Expression Templates: 1
- API Shield Settings: 1
- Argo Smart Routing: 1
- AutoRAG RAG: 1
- Bot Settings: 1
- Feedback: 1
- Botnet Threat Feed: 1
- Builds: 1
- Email Auth: 1
- Build Tokens: 1
- Interconnects: 1
- CSAM Scanner Settings: 1
- CT Alerting: 1
- Custom CSRs for a Zone: 1
- Custom CSRs for an Account: 1
- Custom Hostname Fallback Origin for a Zone: 1
- Custom Origin Trust Store: 1
- Diagnostics: 1
- DNS Settings for a Zone: 1
- DNS Settings for an Account: 1
- DNSSEC: 1
- Email Routing destination addresses: 1
- Email Routing routing rules: 1
- Fraud Detection: 1
- IP Address Management Dynamic Advertisement: 1
- IP Address Management Prefix Delegation: 1
- IP Address Management Service Bindings: 1
- Load Balancer Monitors: 1
- mTLS Certificate Management: 1
- Magic BGP Settings: 1
- Magic CF1 Site Ramps: 1
- Miscategorization: 1
- Origin CA: 1
- Pages Build Cache: 1
- Per-Hostname TLS Settings: 1
- Logcontrol CMB config for an account: 1
- DEX Remote Commands: 1
- Sessions: 1
- Instant Logs jobs for a zone: 1
- Logs Received: 1
- BinDB: 1
- Datasets: 1
- Indicators: 1
- Precursor: 1
- Radar Datasets: 1
- Registrar Domains: 1
- Resources: 1
- Shared: 1
- Smart Shield Settings: 1
- Cache Reserve Clear: 1
- Automatic SSL/TLS: 1
- SSL Verification: 1
- Credential Management: 1
- Stream Signing Keys: 1
- Stream Video Clipping: 1
- Stream Watermark Profile: 1
- Stream Webhook: 1
- Keys: 1
- Query run: 1
- Values: 1
- Tiered Caching: 1
- Total TLS: 1
- Universal SSL Settings for a Zone: 1
- Maintenance Configuration: 1
- Table Maintenance Configuration: 1
- Settings: 1
- URL Scanner (Deprecated): 1
- User's Account Memberships: 1
- User's Invites: 1
- User API Tokens: 1
- User: 1
- User Subscription: 1
- WAF packages: 1
- WAF rule groups: 1
- WAF rules: 1
- Worker Account Settings: 1
- Worker Cron Trigger: 1
- Worker Deployments: 1
- Worker Subdomain: 1
- Worker Versions: 1
- Workers AI Object Detection: 1
- Domains: 1
- Zero Trust Connectivity Settings: 1
- Zero Trust applications review status: 1
- Zero Trust seats: 1
- Origin Post-Quantum: 1
- Zone Cloud Connector Rules PUT: 1
- Zone-Level Access short-lived certificate CAs: 1
- Google Tag Gateway: 1

</details>

---

## Reproduce

```sh
curl -sS -o openapi.json \
  https://raw.githubusercontent.com/cloudflare/api-schemas/main/openapi.json
# Gap 1: mutating ops missing all permission annotation
python3 - <<'EOF'
import json; s=json.load(open('openapi.json')); MUT={'post','put','patch','delete'}
miss=[ (o.get('operationId'),m,p) for p,ms in s['paths'].items() for m,o in ms.items()
       if m in MUT and isinstance(o,dict)
       and 'x-api-token-group' not in o and 'x-cfPermissionsRequired' not in o ]
print(len(miss))
EOF
```

_Snapshot taken against `cloudflare/api-schemas@main`; counts drift as the
schema evolves._