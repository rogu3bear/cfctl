use super::prelude::{PlanV1, Result, SecretStore};
use super::secret_io::plan_secret_body_ref;

pub(super) fn delete_plan_secret(plan: &PlanV1, secrets: &dyn SecretStore) -> Result<bool> {
    let Some(reference) = plan_secret_body_ref(plan).map(str::to_owned) else {
        return Ok(false);
    };
    secrets.delete(&reference)?;
    Ok(true)
}

pub(super) const ENTITLEMENT_UNRESOLVED_GAP: &str =
    "account entitlement has not been resolved for this plan-gated operation";
pub(super) const GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID: &str =
    "devices-resilience-set-global-warp-override";
pub(super) const GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID: &str =
    "devices-resilience-retrieve-global-warp-override";
pub(super) const GLOBAL_WARP_OVERRIDE_PATH: &str =
    "/accounts/{account_id}/devices/resilience/disconnect";
pub(super) const D1_READ_REPLICATION_READ_CAPABILITY_ID: &str = "d1-get-database";
pub(super) const D1_READ_REPLICATION_PATH: &str =
    "/accounts/{account_id}/d1/database/{database_id}";
pub(super) const D1_READ_REPLICATION_PRECONDITION: &str = "d1_read_replication_state";
pub(super) const D1_DATABASE_CREATE_CAPABILITY_ID: &str = "d1-create-database";
pub(super) const D1_DATABASE_DELETE_CAPABILITY_ID: &str = "d1-delete-database";
pub(super) const D1_EMPTY_DATABASE_PRECONDITION: &str = "d1_empty_database_state";
pub(super) const D1_EMPTY_DATABASE_COMPENSATION_STRATEGY: &str =
    "delete_created_empty_d1_database_by_returned_uuid_if_unchanged";
pub(super) const KV_NAMESPACE_CREATE_CAPABILITY_ID: &str =
    "workers-kv-namespace-create-a-namespace";
pub(super) const KV_NAMESPACE_DELETE_CAPABILITY_ID: &str =
    "workers-kv-namespace-remove-a-namespace";
pub(super) const KV_NAMESPACE_KEYS_READ_CAPABILITY_ID: &str =
    "workers-kv-namespace-list-a-namespace'-s-keys";
pub(super) const KV_EMPTY_NAMESPACE_PRECONDITION: &str = "kv_empty_namespace_state";
pub(super) const KV_EMPTY_NAMESPACE_COMPENSATION_STRATEGY: &str =
    "delete_created_empty_kv_namespace_by_returned_id_if_unchanged";
pub(super) const CLOUDFLARE_TUNNEL_CONFIGURATION_MUTATION_CAPABILITY_ID: &str =
    "cloudflare-tunnel-configuration-put-configuration";
pub(super) const CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID: &str =
    "cloudflare-tunnel-configuration-get-configuration";
pub(super) const CLOUDFLARE_TUNNEL_CONFIGURATION_PATH: &str =
    "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations";
pub(super) const CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION: &str =
    "cloudflare_tunnel_configuration_state";
pub(super) const WARP_CONNECTOR_CONFIGURATION_MUTATION_CAPABILITY_ID: &str =
    "cloudflare-tunnel-configuration-update-warp-connector-configuration";
pub(super) const WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID: &str =
    "cloudflare-tunnel-configuration-get-warp-connector-configuration";
pub(super) const WARP_CONNECTOR_CONFIGURATION_PATH: &str =
    "/accounts/{account_id}/warp_connector/{tunnel_id}/configurations";
pub(super) const WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION: &str =
    "warp_connector_configuration_state";
pub(super) const WEB_ANALYTICS_RUM_MUTATION_CAPABILITY_ID: &str = "web-analytics-toggle-rum";
pub(super) const WEB_ANALYTICS_RUM_READ_CAPABILITY_ID: &str = "web-analytics-get-rum-status";
pub(super) const WEB_ANALYTICS_RUM_PATH: &str = "/zones/{zone_id}/settings/rum";
pub(super) const WEB_ANALYTICS_RUM_STATE_PRECONDITION: &str = "web_analytics_rum_state";
pub(super) const DNS_RECORD_DETAIL_READ_CAPABILITY_ID: &str =
    cfctl_core::DNS_RECORD_DETAIL_READ_CAPABILITY_ID;
pub(super) const DNS_RECORD_DETAIL_PATH: &str = cfctl_core::DNS_RECORD_DETAIL_PATH;
pub(super) const DNS_RECORD_STATE_PRECONDITION: &str = "dns_record_state";
pub(super) const DNS_RECORD_RESTORE_CAPABILITY_ID: &str =
    "dns-records-for-a-zone-update-dns-record";
pub(super) const SAME_PATH_PRIOR_STATE_PRECONDITION: &str = "same_path_prior_state";
pub(super) const SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY: &str = "restore_same_path_prior_snapshot";
pub(super) const ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID: &str =
    "access-applications-update-self-hosted-login-methods";
pub(super) const ACCESS_APP_OWNED_WHOLE_HOST_CAPABILITY_ID: &str =
    "access-applications-update-owned-self-hosted-whole-host";
pub(super) const ACCESS_APP_LAUNCHER_LOGIN_METHODS_CAPABILITY_ID: &str =
    "access-applications-update-app-launcher-login-methods";
pub(super) const ACCESS_APP_LIST_CAPABILITY_ID: &str =
    "access-applications-list-access-applications";
pub(super) const ACCESS_APP_COLLECTION_PATH: &str = "/accounts/{account_id}/access/apps";
pub(super) const ACCESS_APP_READ_CAPABILITY_ID: &str =
    "access-applications-get-an-access-application";
pub(super) const ACCESS_APP_DETAIL_PATH: &str = "/accounts/{account_id}/access/apps/{app_id}";
pub(super) const ACCESS_APP_IMPLICIT_OPEN_ROLLBACK_WARNING: &str = "the prior implicit-open identity-provider state cannot be restored automatically; manual rollback requires a separately reviewed Cloudflare Access application change";
pub(super) const ACCESS_HUMAN_POLICY_UPDATE_CAPABILITY_ID: &str =
    "access-policies-update-human-access-controls";
pub(super) const ACCESS_OPERATOR_GROUP_POLICY_CREATE_CAPABILITY_ID: &str =
    "access-policies-create-operator-group-allow-policy";
pub(super) const ACCESS_OPERATOR_GROUP_POLICY_UPDATE_CAPABILITY_ID: &str =
    "access-policies-update-operator-group-allow-policy";
pub(super) const ACCESS_POLICY_LIST_CAPABILITY_ID: &str = "access-policies-list-access-policies";
pub(super) const ACCESS_POLICY_COLLECTION_PATH: &str =
    "/accounts/{account_id}/access/apps/{app_id}/policies";
pub(super) const ACCESS_POLICY_READ_CAPABILITY_ID: &str = "access-policies-get-an-access-policy";
pub(super) const ACCESS_POLICY_DETAIL_PATH: &str =
    "/accounts/{account_id}/access/apps/{app_id}/policies/{policy_id}";
pub(super) const ACCESS_OPERATOR_GROUP_POLICY_OWNERSHIP_PRECONDITION: &str =
    "access_operator_group_policy_ownership";
pub(super) const OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID: &str = "oauth-clients-get";
pub(super) const OAUTH_CLIENT_CREATE_CAPABILITY_ID: &str = "oauth-clients-create";
pub(super) const OAUTH_CLIENT_UPDATE_CAPABILITY_ID: &str = "oauth-clients-update";
pub(super) const OAUTH_CLIENT_COLLECTION_PATH: &str = "/accounts/{account_id}/oauth_clients";
pub(super) const OAUTH_CLIENT_DETAIL_PATH: &str =
    "/accounts/{account_id}/oauth_clients/{oauth_client_id}";
pub(super) const OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION: &str = "oauth_client_key_overlap";
pub(super) const OAUTH_CLIENT_UPDATE_STATE_PRECONDITION: &str = "oauth_client_update_state";
pub(super) const OAUTH_CLIENT_MUTABLE_FIELDS: [&str; 13] = [
    "allowed_cors_origins",
    "client_name",
    "client_uri",
    "grant_types",
    "logo_uri",
    "policy_uri",
    "post_logout_redirect_uris",
    "redirect_uris",
    "response_types",
    "scopes",
    "token_endpoint_auth_method",
    "tos_uri",
    "visibility",
];
pub(super) const ZONE_DETAILS_CAPABILITY_ID: &str = "zones-0-get";
pub(super) const ZONE_SUBSCRIPTION_CAPABILITY_ID: &str =
    "zone-subscription-zone-subscription-details";

pub(super) const ACCESS_APP_MUTABLE_FIELDS: [&str; 17] = [
    "allowed_idps",
    "app_launcher_visible",
    "auto_redirect_to_identity",
    "destinations",
    "domain",
    "eager_redirect_cookie_setting",
    "enable_binding_cookie",
    "http_only_cookie_attribute",
    "name",
    "options_preflight_bypass",
    "path_cookie_attribute",
    "policies",
    "same_site_cookie_attribute",
    "self_hosted_domains",
    "session_duration",
    "tags",
    "type",
];
pub(super) const ACCESS_APP_REQUIRED_FIELDS: [&str; 13] = [
    "allowed_idps",
    "app_launcher_visible",
    "auto_redirect_to_identity",
    "destinations",
    "domain",
    "enable_binding_cookie",
    "http_only_cookie_attribute",
    "name",
    "options_preflight_bypass",
    "policies",
    "self_hosted_domains",
    "session_duration",
    "type",
];
pub(super) const ACCESS_APP_READ_ONLY_FIELDS: [&str; 5] =
    ["aud", "created_at", "id", "uid", "updated_at"];

pub(super) const ACCESS_APP_LAUNCHER_MUTABLE_FIELDS: [&str; 14] = [
    "allowed_idps",
    "app_launcher_logo_url",
    "auto_redirect_to_identity",
    "bg_color",
    "custom_deny_url",
    "custom_non_identity_deny_url",
    "custom_pages",
    "footer_links",
    "header_bg_color",
    "landing_page_design",
    "policies",
    "session_duration",
    "skip_app_launcher_login_page",
    "type",
];
pub(super) const ACCESS_APP_LAUNCHER_REQUIRED_FIELDS: [&str; 7] = [
    "allowed_idps",
    "auto_redirect_to_identity",
    "landing_page_design",
    "policies",
    "session_duration",
    "skip_app_launcher_login_page",
    "type",
];
pub(super) const ACCESS_APP_LAUNCHER_READ_ONLY_FIELDS: [&str; 7] = [
    "aud",
    "created_at",
    "domain",
    "id",
    "name",
    "uid",
    "updated_at",
];

pub(super) const ACCESS_HUMAN_POLICY_MUTABLE_FIELDS: [&str; 8] = [
    "decision",
    "exclude",
    "include",
    "mfa_config",
    "name",
    "precedence",
    "require",
    "session_duration",
];
pub(super) const ACCESS_HUMAN_POLICY_REQUIRED_FIELDS: [&str; 6] = [
    "decision",
    "exclude",
    "include",
    "name",
    "precedence",
    "require",
];
pub(super) const ACCESS_HUMAN_POLICY_DESIRED_FIELDS: [&str; 3] =
    ["exclude", "include", "mfa_config"];
pub(super) const ACCESS_HUMAN_POLICY_READ_ONLY_FIELDS: [&str; 5] =
    ["created_at", "id", "reusable", "uid", "updated_at"];
