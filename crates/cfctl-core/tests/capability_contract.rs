//! Explicit field inventory owned by the universal capability contract.
//! Exact legacy capability identity is enforced by cfctl-catalog and its
//! `catalog_v2_classifies_generic_and_frozen_legacy_authority` test.
#![allow(clippy::expect_used)]

/// Every field permitted on `CapabilityV1`.
///
/// `CapabilityV1` is the single contract every catalog capability is expressed
/// as, so a field added here is carried by all of them, forever, whether or not
/// it applies. Widening it is a deliberate act: `verify` fails until this list
/// is edited in the same change, which makes the addition something a reviewer
/// sees rather than something that arrives quietly.
const CAPABILITY_V1_FIELDS: [&str; 56] = [
    "schema_version",
    "id",
    "title",
    "description",
    "authority_scope",
    "product",
    "source",
    "method",
    "path",
    "account_scope",
    "selectors",
    "aliases",
    "permissions",
    "mutating",
    "execution_supported",
    "risk",
    "effect",
    "maturity",
    "entitlement",
    "cost",
    "verification",
    "rollback",
    "created_resource",
    "created_collection_resource",
    "created_nested_resource",
    "deleted_resource",
    "deleted_nested_resource",
    "updated_resource",
    "same_path_read",
    "async_collection_mutation",
    "adapter_status",
    "blocked_reason",
    "request_schema",
    "response_contract",
    "analytics_query",
    "d1_schema_introspection",
    "mln_0142_post_import_schema",
    "mln_0143_data_invariants",
    "d1_full_export",
    "d1_restore_exact_bookmark",
    "workspace_d1_migration",
    "workspace_d1_policy_projection",
    "workspace_d1_reply_admission",
    "workspace_reply_subdomain_ingress",
    "workspace_d1_evidence",
    "r2_private_file_upload",
    "r2_private_object_digest",
    "email_sending_dns_repair",
    "email_routing_subdomain_dns",
    "d1_approved_mln_import",
    "d1_approved_mln_import_poll_resume",
    "r2_log_retrieval",
    "graphql",
    "workflow",
    "security_action",
    "event_batch",
];
/// Fields on `CapabilityV1` that name one application rather than a provider
/// capability.
///
/// `ANCHOR.md` reserves this repository for the cataloged path to live
/// Cloudflare truth and leaves an application's own deployment policy with the
/// application. These fields are that boundary already crossed, recorded here
/// so the debt is counted rather than assumed.
///
/// **This list may shrink. It must never grow.** Every entry removed is one
/// application contract that moved to the repository that owns it.
const CAPABILITY_V1_APPLICATION_FIELDS: [&str; 10] = [
    "mln_0142_post_import_schema",
    "mln_0143_data_invariants",
    "d1_approved_mln_import",
    "d1_approved_mln_import_poll_resume",
    "workspace_d1_migration",
    "workspace_d1_policy_projection",
    "workspace_d1_reply_admission",
    "workspace_reply_subdomain_ingress",
    "workspace_d1_evidence",
    "email_routing_subdomain_dns",
];
fn declared_fields(content: &str) -> Result<Vec<&str>, String> {
    let body = content
        .split_once("pub struct CapabilityV1 {")
        .and_then(|(_, rest)| rest.split_once("\n}"))
        .map(|(body, _)| body)
        .ok_or_else(|| "cfctl-core source does not declare CapabilityV1".to_owned())?;
    Ok(body
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub "))
        .filter_map(|rest| rest.split_once(':'))
        .map(|(name, _)| name.trim())
        .filter(|name| !name.is_empty())
        .collect())
}

fn check(content: &str) -> Result<(), String> {
    let declared = declared_fields(content)?;
    for field in &declared {
        if !CAPABILITY_V1_FIELDS.contains(field) {
            return Err(format!(
                "CapabilityV1 declares `{field}`, which is not in CAPABILITY_V1_FIELDS; review the universal contract and update its inventory in the same change"
            ));
        }
    }
    for field in CAPABILITY_V1_FIELDS {
        if !declared.contains(&field) {
            return Err(format!(
                "CAPABILITY_V1_FIELDS lists `{field}`, which CapabilityV1 no longer declares; remove it from both inventories if present"
            ));
        }
    }
    for field in CAPABILITY_V1_APPLICATION_FIELDS {
        if !declared.contains(&field) {
            return Err(format!(
                "CAPABILITY_V1_APPLICATION_FIELDS lists `{field}`, which CapabilityV1 no longer declares; remove the extracted application field from the inventory"
            ));
        }
    }
    Ok(())
}

const CORE_SOURCE: &str = include_str!("../src/lib.rs");

#[test]
fn current_contract_matches_the_inventory() {
    check(CORE_SOURCE).expect("current field inventory");
}

#[test]
fn added_field_requires_an_inventory_change() {
    let changed = CORE_SOURCE.replace(
        "pub struct CapabilityV1 {",
        "pub struct CapabilityV1 {\n    pub new_application_field: Option<String>,",
    );
    let error = check(&changed).expect_err("unlisted field");
    assert!(error.contains("new_application_field"));
}

#[test]
fn removed_field_requires_both_inventories_to_follow() {
    let field = CAPABILITY_V1_APPLICATION_FIELDS[0];
    let needle = format!("pub {field}:");
    let changed = CORE_SOURCE
        .lines()
        .filter(|line| !line.trim_start().starts_with(&needle))
        .collect::<Vec<_>>()
        .join("\n");
    let error = check(&changed).expect_err("stale inventory");
    assert!(error.contains(field));
}
