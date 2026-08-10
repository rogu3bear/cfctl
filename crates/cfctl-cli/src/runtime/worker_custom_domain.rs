use cfctl_auth::AuthCredential;
use cfctl_catalog::CatalogSnapshot;
use cfctl_cloudflare::{CallInput, CloudflareResponseV1, Executor};
use cfctl_core::{
    AdapterStatus, CapabilityV1, EvidenceClass, EvidenceV1, PlanV1, ResponseBodyModeV1, hash_value,
    redact_json,
};
use cfctl_storage::StateStore;
use serde_json::{Value, json};

use super::{API_BASE_URL, CliError, Result, capability_missing, http_client, validate_zone_id};

const ATTACH_CAPABILITY_ID: &str = "workers.domains.update";
const ATTACH_PATH: &str = "/accounts/{account_id}/workers/domains";
const ZONE_READ_CAPABILITY_ID: &str = "zones-0-get";
const ZONE_READ_PATH: &str = "/zones/{zone_id}";
const WORKER_READ_CAPABILITY_ID: &str = "worker-script-get-settings";
const WORKER_READ_PATH: &str = "/accounts/{account_id}/workers/scripts/{script_name}/settings";
const DOMAIN_LIST_CAPABILITY_ID: &str = "workers.domains.list";
const DOMAIN_LIST_PATH: &str = "/accounts/{account_id}/workers/domains";
const DNS_LIST_CAPABILITY_ID: &str = "dns-records-for-a-zone-list-dns-records";
const DNS_LIST_PATH: &str = "/zones/{zone_id}/dns_records";

pub(super) const WORKER_CUSTOM_DOMAIN_STATE_PRECONDITION: &str = "worker_custom_domain_state";

#[derive(Clone)]
struct Target {
    account_id: String,
    hostname: String,
    service: String,
    zone_id: String,
}

pub(super) fn should_bind_state(capability: &CapabilityV1) -> bool {
    capability.id == ATTACH_CAPABILITY_ID
        && capability.method == "PUT"
        && capability.path == ATTACH_PATH
        && capability.product == "Domains"
        && capability.account_scope == "account"
        && capability.mutating
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
}

pub(super) fn current_state_command() -> Vec<String> {
    [
        "cfctl",
        "call",
        ATTACH_CAPABILITY_ID,
        "--selector",
        "account_id=<account_id>",
        "--body-json",
        r#"{"hostname":"<hostname>","service":"<service>","zone_id":"<zone_id>"}"#,
        "--json",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn target(capability: &CapabilityV1, input: &CallInput, account_id: &str) -> Result<Target> {
    if !should_bind_state(capability) {
        return Err(CliError::Input(
            "Worker custom-domain attach drifted from its governed live-state contract".to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Worker custom-domain attach requires string selector `account_id`".to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(
            "Worker custom-domain account selector differs from the selected account; create a new plan"
                .to_owned(),
        ));
    }
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input(
                "Worker custom-domain attach requires an exact JSON object body".to_owned(),
            )
        })?;
    let string = |name: &str| {
        body.get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                CliError::Input(format!(
                    "Worker custom-domain attach requires non-empty string body field `{name}`"
                ))
            })
    };
    let zone_id = string("zone_id")?;
    validate_zone_id(&zone_id)?;
    Ok(Target {
        account_id: account_id.to_owned(),
        hostname: string("hostname")?,
        service: string("service")?,
        zone_id,
    })
}

fn read_contract_supported(
    capability: &CapabilityV1,
    id: &str,
    path: &str,
    product: &str,
    account_scope: &str,
) -> bool {
    capability.id == id
        && capability.method == "GET"
        && capability.path == path
        && capability.product == product
        && capability.account_scope == account_scope
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

fn selector_supported(
    capability: &CapabilityV1,
    name: &str,
    location: &str,
    required: bool,
) -> bool {
    capability.selectors.iter().any(|selector| {
        selector.name == name
            && selector.location == location
            && selector.required == required
            && selector.value_type == "string"
    })
}

fn zone_read_supported(capability: &CapabilityV1) -> bool {
    read_contract_supported(
        capability,
        ZONE_READ_CAPABILITY_ID,
        ZONE_READ_PATH,
        "Zone",
        "zone",
    ) && selector_supported(capability, "zone_id", "path", true)
}

fn worker_read_supported(capability: &CapabilityV1) -> bool {
    read_contract_supported(
        capability,
        WORKER_READ_CAPABILITY_ID,
        WORKER_READ_PATH,
        "Worker Script",
        "account",
    ) && selector_supported(capability, "account_id", "path", true)
        && selector_supported(capability, "script_name", "path", true)
}

fn domain_list_supported(capability: &CapabilityV1) -> bool {
    read_contract_supported(
        capability,
        DOMAIN_LIST_CAPABILITY_ID,
        DOMAIN_LIST_PATH,
        "Domains",
        "account",
    ) && selector_supported(capability, "account_id", "path", true)
        && selector_supported(capability, "hostname", "query", false)
}

fn dns_list_supported(capability: &CapabilityV1) -> bool {
    read_contract_supported(
        capability,
        DNS_LIST_CAPABILITY_ID,
        DNS_LIST_PATH,
        "DNS Records for a Zone",
        "zone",
    ) && selector_supported(capability, "zone_id", "path", true)
        && selector_supported(capability, "name.exact", "query", false)
}

fn require_success<'a>(label: &str, response: &'a CloudflareResponseV1) -> Result<&'a Value> {
    if response.success && (200..300).contains(&response.status) {
        Ok(&response.result)
    } else {
        Err(CliError::Input(format!(
            "Cloudflare rejected the Worker custom-domain {label} read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )))
    }
}

pub(super) fn apply_state_responses(
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    zone_response: &CloudflareResponseV1,
    worker_response: &CloudflareResponseV1,
    domain_response: &CloudflareResponseV1,
    dns_response: &CloudflareResponseV1,
) -> Result<Value> {
    let target = target(capability, input, account_id)?;
    let zone = require_success("zone", zone_response)?;
    if zone.get("id").and_then(Value::as_str) != Some(target.zone_id.as_str()) {
        return Err(CliError::Input(
            "Worker custom-domain zone read returned a different or missing zone id; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    if zone.pointer("/account/id").and_then(Value::as_str) != Some(target.account_id.as_str()) {
        return Err(CliError::Input(
            "Worker custom-domain zone belongs to a different or unknown account; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    if zone.get("status").and_then(Value::as_str) != Some("active") {
        return Err(CliError::Input(
            "Worker custom-domain zone is not active; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }

    let worker = require_success("Worker settings", worker_response)?;
    if !worker.is_object() {
        return Err(CliError::Input(
            "Worker custom-domain settings read did not return a Worker settings object; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let worker_settings_hash = hash_value(&redact_json(worker))?;

    let domains = require_success("existing-domain", domain_response)?
        .as_array()
        .ok_or_else(|| {
            CliError::Input(
                "Worker custom-domain list did not return an array; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    if !domains.is_empty() {
        return Err(CliError::Input(format!(
            "hostname `{}` already has {} Worker custom-domain resource(s); the mutation boundary was not crossed",
            target.hostname,
            domains.len()
        )));
    }

    let dns_records = require_success("exact-host DNS", dns_response)?
        .as_array()
        .ok_or_else(|| {
            CliError::Input(
                "Worker custom-domain DNS list did not return an array; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    if !dns_records.is_empty() {
        return Err(CliError::Input(format!(
            "hostname `{}` already has {} DNS record(s); the mutation boundary was not crossed",
            target.hostname,
            dns_records.len()
        )));
    }

    Ok(json!({
        "schema_version": 1,
        "target_capability_id": ATTACH_CAPABILITY_ID,
        "target_method": "PUT",
        "target_path": ATTACH_PATH,
        "target_scope": "account",
        "account_id": target.account_id,
        "hostname": target.hostname,
        "service": target.service,
        "zone_id": target.zone_id,
        "zone_source_capability_id": ZONE_READ_CAPABILITY_ID,
        "zone_source_path": ZONE_READ_PATH,
        "zone_status": "active",
        "worker_source_capability_id": WORKER_READ_CAPABILITY_ID,
        "worker_source_path": WORKER_READ_PATH,
        "worker_settings_hash": worker_settings_hash,
        "custom_domain_source_capability_id": DOMAIN_LIST_CAPABILITY_ID,
        "custom_domain_source_path": DOMAIN_LIST_PATH,
        "existing_custom_domain_count": 0,
        "dns_source_capability_id": DNS_LIST_CAPABILITY_ID,
        "dns_source_path": DNS_LIST_PATH,
        "existing_dns_record_count": 0,
    }))
}

pub(super) async fn read_live_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    let target = target(capability, input, account_id)?;
    let zone_capability = catalog
        .get(ZONE_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(ZONE_READ_CAPABILITY_ID))?;
    let worker_capability = catalog
        .get(WORKER_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(WORKER_READ_CAPABILITY_ID))?;
    let domain_capability = catalog
        .get(DOMAIN_LIST_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(DOMAIN_LIST_CAPABILITY_ID))?;
    let dns_capability = catalog
        .get(DNS_LIST_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(DNS_LIST_CAPABILITY_ID))?;
    if !zone_read_supported(zone_capability)
        || !worker_read_supported(worker_capability)
        || !domain_list_supported(domain_capability)
        || !dns_list_supported(dns_capability)
    {
        return Err(CliError::Input(
            "Worker custom-domain prerequisite source capability drifted from its governed zone, Worker, domain, or DNS read contract"
                .to_owned(),
        ));
    }

    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let zone_response = executor
        .execute_read(
            zone_capability,
            &CallInput {
                selectors: json!({"zone_id":target.zone_id}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let worker_response = executor
        .execute_read(
            worker_capability,
            &CallInput {
                selectors: json!({
                    "account_id":target.account_id,
                    "script_name":target.service,
                }),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let domain_response = executor
        .execute_read(
            domain_capability,
            &CallInput {
                selectors: json!({"account_id":target.account_id}),
                query: json!({"hostname":target.hostname}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let dns_response = executor
        .execute_read(
            dns_capability,
            &CallInput {
                selectors: json!({"zone_id":target.zone_id}),
                query: json!({"name.exact":target.hostname}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_state_responses(
        capability,
        input,
        account_id,
        &zone_response,
        &worker_response,
        &domain_response,
        &dns_response,
    )?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) async fn prepare_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("Worker custom-domain live-state credential was not resolved".to_owned())
    })?;
    read_live_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

fn valid_hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_receipt(plan: &PlanV1, receipt: &Value) -> Result<()> {
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let target = target(&plan.capability, &input, &plan.account_id)?;
    let exact = receipt.as_object().is_some_and(|object| object.len() == 21)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(ATTACH_CAPABILITY_ID)
        && receipt.get("target_method").and_then(Value::as_str) == Some("PUT")
        && receipt.get("target_path").and_then(Value::as_str) == Some(ATTACH_PATH)
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(target.account_id.as_str())
        && receipt.get("hostname").and_then(Value::as_str) == Some(target.hostname.as_str())
        && receipt.get("service").and_then(Value::as_str) == Some(target.service.as_str())
        && receipt.get("zone_id").and_then(Value::as_str) == Some(target.zone_id.as_str())
        && receipt
            .get("zone_source_capability_id")
            .and_then(Value::as_str)
            == Some(ZONE_READ_CAPABILITY_ID)
        && receipt.get("zone_source_path").and_then(Value::as_str) == Some(ZONE_READ_PATH)
        && receipt.get("zone_status").and_then(Value::as_str) == Some("active")
        && receipt
            .get("worker_source_capability_id")
            .and_then(Value::as_str)
            == Some(WORKER_READ_CAPABILITY_ID)
        && receipt.get("worker_source_path").and_then(Value::as_str) == Some(WORKER_READ_PATH)
        && receipt
            .get("worker_settings_hash")
            .and_then(Value::as_str)
            .is_some_and(valid_hash)
        && receipt
            .get("custom_domain_source_capability_id")
            .and_then(Value::as_str)
            == Some(DOMAIN_LIST_CAPABILITY_ID)
        && receipt
            .get("custom_domain_source_path")
            .and_then(Value::as_str)
            == Some(DOMAIN_LIST_PATH)
        && receipt
            .get("existing_custom_domain_count")
            .and_then(Value::as_u64)
            == Some(0)
        && receipt
            .get("dns_source_capability_id")
            .and_then(Value::as_str)
            == Some(DNS_LIST_CAPABILITY_ID)
        && receipt.get("dns_source_path").and_then(Value::as_str) == Some(DNS_LIST_PATH)
        && receipt
            .get("existing_dns_record_count")
            .and_then(Value::as_u64)
            == Some(0);
    if exact {
        Ok(())
    } else {
        Err(CliError::Input(
            "Worker custom-domain live-state receipt has an invalid account, hostname, service, zone, source, status, hash, or conflict count; create a new plan"
                .to_owned(),
        ))
    }
}

pub(super) fn required_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if plan.capability.id != ATTACH_CAPABILITY_ID {
        return Ok(None);
    }
    if !should_bind_state(&plan.capability) {
        return Err(CliError::Input(
            "Worker custom-domain plan is inconsistent with its hash-bound live-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(WORKER_CUSTOM_DOMAIN_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the Worker custom-domain live-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/worker_custom_domain_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound Worker custom-domain live-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan Worker custom-domain receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) async fn validate_live_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live Worker custom-domain prerequisites drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

#[cfg(test)]
mod tests {
    use super::{
        WORKER_CUSTOM_DOMAIN_STATE_PRECONDITION, apply_state_responses, required_precondition,
        should_bind_state,
    };
    use cfctl_cloudflare::{CallInput, CloudflareResponseV1};
    use cfctl_core::{
        AdapterStatus, CapabilityV1, CostV1, EffectClass, PlanV1, RiskClass, hash_value,
    };
    use cfctl_storage::{RuntimePaths, StateStore};
    use serde_json::json;

    use super::super::{plan_requires_live_credential, validate_plan_preconditions};

    fn attach_capability() -> CapabilityV1 {
        let mut capability = CapabilityV1::new(
            "workers.domains.update",
            "Attach Worker custom domain",
            "PUT",
            "/accounts/{account_id}/workers/domains",
        );
        capability.product = "Domains".to_owned();
        capability.account_scope = "account".to_owned();
        capability.permissions = vec!["Workers Scripts Write".to_owned()];
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.mutating = true;
        capability.risk = RiskClass::CrossConfig;
        capability.effect = EffectClass::ReversibleWrite;
        capability.cost = CostV1::default();
        capability
    }

    fn response(result: serde_json::Value) -> CloudflareResponseV1 {
        CloudflareResponseV1 {
            status: 200,
            success: true,
            result,
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        }
    }

    #[test]
    fn custom_domain_state_binds_active_zone_worker_and_exact_hostname_absence() {
        let capability = attach_capability();
        let input = CallInput {
            selectors: json!({"account_id":"account-a"}),
            query: json!({}),
            body: Some(json!({
                "hostname":"cfctl.com",
                "service":"cfctl-site",
                "zone_id":"0123456789abcdef0123456789abcdef",
            })),
            ..CallInput::default()
        };
        assert!(should_bind_state(&capability));
        let receipt = apply_state_responses(
            &capability,
            &input,
            "account-a",
            &response(json!({
                "id":"0123456789abcdef0123456789abcdef",
                "status":"active",
                "account":{"id":"account-a"},
            })),
            &response(json!({"bindings":[],"compatibility_date":"2026-08-10"})),
            &response(json!([])),
            &response(json!([])),
        )
        .expect("bounded live-state receipt");

        assert_eq!(receipt["schema_version"], 1);
        assert_eq!(receipt["hostname"], "cfctl.com");
        assert_eq!(receipt["service"], "cfctl-site");
        assert_eq!(receipt["zone_status"], "active");
        assert_eq!(receipt["existing_custom_domain_count"], 0);
        assert_eq!(receipt["existing_dns_record_count"], 0);
        assert!(
            receipt["worker_settings_hash"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
        assert!(
            hash_value(&receipt)
                .expect("receipt hash")
                .starts_with("sha256:")
        );
        assert_eq!(
            WORKER_CUSTOM_DOMAIN_STATE_PRECONDITION,
            "worker_custom_domain_state"
        );

        let existing_domain = apply_state_responses(
            &capability,
            &input,
            "account-a",
            &response(json!({
                "id":"0123456789abcdef0123456789abcdef",
                "status":"active",
                "account":{"id":"account-a"},
            })),
            &response(json!({"bindings":[]})),
            &response(json!([{"hostname":"cfctl.com","service":"other"}])),
            &response(json!([])),
        )
        .expect_err("an existing custom domain must block planning");
        assert!(
            existing_domain
                .to_string()
                .contains("custom-domain resource")
        );

        let existing_dns = apply_state_responses(
            &capability,
            &input,
            "account-a",
            &response(json!({
                "id":"0123456789abcdef0123456789abcdef",
                "status":"active",
                "account":{"id":"account-a"},
            })),
            &response(json!({"bindings":[]})),
            &response(json!([])),
            &response(json!([{"id":"dns-a","name":"cfctl.com","type":"CNAME"}])),
        )
        .expect_err("an existing DNS record must block planning");
        assert!(existing_dns.to_string().contains("DNS record"));
    }

    #[test]
    fn custom_domain_state_rejects_inactive_or_cross_account_zone() {
        let capability = attach_capability();
        let input = CallInput {
            selectors: json!({"account_id":"account-a"}),
            query: json!({}),
            body: Some(json!({
                "hostname":"cfctl.com",
                "service":"cfctl-site",
                "zone_id":"0123456789abcdef0123456789abcdef",
            })),
            ..CallInput::default()
        };
        for zone in [
            json!({
                "id":"0123456789abcdef0123456789abcdef",
                "status":"pending",
                "account":{"id":"account-a"},
            }),
            json!({
                "id":"0123456789abcdef0123456789abcdef",
                "status":"active",
                "account":{"id":"account-b"},
            }),
        ] {
            apply_state_responses(
                &capability,
                &input,
                "account-a",
                &response(zone),
                &response(json!({"bindings":[]})),
                &response(json!([])),
                &response(json!([])),
            )
            .expect_err("inactive or cross-account zones must block planning");
        }
    }

    #[test]
    fn custom_domain_plan_routes_and_hash_binds_live_state() {
        let capability = attach_capability();
        let input = CallInput {
            selectors: json!({"account_id":"account-a"}),
            query: json!({}),
            body: Some(json!({
                "hostname":"cfctl.com",
                "service":"cfctl-site",
                "zone_id":"0123456789abcdef0123456789abcdef",
            })),
            ..CallInput::default()
        };
        assert!(plan_requires_live_credential(&capability, &json!({})));
        let receipt = apply_state_responses(
            &capability,
            &input,
            "account-a",
            &response(json!({
                "id":"0123456789abcdef0123456789abcdef",
                "status":"active",
                "account":{"id":"account-a"},
            })),
            &response(json!({"bindings":[]})),
            &response(json!([])),
            &response(json!([])),
        )
        .expect("bounded live-state receipt");
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({
                "selectors":input.selectors,
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{
                    WORKER_CUSTOM_DOMAIN_STATE_PRECONDITION:receipt
                }
            }),
        )
        .expect("custom-domain plan");
        plan.input = serde_json::to_value(&input).expect("serialized custom-domain input");
        plan.precondition_hashes.insert(
            WORKER_CUSTOM_DOMAIN_STATE_PRECONDITION.to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        assert_eq!(
            required_precondition(&plan).expect("bound custom-domain precondition"),
            plan.precondition_hashes
                .get(WORKER_CUSTOM_DOMAIN_STATE_PRECONDITION)
                .map(String::as_str)
        );
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        validate_plan_preconditions(&store, &plan)
            .expect("the dedicated live reread, not workspace hashing, validates this receipt");

        let mut retargeted = receipt;
        retargeted["hostname"] = json!("other.example.com");
        plan.precondition_hashes.insert(
            WORKER_CUSTOM_DOMAIN_STATE_PRECONDITION.to_owned(),
            hash_value(&retargeted).expect("retargeted receipt hash"),
        );
        plan.targets["live_preconditions"][WORKER_CUSTOM_DOMAIN_STATE_PRECONDITION] = retargeted;
        required_precondition(&plan).expect_err("a rehashed cross-host receipt must fail");
    }
}
