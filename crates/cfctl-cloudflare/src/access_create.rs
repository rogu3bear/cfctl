//! Exact Access hostname ownership, creation, and readback proof.
use super::{
    AuthCredential, BTreeSet, CallInput, CapabilityV1, CloudflareError, CloudflareResponseV1,
    Executor, OperationVerificationV1, PlanV1, Result, Value, access_application_set_field_matches,
    access_create, clean_verification_query, extend_r2_bucket_create_mismatches, hash_value,
    mismatched_verifiable_planned_fields, page_pagination, render_field_names,
    resource_identity_value,
};
use serde_json::json;

pub(super) const OWNED_CREATE_ID: &str = "access-applications-create-owned-self-hosted-whole-host";
const COLLECTION: &str = "/accounts/{account_id}/access/apps";
const LIST_ID: &str = "access-applications-list-access-applications";

fn invalid(message: &str) -> CloudflareError {
    CloudflareError::InvalidRequestBody(format!("owned Access application: {message}"))
}

/// Cross-field constraints supplement the hash-bound closed catalog schema.
pub fn validate_owned_access_create_input(input: &CallInput) -> Result<()> {
    let selectors = input
        .selectors
        .as_object()
        .ok_or_else(|| invalid("selectors must be an object"))?;
    if selectors.len() != 1
        || selectors
            .get("account_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || !clean_verification_query(input)
    {
        return Err(invalid("requires only account_id and no query controls"));
    }
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("complete body required"))?;
    let hostname = body
        .get("domain")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("domain required"))?;
    if hostname != hostname.to_ascii_lowercase()
        || hostname.len() > 253
        || !hostname.contains('.')
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(invalid("domain must be an exact lowercase whole hostname"));
    }
    if body.get("type") != Some(&json!("self_hosted"))
        || body
            .get("name")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || body.get("policies") != Some(&json!([]))
        || body.get("options_preflight_bypass") != Some(&json!(false))
        || body.contains_key("self_hosted_domains")
        || body.get("destinations") != Some(&json!([{"type":"public","uri":hostname}]))
    {
        return Err(invalid(
            "requires one bare whole-host destination and empty policies without bypass",
        ));
    }
    Ok(())
}

fn hostname_overlap(value: &str, target: &str) -> Result<bool> {
    let raw = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .unwrap_or(value);
    let host = raw
        .split('/')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() || host.contains([':', '?', '#', '@']) {
        return Err(invalid("unclassified hostname in application inventory"));
    }
    let base = host.strip_prefix("*.").unwrap_or(&host);
    if base.split('.').any(|label| {
        label.is_empty()
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return Err(invalid(
            "unclassified hostname pattern in application inventory",
        ));
    }
    Ok(host == target || (host.starts_with("*.") && target.ends_with(&format!(".{base}"))))
}

/// Classify public hostname overlap, rejecting unobservable application inventory.
pub fn access_application_host_overlap(app: &Value, hostname: &str) -> Result<bool> {
    if app
        .get("name")
        .is_some_and(|value| !value.is_string() && !value.is_null())
    {
        return Err(invalid("unclassified application name"));
    }
    let mut matches = false;
    let mut observable = false;
    let app_type = app
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("application type absent"))?;
    if !matches!(app_type, "self_hosted" | "app_launcher" | "saas") {
        return Err(invalid(
            "unclassified application type cannot prove hostname absence",
        ));
    }
    if let Some(domain) = app.get("domain").filter(|v| !v.is_null()) {
        observable = true;
        matches |= hostname_overlap(
            domain
                .as_str()
                .ok_or_else(|| invalid("non-string domain"))?,
            hostname,
        )?;
    }
    if let Some(domains) = app.get("self_hosted_domains").filter(|v| !v.is_null()) {
        for domain in domains
            .as_array()
            .ok_or_else(|| invalid("non-array domains"))?
        {
            observable = true;
            matches |= hostname_overlap(
                domain
                    .as_str()
                    .ok_or_else(|| invalid("non-string domain"))?,
                hostname,
            )?;
        }
    }
    if let Some(destinations) = app.get("destinations").filter(|v| !v.is_null()) {
        for destination in destinations
            .as_array()
            .ok_or_else(|| invalid("non-array destinations"))?
        {
            match destination.get("type").and_then(Value::as_str) {
                Some("public") => {
                    observable = true;
                    matches |= hostname_overlap(
                        destination
                            .get("uri")
                            .and_then(Value::as_str)
                            .ok_or_else(|| invalid("public destination has no URI"))?,
                        hostname,
                    )?;
                }
                Some("private") => {}
                _ => return Err(invalid("unclassified destination type")),
            }
        }
    }
    if app_type == "self_hosted" && !observable {
        return Err(invalid(
            "self-hosted application omitted observable hostname ownership",
        ));
    }
    Ok(matches)
}

/// A terminal inventory must prove zero candidates before creation, or exactly
/// the returned identity afterward. The digest binds unrelated application state.
pub fn access_create_collection_receipt(
    input: &CallInput,
    response: &CloudflareResponseV1,
    created_id: Option<&str>,
) -> Result<Value> {
    validate_owned_access_create_input(input)?;
    let complete = response.result_info.as_ref().is_some_and(|info| {
        let page = info.get("page").and_then(Value::as_u64);
        let pages = info.get("total_pages").and_then(Value::as_u64);
        page.is_some_and(|page| page > 0)
            && page == pages
            && info.get("cfctl_page_complete") == Some(&json!(true))
    });
    if !response.success || !(200..300).contains(&response.status) || !complete {
        return Err(invalid(
            "complete successful terminal application inventory required",
        ));
    }
    let apps = response
        .result
        .as_array()
        .ok_or_else(|| invalid("application inventory must be an array"))?;
    let body = input.body.as_ref().ok_or_else(|| invalid("body absent"))?;
    let name = body["name"]
        .as_str()
        .ok_or_else(|| invalid("name absent"))?;
    let host = body["domain"]
        .as_str()
        .ok_or_else(|| invalid("domain absent"))?;
    let mut ids = BTreeSet::new();
    let mut candidates = Vec::new();
    for app in apps {
        let id = app
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| invalid("application id absent"))?;
        if !ids.insert(id)
            || app
                .get("type")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        {
            return Err(invalid("duplicate identity or unclassified application"));
        }
        let overlap = access_application_host_overlap(app, host)?;
        if created_id == Some(id)
            && (app.get("type").and_then(Value::as_str) != Some("self_hosted")
                || app.get("name").and_then(Value::as_str) != Some(name)
                || !overlap)
        {
            return Err(invalid(
                "returned application identity drifted in inventory",
            ));
        }
        if app.get("name").and_then(Value::as_str) == Some(name) || overlap {
            candidates.push(id);
        }
    }
    let expected = created_id.map(|id| vec![id]).unwrap_or_default();
    if candidates != expected {
        return Err(invalid(
            "name or hostname ownership conflicts with the expected absence/returned identity",
        ));
    }
    Ok(
        json!({"schema_version":1,"capability_id":OWNED_CREATE_ID,"account_id":input.selectors["account_id"],"name":name,"hostname":host,"created_id":created_id,"candidate_count":candidates.len(),"collection_count":apps.len(),"collection_digest":hash_value(&response.result)?,"terminal_pagination":true}),
    )
}

fn exact_created_fields(body: &Value, actual: &Value) -> bool {
    body.as_object().is_some_and(|body| {
        body.iter().all(|(field, planned)| {
            if field == "allowed_idps" {
                return access_application_set_field_matches(field, actual.get(field), planned);
            }
            // No subset comparison: in particular [] must not match an injected policy.
            actual.get(field) == Some(planned)
        })
    })
}

impl Executor {
    /// Read every application page from page one. A terminal last page alone
    /// cannot prove absence across an account.
    pub async fn read_access_application_inventory(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        if capability.id != LIST_ID
            || capability.method != "GET"
            || capability.path != COLLECTION
            || !clean_verification_query(input)
            || input.body.is_some()
        {
            return Err(invalid("application inventory read contract drifted"));
        }
        let request = self.builder.build(capability, input)?;
        let first = self.send(&request, credential).await?;
        if !first.success {
            return Ok(first);
        }
        let pagination = page_pagination(first.result_info.as_ref())?
            .ok_or_else(|| invalid("page-one application inventory metadata missing"))?;
        if pagination.current_page != 1 {
            return Err(invalid("application inventory did not start at page one"));
        }
        self.complete_page_pagination(&request, credential, first, pagination)
            .await
    }
    async fn verify_owned_access_create(
        &self,
        plan: &PlanV1,
        apply: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        validate_owned_access_create_input(input)?;
        let id = apply.result.get("id").and_then(Value::as_str).filter(|id| !id.is_empty()).ok_or_else(|| invalid("creation response omitted exact app ID; inspect consumed operation, never replay"))?;
        let details = CapabilityV1::new(
            "access-applications-get-an-access-application",
            "Owned Access app verification",
            "GET",
            &format!("{COLLECTION}/{{app_id}}"),
        );
        let read_input = CallInput {
            selectors: json!({"account_id":input.selectors["account_id"],"app_id":id}),
            query: json!({}),
            ..CallInput::default()
        };
        let detail = self
            .send(&self.builder.build(&details, &read_input)?, credential)
            .await?;
        let list = CapabilityV1::new(LIST_ID, "Owned Access app uniqueness", "GET", COLLECTION);
        let inventory = self
            .read_access_application_inventory(
                &list,
                &CallInput {
                    selectors: input.selectors.clone(),
                    query: json!({}),
                    ..CallInput::default()
                },
                credential,
            )
            .await?;
        let ownership = access_create_collection_receipt(input, &inventory, Some(id));
        let passed = apply.success
            && (200..300).contains(&apply.status)
            && detail.success
            && (200..300).contains(&detail.status)
            && detail.result.get("id").and_then(Value::as_str) == Some(id)
            && input
                .body
                .as_ref()
                .is_some_and(|body| exact_created_fields(body, &detail.result))
            && ownership.is_ok();
        let mut readback = detail;
        readback.result = json!({"application":readback.result,"ownership":ownership.as_ref().ok(),"ownership_error":ownership.err().map(|e|e.to_string()),"inventory_digest":hash_value(&inventory.result)?,"inventory_result_info":inventory.result_info});
        Ok(OperationVerificationV1 { strategy: plan.capability.verification.strategy.clone(), passed,
            basis: "verified only when the returned application ID has every exact planned field, empty policies and unique whole-host ownership in a terminal account inventory".to_owned(), readback, correlated_resource_id: None })
    }
    pub(super) async fn verify_created_resource(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        if plan.capability.id == access_create::OWNED_CREATE_ID {
            return Box::pin(self.verify_owned_access_create(
                plan,
                apply_response,
                input,
                credential,
            ))
            .await;
        }
        let target = plan.capability.created_resource.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound created-resource contract is absent".to_owned(),
            )
        })?;
        let planned = input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "planned create body is absent, empty, or not an object".to_owned(),
                )
            })?;
        let resource_id = apply_response
            .result
            .pointer(&target.response_result_identity_pointer)
            .and_then(resource_identity_value)
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the successful creation response has no non-empty string or integer schema-proven identity"
                        .to_owned(),
                )
            })?;
        let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned create selectors are not an object".to_owned(),
            )
        })?;
        selectors.insert(target.identity_selector.clone(), resource_id.clone());
        let mut details = CapabilityV1::new(
            &target.read_capability_id,
            "Created resource verification readback",
            "GET",
            &target.detail_path,
        );
        details.selectors.clone_from(&plan.capability.selectors);
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors: Value::Object(selectors),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let readback_identity = readback
            .result
            .pointer(&target.response_result_identity_pointer)
            .and_then(resource_identity_value);
        let mut mismatches =
            mismatched_verifiable_planned_fields(&plan.capability, planned, &readback.result);
        extend_r2_bucket_create_mismatches(plan, input, &readback.result, &mut mismatches);
        let passed = apply_response.success
            && readback.success
            && readback_identity.as_ref() == Some(&resource_id)
            && mismatches.is_empty();
        let basis = if passed {
            "the exact created-resource readback matched the returned identity and every planned field"
                .to_owned()
        } else {
            format!(
                "created resource was not proven (apply success={}, readback HTTP {}, readback success={}, identity match={}, fields={})",
                apply_response.success,
                readback.status,
                readback.success,
                readback_identity.as_ref() == Some(&resource_id),
                render_field_names(&mismatches)
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    fn input() -> CallInput {
        CallInput {
            selectors: json!({"account_id":"account-a"}),
            query: json!({}),
            body: Some(json!({
                "domain":"ops.example.com", "name":"maildesk-ops", "type":"self_hosted",
                "destinations":[{"type":"public","uri":"ops.example.com"}],
                "policies":[], "options_preflight_bypass":false,
                "allowed_idps":["11111111-1111-4111-8111-111111111111"],
                "app_launcher_visible":false, "auto_redirect_to_identity":false,
                "enable_binding_cookie":true,"http_only_cookie_attribute":true,"session_duration":"1h"
            })),
            ..CallInput::default()
        }
    }
    fn response(result: Value) -> CloudflareResponseV1 {
        CloudflareResponseV1 {
            status: 200,
            success: true,
            result,
            errors: vec![],
            result_info: Some(json!({"page":1,"total_pages":1,"cfctl_page_complete":true})),
            etag: None,
            cf_ray: None,
        }
    }
    #[test]
    fn owned_create_accepts_absence_and_binds_complete_inventory() {
        let input = input();
        let empty = access_create_collection_receipt(&input, &response(json!([])), None)
            .expect("valid test fixture");
        assert_eq!(empty["candidate_count"], 0);
        let unrelated =
            json!({"id":"other","type":"self_hosted","name":"other","domain":"other.example.com"});
        let next = access_create_collection_receipt(&input, &response(json!([unrelated])), None)
            .expect("valid test fixture");
        assert_ne!(empty["collection_digest"], next["collection_digest"]);
        let mut incomplete = response(json!([]));
        incomplete.result_info = Some(json!({"page":1,"total_pages":2}));
        assert!(access_create_collection_receipt(&input, &incomplete, None).is_err());
        incomplete.result_info = None;
        assert!(access_create_collection_receipt(&input, &incomplete, None).is_err());
    }
    #[test]
    fn owned_create_rejects_name_host_path_wildcard_and_malformed_overlap() {
        for app in [
            json!({"id":"a","type":"self_hosted","name":"maildesk-ops","domain":"other.example.com"}),
            json!({"id":"a","type":"self_hosted","name":"other","domain":"ops.example.com/admin"}),
            json!({"id":"a","type":"self_hosted","name":"other","domain":"*.example.com"}),
            json!({"id":"a","type":"self_hosted","domain":32}),
            json!({"id":"a","type":"self_hosted"}),
            json!({"id":"a","type":"self_hosted","domain":null,"destinations":[]}),
            json!({"id":"a","type":"future"}),
            json!({"id":"a","type":"self_hosted","destinations":[{"type":"public","uri":"https://ops.example.com:443"}]}),
            json!({"id":"a","type":"self_hosted","destinations":[{"type":"future","uri":"ops.example.com"}]}),
        ] {
            assert!(
                access_create_collection_receipt(&input(), &response(json!([app])), None).is_err()
            );
        }
    }
    #[test]
    fn owned_create_requires_returned_id_to_be_the_only_candidate() {
        let app = json!({"id":"created","type":"self_hosted","name":"maildesk-ops","domain":"ops.example.com"});
        assert!(
            access_create_collection_receipt(
                &input(),
                &response(json!([app.clone()])),
                Some("created")
            )
            .is_ok()
        );
        assert!(
            access_create_collection_receipt(
                &input(),
                &response(json!([app.clone()])),
                Some("wrong")
            )
            .is_err()
        );
        let conflict =
            json!({"id":"other","type":"self_hosted","domain":"ops.example.com/private"});
        assert!(
            access_create_collection_receipt(
                &input(),
                &response(json!([app, conflict])),
                Some("created")
            )
            .is_err()
        );
    }
    #[test]
    fn owned_create_rejects_policy_injection_bypass_and_inconsistent_destinations() {
        for (field, value) in [
            ("policies", json!([{"id":"p"}])),
            ("options_preflight_bypass", json!(true)),
            (
                "destinations",
                json!([{"type":"public","uri":"other.example.com"}]),
            ),
            ("domain", json!("ops.example.com/path")),
            ("self_hosted_domains", json!(["ops.example.com"])),
        ] {
            let mut input = input();
            input.body.as_mut().expect("valid test fixture")[field] = value;
            assert!(
                validate_owned_access_create_input(&input).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn owned_create_readback_does_not_treat_empty_policy_as_a_subset() {
        let body = input().body.expect("valid test fixture");
        let mut actual = body.clone();
        actual["id"] = json!("returned-id");
        actual["self_hosted_domains"] = json!(["deprecated.example.com"]);
        assert!(
            exact_created_fields(&body, &actual),
            "authoritative destinations match despite deprecated field"
        );
        for (field, value) in [
            ("policies", json!([{"decision":"bypass"}])),
            ("domain", json!("other.example.com")),
            ("allowed_idps", json!([])),
            (
                "destinations",
                json!([{"type":"public","uri":"https://ops.example.com/path"}]),
            ),
        ] {
            let mut drift = actual.clone();
            drift[field] = value;
            assert!(!exact_created_fields(&body, &drift), "{field}");
        }
    }
    async fn test_server(
        responses: Vec<Value>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("valid test fixture");
        let address = listener.local_addr().expect("valid test fixture");
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for body in responses {
                let (mut stream, _) = listener.accept().await.expect("valid test fixture");
                let mut bytes = [0_u8; 8192];
                let len = stream.read(&mut bytes).await.expect("valid test fixture");
                requests.push(String::from_utf8_lossy(&bytes[..len]).to_string());
                let body = body.to_string();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.expect("valid test fixture");
            }
            requests
        });
        (address, server)
    }

    #[tokio::test]
    async fn owned_create_inventory_rejects_a_terminal_page_without_page_one() {
        let (address, server) = test_server(vec![
            json!({"success":true,"result":[],"result_info":{"page":2,"total_pages":2}}),
        ])
        .await;
        let executor = Executor::new(reqwest::Client::new(), &format!("http://{address}"))
            .expect("valid test fixture");
        let list = CapabilityV1::new(LIST_ID, "Inventory", "GET", COLLECTION);
        let error = executor
            .read_access_application_inventory(
                &list,
                &CallInput {
                    selectors: json!({"account_id":"account-a"}),
                    query: json!({}),
                    ..CallInput::default()
                },
                &AuthCredential::Bearer {
                    token: "test-placeholder".to_owned(),
                },
            )
            .await
            .expect_err("fixture must be rejected");
        assert!(error.to_string().contains("page one"));
        assert_eq!(server.await.expect("valid test fixture").len(), 1);
    }

    #[tokio::test]
    async fn owned_create_verifies_returned_id_and_all_inventory_pages_without_posting() {
        let input = input();
        let mut actual = input.body.clone().expect("valid test fixture");
        actual["id"] = json!("created");
        let responses = vec![
            json!({"success":true,"result":actual.clone()}),
            json!({"success":true,"result":[actual],"result_info":{"page":1,"per_page":1,"count":1,"total_pages":2,"total_count":2}}),
            json!({"success":true,"result":[{"id":"other","type":"self_hosted","domain":"other.example.com"}],"result_info":{"page":2,"per_page":1,"count":1,"total_pages":2,"total_count":2}}),
        ];
        let (address, server) = test_server(responses).await;
        let capability = CapabilityV1::new(OWNED_CREATE_ID, "Owned app", "POST", COLLECTION);
        let plan = PlanV1::draft("test", "account-a", "catalog", capability, json!({}))
            .expect("valid test fixture");
        let executor = Executor::new(reqwest::Client::new(), &format!("http://{address}"))
            .expect("valid test fixture");
        let proof = executor
            .verify_created_resource(
                &plan,
                &response(json!({"id":"created"})),
                &input,
                &AuthCredential::Bearer {
                    token: "test-placeholder".to_owned(),
                },
            )
            .await
            .expect("valid test fixture");
        assert!(proof.passed, "{} {:?}", proof.basis, proof.readback);
        let requests = server.await.expect("valid test fixture");
        assert!(requests.iter().all(|request| request.starts_with("GET ")));
        assert!(requests[0].contains("/access/apps/created"));
        assert!(requests[2].contains("page=2"));
    }

    #[tokio::test]
    async fn owned_create_missing_returned_identity_never_replays_the_mutation() {
        let capability = CapabilityV1::new(OWNED_CREATE_ID, "Owned app", "POST", COLLECTION);
        let plan = PlanV1::draft("test", "account-a", "catalog", capability, json!({}))
            .expect("valid test fixture");
        let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:1")
            .expect("valid test fixture");
        let error = executor
            .verify_created_resource(
                &plan,
                &response(json!({})),
                &input(),
                &AuthCredential::Bearer {
                    token: "test-placeholder".to_owned(),
                },
            )
            .await
            .expect_err("fixture must be rejected");
        assert!(error.to_string().contains("never replay"));
    }
}
