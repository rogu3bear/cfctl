//! Typed Cloudflare request construction and governed execution.

use std::time::Duration;

use cfctl_auth::AuthCredential;
use cfctl_core::{CapabilityV1, PlanStatus, PlanV1};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::time::sleep;
use url::Url;

#[derive(Debug, Error)]
pub enum CloudflareError {
    #[error("invalid Cloudflare API base URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("selector `{0}` is required to construct the request path")]
    MissingSelector(String),
    #[error("selector `{0}` must be a string, number, or boolean")]
    InvalidSelector(String),
    #[error("required request body is missing for capability `{0}`")]
    MissingRequestBody(String),
    #[error("request body does not satisfy the pinned schema: {0}")]
    InvalidRequestBody(String),
    #[error("capability `{0}` mutates state and requires a consumable approved plan")]
    ApprovedPlanRequired(String),
    #[error("Cloudflare API base URL cannot accept path segments")]
    InvalidBaseUrl,
    #[error("invalid HTTP method `{0}`")]
    InvalidMethod(String),
    #[error("invalid authentication header")]
    InvalidAuthenticationHeader,
    #[error("invalid conditional request header")]
    InvalidConditionalHeader,
    #[error("Cloudflare reported {0} pages, above the governed pagination limit")]
    PaginationLimit(u64),
    #[error("Cloudflare request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("approved plan pins catalog {planned}, but the current catalog is {current}")]
    CatalogDrift { planned: String, current: String },
    #[error("approved plan cannot be executed: {0}")]
    Plan(#[from] cfctl_core::CoreError),
    #[error("verification strategy `{0}` is not implemented by the selected adapter")]
    UnsupportedVerificationStrategy(String),
    #[error("verification target is missing from the mutation result: {0}")]
    MissingVerificationTarget(String),
}

pub type Result<T> = std::result::Result<T, CloudflareError>;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CallInput {
    pub selectors: Value,
    pub query: Value,
    pub body: Option<Value>,
    #[serde(default)]
    pub if_match: Option<String>,
    #[serde(default)]
    pub if_none_match: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreparedRequest {
    pub method: String,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct RequestBuilder {
    base_url: Url,
}

impl RequestBuilder {
    pub fn new(base_url: &str) -> Result<Self> {
        Ok(Self {
            base_url: Url::parse(base_url)?,
        })
    }

    pub fn build(&self, capability: &CapabilityV1, input: &CallInput) -> Result<PreparedRequest> {
        if capability.mutating {
            return Err(CloudflareError::ApprovedPlanRequired(capability.id.clone()));
        }
        self.build_unchecked(capability, input)
    }

    pub fn build_unchecked(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
    ) -> Result<PreparedRequest> {
        validate_request_body(capability, input.body.as_ref())?;
        let mut url = self.base_url.clone();
        let selectors = input.selectors.as_object();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| CloudflareError::InvalidBaseUrl)?;
            segments.pop_if_empty();
            for segment in capability.path.trim_start_matches('/').split('/') {
                if let Some(key) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                    let value = selectors
                        .and_then(|map| map.get(key))
                        .ok_or_else(|| CloudflareError::MissingSelector(key.to_owned()))?;
                    let rendered = scalar(value)
                        .ok_or_else(|| CloudflareError::InvalidSelector(key.to_owned()))?;
                    segments.push(&rendered);
                } else {
                    segments.push(segment);
                }
            }
        }
        if let Some(query) = input.query.as_object().filter(|query| !query.is_empty()) {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                match value {
                    Value::Array(values) => {
                        for item in values {
                            if let Some(rendered) = scalar(item) {
                                pairs.append_pair(key, &rendered);
                            }
                        }
                    }
                    _ => {
                        if let Some(rendered) = scalar(value) {
                            pairs.append_pair(key, &rendered);
                        }
                    }
                }
            }
        }
        let mut headers = HeaderMap::new();
        add_conditional_header(
            &mut headers,
            reqwest::header::IF_MATCH,
            input.if_match.as_ref(),
        )?;
        add_conditional_header(
            &mut headers,
            reqwest::header::IF_NONE_MATCH,
            input.if_none_match.as_ref(),
        )?;
        Ok(PreparedRequest {
            method: capability.method.clone(),
            url,
            headers,
            body: input.body.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudflareApiErrorV1 {
    pub code: Option<i64>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudflareResponseV1 {
    pub status: u16,
    pub success: bool,
    pub result: Value,
    pub errors: Vec<CloudflareApiErrorV1>,
    pub result_info: Option<Value>,
    pub etag: Option<String>,
    pub cf_ray: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationVerificationV1 {
    pub strategy: String,
    pub passed: bool,
    pub basis: String,
    pub readback: CloudflareResponseV1,
}

#[derive(Clone)]
pub struct Executor {
    client: reqwest::Client,
    builder: RequestBuilder,
    max_retries: usize,
}

impl Executor {
    pub fn new(client: reqwest::Client, base_url: &str) -> Result<Self> {
        Ok(Self {
            client,
            builder: RequestBuilder::new(base_url)?,
            max_retries: 3,
        })
    }

    #[must_use]
    pub const fn with_max_retries(mut self, max_retries: usize) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub async fn execute_read(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        let request = self.builder.build(capability, input)?;
        self.send_paginated(&request, credential).await
    }

    pub async fn execute_consumed_plan(
        &self,
        plan: &mut PlanV1,
        current_catalog_hash: &str,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        let input: CallInput = serde_json::from_value(plan.input.clone())
            .map_err(cfctl_core::CoreError::Serialization)?;
        self.execute_consumed_plan_with_input(plan, current_catalog_hash, credential, &input)
            .await
    }

    pub async fn execute_consumed_plan_with_input(
        &self,
        plan: &mut PlanV1,
        current_catalog_hash: &str,
        credential: &AuthCredential,
        input: &CallInput,
    ) -> Result<CloudflareResponseV1> {
        if plan.catalog_hash != current_catalog_hash {
            return Err(CloudflareError::CatalogDrift {
                planned: plan.catalog_hash.clone(),
                current: current_catalog_hash.to_owned(),
            });
        }
        if plan.status != PlanStatus::Consumed {
            return Err(CloudflareError::Plan(
                cfctl_core::CoreError::InvalidPlanState {
                    operation_id: plan.operation_id.clone(),
                    actual: plan.status,
                    expected: "durably persisted consumed plan",
                },
            ));
        }
        validate_verification_preconditions(&plan.capability, input)?;
        let mut request = self.builder.build_unchecked(&plan.capability, input)?;
        request.headers.insert(
            HeaderName::from_static("idempotency-key"),
            HeaderValue::from_str(&plan.operation_id)
                .map_err(|_| CloudflareError::InvalidConditionalHeader)?,
        );
        match self.send(&request, credential).await {
            Ok(response) => {
                plan.status = if response.success {
                    PlanStatus::Running
                } else {
                    PlanStatus::Failed
                };
                Ok(response)
            }
            Err(error) => {
                plan.status = PlanStatus::Failed;
                Err(error)
            }
        }
    }

    /// Runs the operation-specific live readback declared by a plan. Unknown
    /// strategy names fail closed rather than silently becoming generic checks.
    pub async fn verify_plan(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.as_str();
        let input: CallInput = serde_json::from_value(plan.input.clone())
            .map_err(cfctl_core::CoreError::Serialization)?;
        validate_verification_preconditions(&plan.capability, &input)?;
        if strategy.starts_with("api_token_details_") {
            let (token_id, expectation) =
                token_verification_target(strategy, &input, apply_response)?;
            let account_scoped = plan.capability.path.starts_with("/accounts/");
            let details_path = if account_scoped {
                "/accounts/{account_id}/tokens/{token_id}"
            } else {
                "/user/tokens/{token_id}"
            };
            let details = CapabilityV1::new(
                "api-token-verification-readback",
                "API token verification readback",
                "GET",
                details_path,
            );
            let selectors = if account_scoped {
                serde_json::json!({"account_id": plan.account_id, "token_id": token_id})
            } else {
                serde_json::json!({"token_id": token_id})
            };
            let request = self.builder.build(
                &details,
                &CallInput {
                    selectors,
                    query: Value::Object(serde_json::Map::new()),
                    body: None,
                    ..CallInput::default()
                },
            )?;
            let readback = self.send(&request, credential).await?;
            let (passed, basis) = evaluate_token_readback(expectation, &token_id, &readback);
            return Ok(OperationVerificationV1 {
                strategy: strategy.to_owned(),
                passed,
                basis,
                readback,
            });
        }

        if strategy.starts_with("dns_record_details_") {
            let (zone_id, record_id, expectation) =
                dns_record_verification_target(strategy, &input, apply_response)?;
            let details = CapabilityV1::new(
                "dns-record-verification-readback",
                "DNS record verification readback",
                "GET",
                "/zones/{zone_id}/dns_records/{dns_record_id}",
            );
            let request = self.builder.build(
                &details,
                &CallInput {
                    selectors: serde_json::json!({
                        "zone_id": zone_id,
                        "dns_record_id": record_id,
                    }),
                    query: Value::Object(serde_json::Map::new()),
                    body: None,
                    ..CallInput::default()
                },
            )?;
            let readback = self.send(&request, credential).await?;
            let (passed, basis) = evaluate_dns_record_readback(
                expectation,
                &record_id,
                input.body.as_ref(),
                apply_response,
                &readback,
            )?;
            return Ok(OperationVerificationV1 {
                strategy: strategy.to_owned(),
                passed,
                basis,
                readback,
            });
        }

        if is_delete_verifier(strategy) {
            return self
                .verify_resource_delete(plan, apply_response, &input, credential)
                .await;
        }
        if is_update_verifier(strategy) {
            return self
                .verify_resource_update(plan, apply_response, &input, credential)
                .await;
        }
        if strategy == "created_resource_contains_planned_fields_by_returned_id" {
            return self
                .verify_created_resource(plan, apply_response, &input, credential)
                .await;
        }

        Err(CloudflareError::UnsupportedVerificationStrategy(
            strategy.to_owned(),
        ))
    }

    async fn verify_resource_delete(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        match plan.capability.verification.strategy.as_str() {
            "same_resource_returns_not_found_after_delete" => {
                self.verify_exact_resource_delete(plan, apply_response, input, credential)
                    .await
            }
            "parent_collection_omits_deleted_resource_id" => {
                self.verify_parent_collection_delete(plan, apply_response, input, credential)
                    .await
            }
            strategy => Err(CloudflareError::UnsupportedVerificationStrategy(
                strategy.to_owned(),
            )),
        }
    }

    async fn verify_exact_resource_delete(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let details = CapabilityV1::new(
            "exact-resource-delete-verification-readback",
            "Exact resource deletion verification readback",
            "GET",
            &plan.capability.path,
        );
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors: input.selectors.clone(),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let passed = apply_response.success && readback.status == 404 && !readback.success;
        let basis = if passed {
            "the exact planned resource path returned not found after deletion".to_owned()
        } else {
            format!(
                "exact resource deletion was not proven (apply success={}, readback HTTP {}, readback success={})",
                apply_response.success, readback.status, readback.success
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
        })
    }

    async fn verify_parent_collection_delete(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan.capability.deleted_resource.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound deleted-resource contract is absent".to_owned(),
            )
        })?;
        let deleted_identity = input
            .selectors
            .get(&target.identity_selector)
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the planned delete selector has no non-empty resource identity".to_owned(),
                )
            })?;
        let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned delete selectors are not an object".to_owned(),
            )
        })?;
        selectors.remove(&target.identity_selector);
        let collection = CapabilityV1::new(
            &target.read_capability_id,
            "Deleted resource collection verification readback",
            "GET",
            &target.collection_path,
        );
        let request = self.builder.build(
            &collection,
            &CallInput {
                selectors: Value::Object(selectors),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send_paginated(&request, credential).await?;
        let pagination_complete =
            collection_pagination_complete(target.requires_page_number_completion, &readback);
        let identities = readback.result.as_array().map(|items| {
            items
                .iter()
                .map(|item| {
                    item.pointer(&target.response_item_identity_pointer)
                        .and_then(Value::as_str)
                        .filter(|identity| !identity.is_empty())
                })
                .collect::<Vec<_>>()
        });
        let identity_shape_valid = identities
            .as_ref()
            .is_some_and(|identities| identities.iter().all(Option::is_some));
        let deleted_identity_absent = identities.as_ref().is_some_and(|identities| {
            identities
                .iter()
                .all(|identity| *identity != Some(deleted_identity))
        });
        let passed = apply_response.success
            && readback.success
            && pagination_complete
            && identity_shape_valid
            && deleted_identity_absent;
        let basis = if passed {
            "the complete schema-proven parent collection omitted the exact deleted resource identity"
                .to_owned()
        } else {
            format!(
                "parent collection did not prove deletion (apply success={}, readback HTTP {}, readback success={}, pagination complete={}, result array={}, item identities valid={}, deleted identity absent={})",
                apply_response.success,
                readback.status,
                readback.success,
                pagination_complete,
                identities.is_some(),
                identity_shape_valid,
                deleted_identity_absent
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
        })
    }

    async fn verify_exact_resource_update(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let planned = input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "planned update body is absent, empty, or not an object".to_owned(),
                )
            })?;
        let details = CapabilityV1::new(
            "exact-resource-update-verification-readback",
            "Exact resource update verification readback",
            "GET",
            &plan.capability.path,
        );
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors: input.selectors.clone(),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let mismatches = mismatched_planned_fields(planned, &readback.result);
        let passed = apply_response.success && readback.success && mismatches.is_empty();
        let basis = if passed {
            "the exact resource readback contained every planned update field".to_owned()
        } else {
            format!(
                "exact resource update was not proven (apply success={}, readback HTTP {}, readback success={}, fields={})",
                apply_response.success,
                readback.status,
                readback.success,
                render_field_names(&mismatches)
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
        })
    }

    async fn verify_resource_update(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        match plan.capability.verification.strategy.as_str() {
            "same_resource_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_update" => {
                self.verify_exact_resource_update(plan, apply_response, input, credential)
                    .await
            }
            "parent_collection_item_contains_planned_fields_after_update" => {
                self.verify_parent_collection_update(plan, apply_response, input, credential)
                    .await
            }
            strategy => Err(CloudflareError::UnsupportedVerificationStrategy(
                strategy.to_owned(),
            )),
        }
    }

    async fn verify_parent_collection_update(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan.capability.updated_resource.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound updated-resource contract is absent".to_owned(),
            )
        })?;
        let updated_identity = input
            .selectors
            .get(&target.identity_selector)
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the planned update selector has no non-empty resource identity".to_owned(),
                )
            })?;
        let planned = input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "planned update body is absent, empty, or not an object".to_owned(),
                )
            })?;
        let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned update selectors are not an object".to_owned(),
            )
        })?;
        selectors.remove(&target.identity_selector);
        let collection = CapabilityV1::new(
            &target.read_capability_id,
            "Updated resource collection verification readback",
            "GET",
            &target.collection_path,
        );
        let request = self.builder.build(
            &collection,
            &CallInput {
                selectors: Value::Object(selectors),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send_paginated(&request, credential).await?;
        let pagination_complete =
            collection_pagination_complete(target.requires_page_number_completion, &readback);
        let items = readback.result.as_array();
        let identity_shape_valid = items.is_some_and(|items| {
            items.iter().all(|item| {
                item.pointer(&target.response_item_identity_pointer)
                    .and_then(Value::as_str)
                    .is_some_and(|identity| !identity.is_empty())
            })
        });
        let matching_items = items
            .into_iter()
            .flatten()
            .filter(|item| {
                item.pointer(&target.response_item_identity_pointer)
                    .and_then(Value::as_str)
                    == Some(updated_identity)
            })
            .collect::<Vec<_>>();
        let planned_fields_match = matching_items
            .first()
            .is_some_and(|item| contains_planned_value(item, &Value::Object(planned.clone())));
        let passed = apply_response.success
            && readback.success
            && pagination_complete
            && identity_shape_valid
            && matching_items.len() == 1
            && planned_fields_match;
        let basis = if passed {
            "the complete schema-proven parent collection contained exactly one matching identity with every planned update field"
                .to_owned()
        } else {
            format!(
                "parent collection did not prove update (apply success={}, readback HTTP {}, readback success={}, pagination complete={}, result array={}, item identities valid={}, identity matches={}, planned fields match={})",
                apply_response.success,
                readback.status,
                readback.success,
                pagination_complete,
                items.is_some(),
                identity_shape_valid,
                matching_items.len(),
                planned_fields_match
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
        })
    }

    async fn verify_created_resource(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
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
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the successful creation response has no non-empty schema-proven identity"
                        .to_owned(),
                )
            })?;
        let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned create selectors are not an object".to_owned(),
            )
        })?;
        selectors.insert(
            target.identity_selector.clone(),
            Value::String(resource_id.to_owned()),
        );
        let details = CapabilityV1::new(
            &target.read_capability_id,
            "Created resource verification readback",
            "GET",
            &target.detail_path,
        );
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
            .and_then(Value::as_str);
        let mismatches = mismatched_planned_fields(planned, &readback.result);
        let passed = apply_response.success
            && readback.success
            && readback_identity == Some(resource_id)
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
                readback_identity == Some(resource_id),
                render_field_names(&mismatches)
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
        })
    }

    async fn send(
        &self,
        request: &PreparedRequest,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|_| CloudflareError::InvalidMethod(request.method.clone()))?;
        let mut attempt = 0;
        loop {
            let mut outgoing = self
                .client
                .request(method.clone(), request.url.clone())
                .headers(request.headers.clone());
            outgoing = apply_credential(outgoing, credential)?;
            if let Some(body) = &request.body {
                outgoing = outgoing.json(body);
            }
            let response = outgoing.send().await?;
            let status = response.status();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1)
                .min(30);
            if (status.as_u16() == 429 || status.is_server_error()) && attempt < self.max_retries {
                attempt += 1;
                sleep(Duration::from_secs(retry_after)).await;
                continue;
            }
            let status_code = status.as_u16();
            let etag = header_text(response.headers(), reqwest::header::ETAG);
            let cf_ray = response
                .headers()
                .get(HeaderName::from_static("cf-ray"))
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let body = response.json::<Value>().await?;
            return Ok(parse_response(status_code, &body, etag, cf_ray));
        }
    }

    async fn send_paginated(
        &self,
        request: &PreparedRequest,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        let mut combined = self.send(request, credential).await?;
        if !combined.success || !request.method.eq_ignore_ascii_case("GET") {
            return Ok(combined);
        }
        let Some((current_page, total_pages)) = pagination_bounds(combined.result_info.as_ref())
        else {
            return Ok(combined);
        };
        if total_pages > 1_000 {
            return Err(CloudflareError::PaginationLimit(total_pages));
        }
        let Some(results) = combined.result.as_array_mut() else {
            return Ok(combined);
        };
        for page in (current_page + 1)..=total_pages {
            let mut page_request = request.clone();
            set_query_parameter(&mut page_request.url, "page", &page.to_string());
            let response = self.send(&page_request, credential).await?;
            if !response.success {
                return Ok(response);
            }
            if let Some(page_results) = response.result.as_array() {
                results.extend(page_results.iter().cloned());
            }
            combined.etag = response.etag;
            combined.cf_ray = response.cf_ray;
        }
        if let Some(result_info) = combined.result_info.as_mut().and_then(Value::as_object_mut) {
            result_info.insert("page".to_owned(), Value::from(total_pages));
            result_info.insert("count".to_owned(), Value::from(results.len()));
        }
        Ok(combined)
    }
}

fn add_conditional_header(
    headers: &mut HeaderMap,
    name: HeaderName,
    value: Option<&String>,
) -> Result<()> {
    if let Some(value) = value {
        headers.insert(
            name,
            HeaderValue::from_str(value).map_err(|_| CloudflareError::InvalidConditionalHeader)?,
        );
    }
    Ok(())
}

fn pagination_bounds(result_info: Option<&Value>) -> Option<(u64, u64)> {
    let result_info = result_info?;
    let current = result_info.get("page").and_then(Value::as_u64).unwrap_or(1);
    let total = result_info.get("total_pages").and_then(Value::as_u64)?;
    (total > current).then_some((current, total))
}

fn collection_pagination_complete(required: bool, readback: &CloudflareResponseV1) -> bool {
    !required
        || readback.result_info.as_ref().is_some_and(|result_info| {
            let page = result_info.get("page").and_then(Value::as_u64);
            let total_pages = result_info.get("total_pages").and_then(Value::as_u64);
            page.is_some_and(|page| page > 0 && Some(page) == total_pages)
        })
}

fn set_query_parameter(url: &mut Url, name: &str, value: &str) {
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != name)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(pairs)
        .append_pair(name, value);
}

fn header_text(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn apply_credential(
    request: reqwest::RequestBuilder,
    credential: &AuthCredential,
) -> Result<reqwest::RequestBuilder> {
    if let Some(token) = credential.bearer_token() {
        let value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| CloudflareError::InvalidAuthenticationHeader)?;
        return Ok(request.header(reqwest::header::AUTHORIZATION, value));
    }
    let email = credential
        .global_email()
        .ok_or(CloudflareError::InvalidAuthenticationHeader)?;
    let key = credential
        .global_key()
        .ok_or(CloudflareError::InvalidAuthenticationHeader)?;
    let email_value =
        HeaderValue::from_str(email).map_err(|_| CloudflareError::InvalidAuthenticationHeader)?;
    let key_value =
        HeaderValue::from_str(key).map_err(|_| CloudflareError::InvalidAuthenticationHeader)?;
    Ok(request
        .header(HeaderName::from_static("x-auth-email"), email_value)
        .header(HeaderName::from_static("x-auth-key"), key_value))
}

fn parse_response(
    status: u16,
    body: &Value,
    etag: Option<String>,
    cf_ray: Option<String>,
) -> CloudflareResponseV1 {
    let errors = body
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|error| CloudflareApiErrorV1 {
            code: error.get("code").and_then(Value::as_i64),
            message: error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Cloudflare returned an unspecified error")
                .to_owned(),
        })
        .collect();
    CloudflareResponseV1 {
        status,
        success: body
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or((200..300).contains(&status)),
        result: body.get("result").cloned().unwrap_or(Value::Null),
        errors,
        result_info: body.get("result_info").cloned(),
        etag,
        cf_ray,
    }
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenVerificationExpectation {
    Active,
    Revoked,
}

fn token_verification_target(
    strategy: &str,
    input: &CallInput,
    apply_response: &CloudflareResponseV1,
) -> Result<(String, TokenVerificationExpectation)> {
    match strategy {
        "api_token_details_match_created_id_and_active_status" => apply_response
            .result
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(|token_id| (token_id.to_owned(), TokenVerificationExpectation::Active))
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget("created token id is absent".to_owned())
            }),
        "api_token_details_report_active_after_value_roll" => {
            planned_token_id(input).map(|token_id| (token_id, TokenVerificationExpectation::Active))
        }
        "api_token_details_returns_not_found_after_revoke" => planned_token_id(input)
            .map(|token_id| (token_id, TokenVerificationExpectation::Revoked)),
        other => Err(CloudflareError::UnsupportedVerificationStrategy(
            other.to_owned(),
        )),
    }
}

fn planned_token_id(input: &CallInput) -> Result<String> {
    input
        .selectors
        .get("token_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned token_id selector is absent".to_owned(),
            )
        })
}

fn evaluate_token_readback(
    expectation: TokenVerificationExpectation,
    token_id: &str,
    readback: &CloudflareResponseV1,
) -> (bool, String) {
    match expectation {
        TokenVerificationExpectation::Active => {
            let readback_id = readback.result.get("id").and_then(Value::as_str);
            let readback_status = readback.result.get("status").and_then(Value::as_str);
            let passed = readback.success
                && readback_id == Some(token_id)
                && readback_status == Some("active");
            let basis = if passed {
                format!("live token details matched `{token_id}` with active status")
            } else {
                format!(
                    "live token details did not match active token `{token_id}` (status {}, id {})",
                    readback_status.unwrap_or("missing"),
                    readback_id.unwrap_or("missing")
                )
            };
            (passed, basis)
        }
        TokenVerificationExpectation::Revoked => {
            let passed = readback.status == 404 && !readback.success;
            let basis = if passed {
                format!("live token details returned not found for revoked token `{token_id}`")
            } else {
                format!(
                    "revoked token `{token_id}` still produced HTTP {} with success={}",
                    readback.status, readback.success
                )
            };
            (passed, basis)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsRecordVerificationExpectation {
    MatchesPlannedFields,
    Deleted,
}

fn dns_record_verification_target(
    strategy: &str,
    input: &CallInput,
    apply_response: &CloudflareResponseV1,
) -> Result<(String, String, DnsRecordVerificationExpectation)> {
    let zone_id = planned_selector(input, "zone_id")?;
    match strategy {
        "dns_record_details_match_created_id_and_planned_fields" => apply_response
            .result
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(|record_id| {
                (
                    zone_id,
                    record_id.to_owned(),
                    DnsRecordVerificationExpectation::MatchesPlannedFields,
                )
            })
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "created DNS record id is absent".to_owned(),
                )
            }),
        "dns_record_details_match_planned_id_and_fields" => Ok((
            zone_id,
            planned_selector(input, "dns_record_id")?,
            DnsRecordVerificationExpectation::MatchesPlannedFields,
        )),
        "dns_record_details_returns_not_found_after_delete" => Ok((
            zone_id,
            planned_selector(input, "dns_record_id")?,
            DnsRecordVerificationExpectation::Deleted,
        )),
        other => Err(CloudflareError::UnsupportedVerificationStrategy(
            other.to_owned(),
        )),
    }
}

fn planned_selector(input: &CallInput, name: &str) -> Result<String> {
    input
        .selectors
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(format!("planned {name} selector is absent"))
        })
}

fn evaluate_dns_record_readback(
    expectation: DnsRecordVerificationExpectation,
    record_id: &str,
    planned_body: Option<&Value>,
    apply_response: &CloudflareResponseV1,
    readback: &CloudflareResponseV1,
) -> Result<(bool, String)> {
    if expectation == DnsRecordVerificationExpectation::Deleted {
        let passed = readback.status == 404 && !readback.success;
        let basis = if passed {
            format!("live DNS record details returned not found for deleted record `{record_id}`")
        } else {
            format!(
                "deleted DNS record `{record_id}` still produced HTTP {} with success={}",
                readback.status, readback.success
            )
        };
        return Ok((passed, basis));
    }

    let planned = planned_body.and_then(Value::as_object).ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "planned DNS record request body is absent or not an object".to_owned(),
        )
    })?;
    let apply_id = apply_response.result.get("id").and_then(Value::as_str);
    let readback_id = readback.result.get("id").and_then(Value::as_str);
    let apply_mismatches = mismatched_planned_fields(planned, &apply_response.result);
    let readback_mismatches = mismatched_planned_fields(planned, &readback.result);
    let passed = apply_response.success
        && readback.success
        && apply_id == Some(record_id)
        && readback_id == Some(record_id)
        && apply_mismatches.is_empty()
        && readback_mismatches.is_empty();
    let basis = if passed {
        format!(
            "mutation response and live DNS record details matched record `{record_id}` and every planned field"
        )
    } else {
        format!(
            "DNS record `{record_id}` verification mismatch (apply success={}, apply id={}, readback success={}, readback id={}, apply fields={}, readback fields={})",
            apply_response.success,
            apply_id.unwrap_or("missing"),
            readback.success,
            readback_id.unwrap_or("missing"),
            render_field_names(&apply_mismatches),
            render_field_names(&readback_mismatches),
        )
    };
    Ok((passed, basis))
}

fn mismatched_planned_fields(
    planned: &serde_json::Map<String, Value>,
    actual: &Value,
) -> Vec<String> {
    planned
        .iter()
        .filter(|(name, planned_value)| {
            actual
                .get(name.as_str())
                .is_none_or(|actual_value| !contains_planned_value(actual_value, planned_value))
        })
        .map(|(name, _)| name.clone())
        .collect()
}

fn contains_planned_value(actual: &Value, planned: &Value) -> bool {
    match (actual, planned) {
        (Value::Object(actual), Value::Object(planned)) => planned.iter().all(|(name, value)| {
            actual
                .get(name)
                .is_some_and(|actual_value| contains_planned_value(actual_value, value))
        }),
        _ => actual == planned,
    }
}

fn render_field_names(fields: &[String]) -> String {
    if fields.is_empty() {
        "none".to_owned()
    } else {
        fields.join(",")
    }
}

fn validate_verification_preconditions(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let strategy = capability.verification.strategy.as_str();
    if !capability.verification_contract_supported() {
        return Err(CloudflareError::UnsupportedVerificationStrategy(
            strategy.to_owned(),
        ));
    }
    let body_label = match strategy {
        "created_resource_contains_planned_fields_by_returned_id"
        | "dns_record_details_match_created_id_and_planned_fields" => Some("create"),
        "same_resource_contains_planned_fields_after_update"
        | "same_path_result_contains_planned_fields_after_update"
        | "parent_collection_item_contains_planned_fields_after_update"
        | "dns_record_details_match_planned_id_and_fields" => Some("update"),
        _ => None,
    };
    if let Some(label) = body_label {
        input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(format!(
                    "planned {label} body is absent, empty, or not an object"
                ))
            })?;
    }
    match strategy {
        "created_resource_contains_planned_fields_by_returned_id" => {
            validate_created_resource_target(capability)
        }
        "parent_collection_omits_deleted_resource_id" => {
            validate_deleted_resource_target(capability, input)
        }
        "parent_collection_item_contains_planned_fields_after_update" => {
            validate_updated_resource_target(capability, input)
        }
        _ => Ok(()),
    }
}

fn validate_created_resource_target(capability: &CapabilityV1) -> Result<()> {
    let target = capability.created_resource.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound created-resource contract is absent".to_owned(),
        )
    })?;
    let expected_suffix = format!("/{{{}}}", target.identity_selector);
    if target.identity_selector.is_empty()
        || !target.detail_path.ends_with(&expected_suffix)
        || !target.response_result_identity_pointer.starts_with('/')
        || target.read_capability_id.is_empty()
        || target.delete_capability_id.is_empty()
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the hash-bound created-resource contract is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_deleted_resource_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let target = capability.deleted_resource.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound deleted-resource contract is absent".to_owned(),
        )
    })?;
    let expected_path = format!(
        "{}/{{{}}}",
        target.collection_path.trim_end_matches('/'),
        target.identity_selector
    );
    if target.identity_selector.is_empty()
        || capability.path != expected_path
        || target.response_item_identity_pointer != "/id"
        || target.read_capability_id.is_empty()
        || input
            .selectors
            .get(&target.identity_selector)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the hash-bound deleted-resource contract is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_updated_resource_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let target = capability.updated_resource.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound updated-resource contract is absent".to_owned(),
        )
    })?;
    let expected_path = format!(
        "{}/{{{}}}",
        target.collection_path.trim_end_matches('/'),
        target.identity_selector
    );
    if target.identity_selector.is_empty()
        || capability.path != expected_path
        || target.response_item_identity_pointer != "/id"
        || target.read_capability_id.is_empty()
        || input
            .selectors
            .get(&target.identity_selector)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the hash-bound updated-resource contract is malformed".to_owned(),
        ));
    }
    let Some(planned) = input.body.as_ref().and_then(Value::as_object) else {
        return Err(CloudflareError::MissingVerificationTarget(
            "planned update body is absent, empty, or not an object".to_owned(),
        ));
    };
    if planned.keys().any(|field| {
        target
            .verified_response_fields
            .binary_search(field)
            .is_err()
    }) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned update contains a field outside the hash-bound collection readback fields"
                .to_owned(),
        ));
    }
    Ok(())
}

fn is_update_verifier(strategy: &str) -> bool {
    matches!(
        strategy,
        "same_resource_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_update"
            | "parent_collection_item_contains_planned_fields_after_update"
    )
}

fn is_delete_verifier(strategy: &str) -> bool {
    matches!(
        strategy,
        "same_resource_returns_not_found_after_delete"
            | "parent_collection_omits_deleted_resource_id"
    )
}

fn validate_request_body(capability: &CapabilityV1, body: Option<&Value>) -> Result<()> {
    let Some(schema) = capability.request_schema.as_ref() else {
        return Ok(());
    };
    if body.is_none()
        && schema
            .get("x-cfctl-body-required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err(CloudflareError::MissingRequestBody(capability.id.clone()));
    }
    let Some(body) = body else {
        return Ok(());
    };
    if let Some(expected) = schema.get("type").and_then(Value::as_str)
        && !json_type_matches(body, expected)
    {
        return Err(CloudflareError::InvalidRequestBody(format!(
            "expected top-level {expected}"
        )));
    }
    let Some(object) = body.as_object() else {
        return Ok(());
    };
    for required in schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !object.contains_key(required) {
            return Err(CloudflareError::InvalidRequestBody(format!(
                "missing required property `{required}`"
            )));
        }
    }
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return Ok(());
    };
    for (name, value) in object {
        let Some(expected) = properties
            .get(name)
            .and_then(|property| property.get("type"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        if !json_type_matches(value, expected) {
            return Err(CloudflareError::InvalidRequestBody(format!(
                "property `{name}` must be {expected}"
            )));
        }
    }
    Ok(())
}

fn json_type_matches(value: &Value, expected: &str) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true,
    }
}
