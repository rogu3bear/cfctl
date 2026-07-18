//! Typed Cloudflare request construction and governed execution.

use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use cfctl_auth::AuthCredential;
use cfctl_core::{
    CapabilityV1, PlanStatus, PlanV1, ResponseBodyModeV1, ResponseContractV1, SelectorV1,
    request_header_is_reserved,
};
use chrono::{DateTime, Utc};
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
    #[error("catalog header selector `{0}` is required")]
    MissingHeaderSelector(String),
    #[error("selector `{0}` must be a string, number, or boolean")]
    InvalidSelector(String),
    #[error(
        "selector input must be an object of catalog-declared path, header, or target controls"
    )]
    InvalidSelectorObject,
    #[error("selector `{0}` is not declared by the catalog capability or request path")]
    UndeclaredSelector(String),
    #[error("catalog selector `{name}` does not satisfy its pinned schema: {reason}")]
    InvalidSelectorSchema { name: String, reason: String },
    #[error("query input must be an object of catalog-declared controls")]
    InvalidQueryObject,
    #[error("query control `{0}` is not declared by the catalog capability")]
    UndeclaredQuerySelector(String),
    #[error("catalog query control `{0}` is required")]
    MissingQuerySelector(String),
    #[error("catalog query control `{name}` must have type `{expected}`")]
    InvalidQuerySelector { name: String, expected: String },
    #[error("catalog query control `{name}` does not satisfy its pinned schema: {reason}")]
    InvalidQuerySelectorSchema { name: String, reason: String },
    #[error("catalog query control `{name}` uses unsupported serialization: {reason}")]
    UnsupportedQuerySerialization { name: String, reason: String },
    #[error("required request body is missing for capability `{0}`")]
    MissingRequestBody(String),
    #[error("request body does not satisfy the pinned schema: {0}")]
    InvalidRequestBody(String),
    #[error("catalog response contract is unsupported by the executor: {0}")]
    UnsupportedResponseContract(String),
    #[error(
        "Cloudflare returned HTTP {status} with response media `{received}`, which does not match the pinned application/json contract"
    )]
    UnexpectedResponseMediaType { status: u16, received: String },
    #[error("Cloudflare returned HTTP {status} without the pinned JSON success envelope")]
    InvalidResponseEnvelope { status: u16 },
    #[error(
        "Cloudflare returned successful HTTP {status}, which is not in the pinned response statuses: {expected}"
    )]
    UnexpectedSuccessStatus { status: u16, expected: String },
    #[error(
        "Cloudflare returned HTTP {status} with {received_bytes} body bytes despite the pinned empty response contract"
    )]
    UnexpectedResponseBody { status: u16, received_bytes: usize },
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
    #[error("catalog header selector `{0}` is reserved and cannot be set through selectors")]
    ReservedHeaderSelector(String),
    #[error("catalog header selector `{0}` has an invalid name or value")]
    InvalidHeaderSelector(String),
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
    pub response_contract: Option<ResponseContractV1>,
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
        validate_request_contract(capability, input)?;
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
                let selector = capability
                    .selectors
                    .iter()
                    .find(|selector| selector.location == "query" && selector.name == *key)
                    .ok_or_else(|| CloudflareError::UndeclaredQuerySelector(key.clone()))?;
                let (explode, _) = validated_query_serialization(selector)?;
                match value {
                    Value::Array(values) => {
                        let rendered = values
                            .iter()
                            .map(scalar)
                            .collect::<Option<Vec<_>>>()
                            .ok_or_else(|| CloudflareError::InvalidQuerySelector {
                                name: key.clone(),
                                expected: selector.value_type.clone(),
                            })?;
                        if rendered.is_empty() {
                            pairs.append_pair(key, "");
                        } else if explode {
                            for rendered in rendered {
                                pairs.append_pair(key, &rendered);
                            }
                        } else {
                            pairs.append_pair(key, &rendered.join(","));
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
        add_declared_header_selectors(&mut headers, capability, selectors)?;
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
            response_contract: capability.response_contract.clone(),
        })
    }
}

fn add_declared_header_selectors(
    headers: &mut HeaderMap,
    capability: &CapabilityV1,
    selectors: Option<&serde_json::Map<String, Value>>,
) -> Result<()> {
    for selector in capability
        .selectors
        .iter()
        .filter(|selector| selector.location == "header")
    {
        let Some(value) = selectors.and_then(|values| values.get(&selector.name)) else {
            if selector.required {
                return Err(CloudflareError::MissingHeaderSelector(
                    selector.name.clone(),
                ));
            }
            continue;
        };
        if request_header_is_reserved(&selector.name) {
            return Err(CloudflareError::ReservedHeaderSelector(
                selector.name.clone(),
            ));
        }
        let rendered = if selector.name == "cf-r2-jurisdiction" {
            value.as_str().map(str::to_owned)
        } else {
            scalar(value)
        }
        .ok_or_else(|| CloudflareError::InvalidHeaderSelector(selector.name.clone()))?;
        let name = HeaderName::from_bytes(selector.name.as_bytes())
            .map_err(|_| CloudflareError::InvalidHeaderSelector(selector.name.clone()))?;
        let value = HeaderValue::from_str(&rendered)
            .map_err(|_| CloudflareError::InvalidHeaderSelector(selector.name.clone()))?;
        headers.insert(name, value);
    }
    Ok(())
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
        let input: CallInput = serde_json::from_value(plan.input.clone())
            .map_err(cfctl_core::CoreError::Serialization)?;
        self.verify_plan_with_input(plan, apply_response, &input, credential)
            .await
    }

    /// Runs the operation-specific verifier with the exact execution input
    /// already validated by the caller. This lane is required for secret
    /// request bodies because the durable plan contains only a hash-bound
    /// credential-store reference, never the value-bearing body.
    pub async fn verify_plan_with_input(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.as_str();
        validate_verification_preconditions(&plan.capability, input)?;
        if strategy.starts_with("api_token_details_") {
            return self
                .verify_api_token(plan, apply_response, input, credential)
                .await;
        }

        if strategy.starts_with("dns_record_details_") {
            return self
                .verify_dns_record(plan, apply_response, input, credential)
                .await;
        }

        if strategy.starts_with("oauth_client_") {
            return self
                .verify_oauth_client_secret_rotation(plan, apply_response, input, credential)
                .await;
        }

        if strategy == "worker_script_secret_reports_planned_name_and_type_after_put" {
            return self
                .verify_worker_script_secret_put(plan, apply_response, input, credential)
                .await;
        }

        if strategy == "access_service_token_reports_refreshed_expiration" {
            return self
                .verify_access_service_token_refresh(plan, apply_response, input, credential)
                .await;
        }

        if strategy == "cache_purge_response_reports_target_zone_id" {
            return self.verify_cache_purge(plan, apply_response, input);
        }

        if strategy == "email_routing_settings_response_reports_enabled_state" {
            return self.verify_email_routing_settings(plan, apply_response);
        }

        if is_delete_verifier(strategy) {
            return self
                .verify_resource_delete(plan, apply_response, input, credential)
                .await;
        }
        if is_update_verifier(strategy) {
            return self
                .verify_resource_update(plan, apply_response, input, credential)
                .await;
        }
        if is_create_verifier(strategy) {
            return self
                .verify_resource_create(plan, apply_response, input, credential)
                .await;
        }

        Err(CloudflareError::UnsupportedVerificationStrategy(
            strategy.to_owned(),
        ))
    }

    async fn verify_api_token(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.as_str();
        let (token_id, expectation) = token_verification_target(strategy, input, apply_response)?;
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
        Ok(OperationVerificationV1 {
            strategy: strategy.to_owned(),
            passed,
            basis,
            readback,
        })
    }

    /// Verifies a cache purge by asserting Cloudflare accepted the request and
    /// echoed the target zone id in `result.id`. There is no readback that can
    /// prove cache eviction, so this is deliberately a no-readback verifier:
    /// the `apply_response` itself is the evidence, and the basis states plainly
    /// that it proves acceptance and scoping, not eviction.
    // Takes `&self` to sit uniformly beside the async `verify_*` siblings the
    // dispatcher calls as methods, though this no-readback verifier needs no
    // client state of its own.
    #[allow(clippy::unused_self)]
    fn verify_cache_purge(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.clone();
        let zone_id = input
            .selectors
            .as_object()
            .and_then(|selectors| selectors.get("zone_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the planned cache purge zone_id selector is absent".to_owned(),
                )
            })?;
        let returned_id = apply_response.result.pointer("/id").and_then(Value::as_str);
        let (passed, basis) = match returned_id {
            Some(id) if id == zone_id => (
                true,
                format!(
                    "Cloudflare accepted the cache purge and echoed the target zone id `{zone_id}` in result.id; this proves the purge was accepted and scoped to the target zone, not that cached content was evicted (no readback can verify eviction)"
                ),
            ),
            Some(id) => (
                false,
                format!(
                    "cache purge response reported zone id `{id}`, which does not match the target zone `{zone_id}`; the purge scope cannot be confirmed"
                ),
            ),
            None => (
                false,
                "cache purge response did not report a result.id; acceptance and scope cannot be confirmed".to_owned(),
            ),
        };
        Ok(OperationVerificationV1 {
            strategy,
            passed,
            basis,
            readback: apply_response.clone(),
        })
    }

    /// Verifies an Email Routing enable/disable toggle by asserting the settings
    /// object the action endpoint returns reports `enabled` at the intended
    /// value (`true` for enable, `false` for disable). Like the cache-purge
    /// verifier this is deliberately a no-readback verifier: the `apply_response`
    /// is the evidence, and the basis states plainly it proves the setting now
    /// reports the intended value, not that MX/DNS propagation or live mail
    /// delivery has converged.
    // Takes `&self` to sit uniformly beside the async `verify_*` siblings the
    // dispatcher calls as methods, though this no-readback verifier needs no
    // client state of its own.
    #[allow(clippy::unused_self)]
    fn verify_email_routing_settings(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.clone();
        let expected_enabled = match plan.capability.id.as_str() {
            "email-routing-settings-enable-email-routing" => true,
            "email-routing-settings-disable-email-routing" => false,
            other => {
                return Err(CloudflareError::MissingVerificationTarget(format!(
                    "the Email Routing settings verifier is bound to an unexpected capability `{other}`"
                )));
            }
        };
        let reported = apply_response
            .result
            .pointer("/enabled")
            .and_then(Value::as_bool);
        let (passed, basis) = match reported {
            Some(state) if state == expected_enabled => (
                true,
                format!(
                    "Cloudflare accepted the request and its Email Routing settings response reports enabled={state}, matching the intended state; this proves the routing setting now reports the target value, not that MX/DNS propagation or live mail delivery has converged"
                ),
            ),
            Some(state) => (
                false,
                format!(
                    "Email Routing settings response reports enabled={state}, but the operation intended enabled={expected_enabled}; the setting change cannot be confirmed"
                ),
            ),
            None => (
                false,
                "Email Routing settings response did not report a boolean result.enabled; the setting change cannot be confirmed".to_owned(),
            ),
        };
        Ok(OperationVerificationV1 {
            strategy,
            passed,
            basis,
            readback: apply_response.clone(),
        })
    }

    async fn verify_worker_script_secret_put(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan.capability.same_path_read.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound Worker script secret readback contract is absent".to_owned(),
            )
        })?;
        let body = input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the planned Worker script secret body is absent or not an object".to_owned(),
                )
            })?;
        let secret_name = body.get("name").and_then(Value::as_str).ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the planned Worker script secret name is absent".to_owned(),
            )
        })?;
        let secret_type = body.get("type").and_then(Value::as_str).ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the planned Worker script secret type is absent".to_owned(),
            )
        })?;
        let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the planned Worker script selectors are not an object".to_owned(),
            )
        })?;
        selectors.insert(
            "secret_name".to_owned(),
            Value::String(secret_name.to_owned()),
        );
        let details = same_path_verification_capability(
            &plan.capability,
            &target.read_capability_id,
            "Worker script secret verification readback",
            &target.path,
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
        let (passed, basis) = evaluate_worker_script_secret_put_readback(
            secret_name,
            secret_type,
            apply_response,
            &readback,
        );
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
        })
    }

    async fn verify_dns_record(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.as_str();
        let (zone_id, record_id, expectation) =
            dns_record_verification_target(strategy, input, apply_response)?;
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
        Ok(OperationVerificationV1 {
            strategy: strategy.to_owned(),
            passed,
            basis,
            readback,
        })
    }

    async fn verify_oauth_client_secret_rotation(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.as_str();
        let target = plan.capability.same_path_read.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound OAuth client detail readback contract is absent".to_owned(),
            )
        })?;
        let oauth_client_id = input
            .selectors
            .get("oauth_client_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the planned OAuth client selector is absent or empty".to_owned(),
                )
            })?;
        let details = same_path_verification_capability(
            &plan.capability,
            &target.read_capability_id,
            "OAuth client secret rotation verification readback",
            &target.path,
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
        let (passed, basis) = evaluate_oauth_client_secret_readback(
            strategy,
            oauth_client_id,
            apply_response,
            &readback,
        )?;
        Ok(OperationVerificationV1 {
            strategy: strategy.to_owned(),
            passed,
            basis,
            readback,
        })
    }

    async fn verify_access_service_token_refresh(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan.capability.same_path_read.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound Access service-token detail readback contract is absent".to_owned(),
            )
        })?;
        let service_token_id = input
            .selectors
            .get("service_token_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the planned Access service-token selector is absent or empty".to_owned(),
                )
            })?;
        let details = same_path_verification_capability(
            &plan.capability,
            &target.read_capability_id,
            "Access service-token refresh verification readback",
            &target.path,
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
        let (passed, basis) = evaluate_access_service_token_refresh_readback(
            service_token_id,
            apply_response,
            &readback,
        );
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
        })
    }

    async fn verify_resource_create(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        match plan.capability.verification.strategy.as_str() {
            "created_resource_contains_planned_fields_by_returned_id" => {
                self.verify_created_resource(plan, apply_response, input, credential)
                    .await
            }
            "parent_collection_contains_created_resource_id_and_planned_fields" => {
                self.verify_created_collection_resource(plan, apply_response, input, credential)
                    .await
            }
            strategy => Err(CloudflareError::UnsupportedVerificationStrategy(
                strategy.to_owned(),
            )),
        }
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
        let target = plan.capability.same_path_read.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound same-path delete readback contract is absent".to_owned(),
            )
        })?;
        let details = same_path_verification_capability(
            &plan.capability,
            &target.read_capability_id,
            "Exact resource deletion verification readback",
            &target.path,
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
        let operation = if plan.capability.verification.strategy
            == "same_path_result_contains_planned_fields_after_mutation"
        {
            "mutation"
        } else {
            "update"
        };
        let target = plan.capability.same_path_read.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(format!(
                "the hash-bound same-path {operation} readback contract is absent"
            ))
        })?;
        let planned = input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(format!(
                    "planned {operation} body is absent, empty, or not an object"
                ))
            })?;
        let readback_title = format!("Exact resource {operation} verification readback");
        let details = same_path_verification_capability(
            &plan.capability,
            &target.read_capability_id,
            &readback_title,
            &target.path,
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
        let mismatches =
            mismatched_verifiable_planned_fields(&plan.capability, planned, &readback.result);
        let passed = apply_response.success && readback.success && mismatches.is_empty();
        let basis = if passed {
            format!("the exact resource readback contained every planned {operation} field")
        } else {
            format!(
                "exact resource {operation} was not proven (apply success={}, readback HTTP {}, readback success={}, fields={})",
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
            | "same_path_result_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_mutation" => {
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
        let planned_fields_match = matching_items.first().is_some_and(|item| {
            mismatched_verifiable_planned_fields(&plan.capability, planned, item).is_empty()
        });
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
            .and_then(Value::as_str);
        let mut mismatches =
            mismatched_verifiable_planned_fields(&plan.capability, planned, &readback.result);
        extend_r2_bucket_create_mismatches(plan, input, &readback.result, &mut mismatches);
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

    async fn verify_created_collection_resource(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan
            .capability
            .created_collection_resource
            .as_ref()
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the hash-bound created-collection-resource contract is absent".to_owned(),
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
        let collection = CapabilityV1::new(
            &target.read_capability_id,
            "Created resource collection verification readback",
            "GET",
            &target.collection_path,
        );
        let request = self.builder.build(
            &collection,
            &CallInput {
                selectors: input.selectors.clone(),
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
                    == Some(resource_id)
            })
            .collect::<Vec<_>>();
        let planned_fields_match = matching_items.first().is_some_and(|item| {
            mismatched_verifiable_planned_fields(&plan.capability, planned, item).is_empty()
        });
        let passed = apply_response.success
            && readback.success
            && pagination_complete
            && identity_shape_valid
            && matching_items.len() == 1
            && planned_fields_match;
        let basis = if passed {
            "the complete schema-proven parent collection contained exactly one returned creation identity with every planned field"
                .to_owned()
        } else {
            format!(
                "parent collection did not prove creation (apply success={}, readback HTTP {}, readback success={}, pagination complete={}, result array={}, item identities valid={}, identity matches={}, planned fields match={})",
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
            let content_type = header_text(response.headers(), reqwest::header::CONTENT_TYPE);
            if status.is_success()
                && let Some(contract) = request.response_contract.as_ref()
            {
                if !contract.success_statuses.is_empty()
                    && !contract
                        .success_statuses
                        .iter()
                        .any(|expected| response_status_matches(expected, status_code))
                {
                    return Err(CloudflareError::UnexpectedSuccessStatus {
                        status: status_code,
                        expected: contract.success_statuses.join(", "),
                    });
                }
                match contract.body_mode {
                    ResponseBodyModeV1::CloudflareJsonEnvelope => {
                        if !content_type.as_deref().is_some_and(is_application_json) {
                            return Err(CloudflareError::UnexpectedResponseMediaType {
                                status: status_code,
                                received: content_type.unwrap_or_else(|| "missing".to_owned()),
                            });
                        }
                        let body = response.json::<Value>().await?;
                        if body.get("success").and_then(Value::as_bool).is_none() {
                            return Err(CloudflareError::InvalidResponseEnvelope {
                                status: status_code,
                            });
                        }
                        return Ok(parse_response(status_code, &body, etag, cf_ray));
                    }
                    ResponseBodyModeV1::Empty => {
                        let body = response.bytes().await?;
                        if !body.is_empty() {
                            return Err(CloudflareError::UnexpectedResponseBody {
                                status: status_code,
                                received_bytes: body.len(),
                            });
                        }
                        return Ok(parse_response(status_code, &Value::Null, etag, cf_ray));
                    }
                    ResponseBodyModeV1::Unsupported => {}
                }
            }
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

fn is_application_json(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
}

fn response_status_matches(expected: &str, received: u16) -> bool {
    if expected.parse::<u16>() == Ok(received) {
        return true;
    }
    let expected = expected.as_bytes();
    let received = received.to_string();
    expected.len() == received.len()
        && expected
            .iter()
            .zip(received.as_bytes())
            .all(|(expected, received)| {
                expected.eq_ignore_ascii_case(&b'X') || expected == received
            })
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

fn mismatched_verifiable_planned_fields(
    capability: &CapabilityV1,
    planned: &serde_json::Map<String, Value>,
    actual: &Value,
) -> Vec<String> {
    let schema = capability.request_schema.as_ref();
    planned
        .iter()
        .filter(|(name, planned_value)| {
            let mut path = vec![RequestSchemaPathStep::Property((*name).clone())];
            let response_field =
                verification_response_field(capability, name).unwrap_or_else(|| (*name).clone());
            !contains_verifiable_planned_value(
                actual.get(response_field.as_str()),
                planned_value,
                schema,
                &mut path,
                0,
            )
        })
        .map(|(name, _)| name.clone())
        .collect()
}

fn verification_response_field(capability: &CapabilityV1, request_field: &str) -> Option<String> {
    if capability.id != "r2-create-bucket"
        || capability.method != "POST"
        || capability.product != "R2 Bucket"
        || capability.path != "/accounts/{account_id}/r2/buckets"
        || request_field != "storageClass"
    {
        return None;
    }
    capability
        .request_object_field_verification_response_field(request_field)
        .filter(|response_field| response_field == "storage_class")
}

fn extend_r2_bucket_create_mismatches(
    plan: &PlanV1,
    input: &CallInput,
    actual: &Value,
    mismatches: &mut Vec<String>,
) {
    if plan.capability.id != "r2-create-bucket"
        || plan.capability.product != "R2 Bucket"
        || plan.capability.path != "/accounts/{account_id}/r2/buckets"
    {
        return;
    }
    if input
        .selectors
        .get("cf-r2-jurisdiction")
        .is_some_and(|planned_jurisdiction| {
            actual.get("jurisdiction") != Some(planned_jurisdiction)
        })
    {
        mismatches.push("cf-r2-jurisdiction".to_owned());
    }
    mismatches.sort();
    mismatches.dedup();
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestSchemaPathStep {
    Property(String),
    Item,
}

fn contains_verifiable_planned_value(
    actual: Option<&Value>,
    planned: &Value,
    schema: Option<&Value>,
    path: &mut Vec<RequestSchemaPathStep>,
    depth: usize,
) -> bool {
    if depth > MAX_REQUEST_VALIDATION_DEPTH {
        return false;
    }
    if schema.is_some_and(|schema| request_schema_path_is_verification_omitted(schema, path)) {
        return true;
    }
    let Some(actual) = actual else {
        return false;
    };
    match (actual, planned) {
        (Value::Object(actual), Value::Object(planned)) => planned.iter().all(|(name, value)| {
            path.push(RequestSchemaPathStep::Property(name.clone()));
            let matches =
                contains_verifiable_planned_value(actual.get(name), value, schema, path, depth + 1);
            path.pop();
            matches
        }),
        (Value::Array(actual), Value::Array(planned)) => {
            if actual.len() != planned.len() {
                return false;
            }
            path.push(RequestSchemaPathStep::Item);
            let matches = actual.iter().zip(planned).all(|(actual, planned)| {
                contains_verifiable_planned_value(Some(actual), planned, schema, path, depth + 1)
            });
            path.pop();
            matches
        }
        _ => actual == planned,
    }
}

fn request_schema_path_is_verification_omitted(
    schema: &Value,
    path: &[RequestSchemaPathStep],
) -> bool {
    let mut remaining_steps = MAX_REQUEST_SCHEMA_PROJECTION_STEPS;
    let Some(candidates) = request_schema_path_candidates(schema, path, 0, &mut remaining_steps)
    else {
        return false;
    };
    !candidates.is_empty()
        && candidates.iter().all(|candidate| {
            schema_declares_verification_omitted(candidate, 0, &mut remaining_steps)
        })
}

const MAX_REQUEST_SCHEMA_PROJECTION_STEPS: usize = 4_096;

fn request_schema_path_candidates<'a>(
    schema: &'a Value,
    path: &[RequestSchemaPathStep],
    depth: usize,
    remaining_steps: &mut usize,
) -> Option<Vec<&'a Value>> {
    if depth > MAX_REQUEST_VALIDATION_DEPTH || *remaining_steps == 0 {
        return None;
    }
    *remaining_steps -= 1;
    let Some((step, remaining)) = path.split_first() else {
        return Some(vec![schema]);
    };
    let mut candidates = Vec::new();
    let child = match step {
        RequestSchemaPathStep::Property(name) => schema
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(name)),
        RequestSchemaPathStep::Item => schema.get("items"),
    };
    if let Some(child) = child {
        candidates.extend(request_schema_path_candidates(
            child,
            remaining,
            depth + 1,
            remaining_steps,
        )?);
    }
    for composition in ["allOf", "oneOf", "anyOf"] {
        for member in schema
            .get(composition)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            candidates.extend(request_schema_path_candidates(
                member,
                path,
                depth + 1,
                remaining_steps,
            )?);
        }
    }
    Some(candidates)
}

fn schema_declares_verification_omitted(
    schema: &Value,
    depth: usize,
    remaining_steps: &mut usize,
) -> bool {
    if depth > MAX_REQUEST_VALIDATION_DEPTH || *remaining_steps == 0 {
        return false;
    }
    *remaining_steps -= 1;
    if schema.get("writeOnly").and_then(Value::as_bool) == Some(true)
        || schema
            .get("x-cfctl-verification-observable")
            .and_then(Value::as_bool)
            == Some(false)
    {
        return true;
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members.iter().any(|member| {
                schema_declares_verification_omitted(member, depth + 1, remaining_steps)
            })
        })
    {
        return true;
    }
    ["oneOf", "anyOf"].iter().any(|composition| {
        schema
            .get(*composition)
            .and_then(Value::as_array)
            .is_some_and(|members| {
                !members.is_empty()
                    && members.iter().all(|member| {
                        schema_declares_verification_omitted(member, depth + 1, remaining_steps)
                    })
            })
    })
}

#[cfg(test)]
mod request_schema_projection_tests {
    use super::{RequestSchemaPathStep, request_schema_path_is_verification_omitted};

    #[test]
    fn write_only_projection_fails_closed_when_schema_work_is_exhausted() {
        let branches = (0..5_000)
            .map(|_| {
                serde_json::json!({
                    "type":"object",
                    "properties":{
                        "secret":{"type":"string", "writeOnly":true}
                    }
                })
            })
            .collect::<Vec<_>>();
        let schema = serde_json::json!({"oneOf":branches});
        let path = [RequestSchemaPathStep::Property("secret".to_owned())];

        assert!(!request_schema_path_is_verification_omitted(&schema, &path));
    }
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

fn evaluate_oauth_client_secret_readback(
    strategy: &str,
    oauth_client_id: &str,
    apply_response: &CloudflareResponseV1,
    readback: &CloudflareResponseV1,
) -> Result<(bool, String)> {
    let readback_identity_matches =
        readback.result.get("client_id").and_then(Value::as_str) == Some(oauth_client_id);
    let apply_status_matches = apply_response.status == 200;
    let readback_status_matches = readback.status == 200;
    let rotated_state = readback
        .result
        .get("has_rotated_secret")
        .and_then(Value::as_bool);
    match strategy {
        "oauth_client_reports_rotated_secret_after_value_roll" => {
            let client_secret_present = apply_response
                .result
                .get("client_secret")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty());
            let rotated_state_matches = rotated_state == Some(true);
            let passed = apply_response.success
                && apply_status_matches
                && client_secret_present
                && readback.success
                && readback_status_matches
                && readback_identity_matches
                && rotated_state_matches;
            let basis = format!(
                "OAuth client rotation proof (apply HTTP {}, apply success={}, one-time client secret present={}, readback HTTP {}, readback success={}, readback client identity matches={}, has_rotated_secret=true={})",
                apply_response.status,
                apply_response.success,
                client_secret_present,
                readback.status,
                readback.success,
                readback_identity_matches,
                rotated_state_matches
            );
            Ok((passed, basis))
        }
        "oauth_client_reports_no_rotated_secret_after_old_secret_delete" => {
            let apply_identity_matches =
                apply_response.result.get("id").and_then(Value::as_str) == Some(oauth_client_id);
            let rotated_state_matches = rotated_state == Some(false);
            let passed = apply_response.success
                && apply_status_matches
                && apply_identity_matches
                && readback.success
                && readback_status_matches
                && readback_identity_matches
                && rotated_state_matches;
            let basis = format!(
                "OAuth client old-secret deletion proof (apply HTTP {}, apply success={}, apply identity matches={}, readback HTTP {}, readback success={}, readback client identity matches={}, has_rotated_secret=false={})",
                apply_response.status,
                apply_response.success,
                apply_identity_matches,
                readback.status,
                readback.success,
                readback_identity_matches,
                rotated_state_matches
            );
            Ok((passed, basis))
        }
        _ => Err(CloudflareError::UnsupportedVerificationStrategy(
            strategy.to_owned(),
        )),
    }
}

fn evaluate_worker_script_secret_put_readback(
    planned_name: &str,
    planned_type: &str,
    apply_response: &CloudflareResponseV1,
    readback: &CloudflareResponseV1,
) -> (bool, String) {
    let apply_name_matches =
        apply_response.result.get("name").and_then(Value::as_str) == Some(planned_name);
    let apply_type_matches =
        apply_response.result.get("type").and_then(Value::as_str) == Some(planned_type);
    let readback_name_matches =
        readback.result.get("name").and_then(Value::as_str) == Some(planned_name);
    let readback_type_matches =
        readback.result.get("type").and_then(Value::as_str) == Some(planned_type);
    let passed = apply_response.status == 200
        && apply_response.success
        && apply_name_matches
        && apply_type_matches
        && readback.status == 200
        && readback.success
        && readback_name_matches
        && readback_type_matches;
    let basis = format!(
        "Worker script secret proof (apply HTTP {}, apply success={}, apply name matches={}, apply type matches={}, readback HTTP {}, readback success={}, readback name matches={}, readback type matches={})",
        apply_response.status,
        apply_response.success,
        apply_name_matches,
        apply_type_matches,
        readback.status,
        readback.success,
        readback_name_matches,
        readback_type_matches
    );
    (passed, basis)
}

fn evaluate_access_service_token_refresh_readback(
    service_token_id: &str,
    apply_response: &CloudflareResponseV1,
    readback: &CloudflareResponseV1,
) -> (bool, String) {
    let apply_identity_matches =
        apply_response.result.get("id").and_then(Value::as_str) == Some(service_token_id);
    let readback_identity_matches =
        readback.result.get("id").and_then(Value::as_str) == Some(service_token_id);
    let apply_expiration = apply_response
        .result
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok());
    let readback_expiration = readback
        .result
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok());
    let apply_expiration_future = apply_expiration
        .as_ref()
        .is_some_and(|expiration| expiration.timestamp() > Utc::now().timestamp());
    let expiration_matches = apply_expiration
        .as_ref()
        .zip(readback_expiration.as_ref())
        .is_some_and(|(apply, readback)| apply == readback);
    let passed = apply_response.status == 200
        && apply_response.success
        && apply_identity_matches
        && apply_expiration_future
        && readback.status == 200
        && readback.success
        && readback_identity_matches
        && expiration_matches;
    let basis = format!(
        "Access service-token refresh proof (apply HTTP {}, apply success={}, apply identity matches={}, apply expiration is valid and future={}, readback HTTP {}, readback success={}, readback identity matches={}, expiration matches={})",
        apply_response.status,
        apply_response.success,
        apply_identity_matches,
        apply_expiration_future,
        readback.status,
        readback.success,
        readback_identity_matches,
        expiration_matches
    );
    (passed, basis)
}

fn validate_verification_preconditions(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let strategy = capability.verification.strategy.as_str();
    if !capability.verification_contract_supported() {
        return Err(CloudflareError::UnsupportedVerificationStrategy(
            strategy.to_owned(),
        ));
    }
    if matches!(
        strategy,
        "oauth_client_reports_rotated_secret_after_value_roll"
            | "oauth_client_reports_no_rotated_secret_after_old_secret_delete"
    ) {
        return validate_oauth_client_secret_target(capability, input);
    }
    if strategy == "worker_script_secret_reports_planned_name_and_type_after_put" {
        return validate_worker_script_secret_put_target(capability, input);
    }
    if strategy == "access_service_token_reports_refreshed_expiration" {
        return validate_access_service_token_refresh_target(capability, input);
    }
    let body_label = match strategy {
        "created_resource_contains_planned_fields_by_returned_id"
        | "parent_collection_contains_created_resource_id_and_planned_fields"
        | "dns_record_details_match_created_id_and_planned_fields" => Some("create"),
        "same_resource_contains_planned_fields_after_update"
        | "same_path_result_contains_planned_fields_after_update"
        | "parent_collection_item_contains_planned_fields_after_update"
        | "dns_record_details_match_planned_id_and_fields" => Some("update"),
        "same_path_result_contains_planned_fields_after_mutation" => Some("mutation"),
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
        "same_resource_returns_not_found_after_delete" => {
            validate_same_path_delete_target(capability, input)
        }
        "same_resource_contains_planned_fields_after_update"
        | "same_path_result_contains_planned_fields_after_update"
        | "same_path_result_contains_planned_fields_after_mutation" => {
            validate_same_path_update_target(capability, input)
        }
        "created_resource_contains_planned_fields_by_returned_id" => {
            validate_created_resource_target(capability, input)
        }
        "parent_collection_contains_created_resource_id_and_planned_fields" => {
            validate_created_collection_resource_target(capability, input)
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

fn validate_worker_script_secret_put_target(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound Worker script secret readback contract is absent".to_owned(),
        )
    })?;
    if target.path != "/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}"
        || target.read_capability_id != "worker-get-script-secret"
        || target.verified_response_fields != ["name", "type"]
        || !clean_verification_query(input)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the Worker script secret operation does not match its hash-bound exact readback contract"
                .to_owned(),
        ));
    }
    let selectors = input.selectors.as_object().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the planned Worker script selectors are not an object".to_owned(),
        )
    })?;
    if selectors.len() != 2
        || ["account_id", "script_name"].iter().any(|name| {
            selectors
                .get(*name)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned Worker script selectors are missing, empty, or broader than the exact account and script target"
                .to_owned(),
        ));
    }
    validate_request_contract(capability, input)?;
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the planned Worker script secret body is absent or not an object".to_owned(),
            )
        })?;
    if body
        .get("name")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || !matches!(
            body.get("type").and_then(Value::as_str),
            Some("secret_text" | "secret_key")
        )
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned Worker script secret name or type is absent or invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_oauth_client_secret_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound OAuth client detail readback contract is absent".to_owned(),
        )
    })?;
    if target.path != "/accounts/{account_id}/oauth_clients/{oauth_client_id}"
        || target.read_capability_id != "oauth-clients-get"
        || target.verified_response_fields != ["client_id", "has_rotated_secret"]
        || capability.request_schema.is_some()
        || input.body.is_some()
        || !clean_verification_query(input)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the OAuth client secret operation does not match its hash-bound body-free detail readback contract"
                .to_owned(),
        ));
    }
    let selectors = input.selectors.as_object().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the planned OAuth client selectors are not an object".to_owned(),
        )
    })?;
    if selectors.len() != 2
        || ["account_id", "oauth_client_id"].iter().any(|name| {
            selectors
                .get(*name)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned OAuth client selectors are missing, empty, or broader than the exact account and client target"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_access_service_token_refresh_target(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound Access service-token detail readback contract is absent".to_owned(),
        )
    })?;
    if target.path != "/accounts/{account_id}/access/service_tokens/{service_token_id}"
        || target.read_capability_id != "access-service-tokens-get-a-service-token"
        || target.verified_response_fields != ["expires_at", "id"]
        || capability.request_schema.is_some()
        || input.body.is_some()
        || !clean_verification_query(input)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the Access service-token refresh does not match its hash-bound body-free detail readback contract"
                .to_owned(),
        ));
    }
    let selectors = input.selectors.as_object().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the planned Access service-token selectors are not an object".to_owned(),
        )
    })?;
    if selectors.len() != 2
        || ["account_id", "service_token_id"].iter().any(|name| {
            selectors
                .get(*name)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned Access service-token selectors are missing, empty, or broader than the exact account and token target"
                .to_owned(),
        ));
    }
    Ok(())
}

fn clean_verification_query(input: &CallInput) -> bool {
    input.query.is_null()
        || input
            .query
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
}

fn same_path_verification_capability(
    mutation: &CapabilityV1,
    read_capability_id: &str,
    title: &str,
    path: &str,
) -> CapabilityV1 {
    let mut readback = CapabilityV1::new(read_capability_id, title, "GET", path);
    readback.product.clone_from(&mutation.product);
    readback.selectors = mutation
        .selectors
        .iter()
        .filter(|selector| same_path_routing_header(mutation, selector))
        .cloned()
        .collect();
    readback
}

fn same_path_routing_header(capability: &CapabilityV1, selector: &SelectorV1) -> bool {
    selector.location == "header"
        && selector.name == "cf-r2-jurisdiction"
        && !selector.required
        && selector.value_type == "string"
        && matches!(capability.product.as_str(), "R2 Bucket" | "R2 Object")
}

fn validate_same_path_delete_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound same-path delete readback contract is absent".to_owned(),
        )
    })?;
    if target.path != capability.path
        || target.read_capability_id.is_empty()
        || !target.verified_response_fields.is_empty()
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the exact delete contains inputs outside its hash-bound same-path readback contract"
                .to_owned(),
        ));
    }
    if capability.request_schema.is_none() {
        if input.body.is_some() {
            return Err(CloudflareError::MissingVerificationTarget(
                "the exact delete contains inputs outside its hash-bound same-path readback contract"
                    .to_owned(),
            ));
        }
    } else if !capability.required_empty_request_body_contract()
        || !input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .is_some_and(serde_json::Map::is_empty)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the exact delete does not match its hash-bound required empty body contract"
                .to_owned(),
        ));
    }
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned delete contains query controls outside the hash-bound same-path readback contract"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_same_path_update_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let operation = if capability.verification.strategy
        == "same_path_result_contains_planned_fields_after_mutation"
    {
        "mutation"
    } else {
        "update"
    };
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(format!(
            "the hash-bound same-path {operation} readback contract is absent"
        ))
    })?;
    if target.path != capability.path
        || target.read_capability_id.is_empty()
        || target.verified_response_fields.is_empty()
        || target
            .verified_response_fields
            .windows(2)
            .any(|fields| fields[0] >= fields[1])
    {
        return Err(CloudflareError::MissingVerificationTarget(format!(
            "the hash-bound same-path {operation} readback contract is malformed"
        )));
    }
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(format!(
            "the planned {operation} contains query controls outside the hash-bound same-path readback contract"
        )));
    }
    let Some(planned) = input.body.as_ref().and_then(Value::as_object) else {
        return Err(CloudflareError::MissingVerificationTarget(format!(
            "planned {operation} body is absent, empty, or not an object"
        )));
    };
    if planned.keys().any(|field| {
        !planned_field_is_bound_to_readback(capability, &target.verified_response_fields, field)
    }) {
        return Err(CloudflareError::MissingVerificationTarget(format!(
            "the planned {operation} contains a field outside the hash-bound same-path readback fields"
        )));
    }
    Ok(())
}

fn validate_created_resource_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let target = capability.created_resource.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound created-resource contract is absent".to_owned(),
        )
    })?;
    let expected_suffix = format!("/{{{}}}", target.identity_selector);
    if target.identity_selector.is_empty()
        || !target.detail_path.ends_with(&expected_suffix)
        || !response_identity_pointer_supported(
            &target.identity_selector,
            &target.response_result_identity_pointer,
        )
        || target.read_capability_id.is_empty()
        || target.delete_capability_id.is_empty()
        || target.verified_response_fields.is_empty()
        || target
            .verified_response_fields
            .iter()
            .any(|field| field.is_empty() || field.contains('/'))
        || target
            .verified_response_fields
            .windows(2)
            .any(|fields| fields[0] >= fields[1])
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the hash-bound created-resource contract is malformed".to_owned(),
        ));
    }
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned create contains query controls outside the hash-bound exact readback contract"
                .to_owned(),
        ));
    }
    let Some(planned) = input.body.as_ref().and_then(Value::as_object) else {
        return Err(CloudflareError::MissingVerificationTarget(
            "planned create body is absent, empty, or not an object".to_owned(),
        ));
    };
    if planned.keys().any(|field| {
        !planned_field_is_bound_to_readback(capability, &target.verified_response_fields, field)
    }) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned create contains a field outside the hash-bound exact readback fields"
                .to_owned(),
        ));
    }
    Ok(())
}

fn selector_can_be_response_id(selector: &str) -> bool {
    matches!(selector, "id" | "identifier")
        || selector.ends_with("_id")
        || selector.ends_with("_identifier")
}

// Kept in sync with `cfctl_core::response_identity_pointer_supported` — the
// classifier gate (core) and the executor verify gate (here) must accept the
// same identity pointers, or a capability the catalog marks `dynamic_api` fails
// closed at verify time. The `database_id`->`/uuid` branch mirrors core so D1
// database creates (identity `database_id`, pointer `/uuid`) verify instead of
// falsely landing in RectificationRequired after a successful create.
fn response_identity_pointer_supported(selector: &str, pointer: &str) -> bool {
    // Fail closed: an identity pointer that names a secret field is never
    // supported (mirrors the core gate), so no verifier dereferences secret
    // material as a resource identity.
    if cfctl_core::pointer_names_secret_field(pointer) {
        return false;
    }
    (selector_can_be_response_id(selector) && pointer == "/id")
        || (selector.ends_with("_name") && pointer == "/name")
        || (selector == "database_id" && pointer == "/uuid")
        || (!selector
            .chars()
            .any(|character| matches!(character, '/' | '~'))
            && pointer.strip_prefix('/') == Some(selector))
}

#[cfg(test)]
mod identity_pointer_parity_tests {
    use super::response_identity_pointer_supported;

    #[test]
    fn executor_gate_matches_core_including_database_id_uuid() {
        // Regression: the D1 create contract (identity `database_id`, pointer
        // `/uuid`) is classified `dynamic_api` by the core gate, so the executor
        // gate must accept it too — otherwise a successful create verifies
        // false and lands in RectificationRequired.
        assert!(response_identity_pointer_supported("database_id", "/uuid"));
        // Standard identities still hold.
        assert!(response_identity_pointer_supported("id", "/id"));
        assert!(response_identity_pointer_supported("widget_name", "/name"));
        assert!(response_identity_pointer_supported("slug", "/slug"));
        // The secret-field guard still fails closed for every shape.
        assert!(!response_identity_pointer_supported("value", "/value"));
        assert!(!response_identity_pointer_supported(
            "secretAccessKey",
            "/secretAccessKey"
        ));
        // A pointer that does not match its selector is rejected.
        assert!(!response_identity_pointer_supported("database_id", "/name"));
    }
}

fn validate_created_collection_resource_target(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let target = capability
        .created_collection_resource
        .as_ref()
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound created-collection-resource contract is absent".to_owned(),
            )
        })?;
    if target.collection_path != capability.path
        || target.identity_selector.is_empty()
        || target.response_result_identity_pointer != target.response_item_identity_pointer
        || !response_identity_pointer_supported(
            &target.identity_selector,
            &target.response_result_identity_pointer,
        )
        || target.read_capability_id.is_empty()
        || target.delete_capability_id.is_empty()
        || target.verified_response_fields.is_empty()
        || target
            .verified_response_fields
            .iter()
            .any(|field| field.is_empty() || field.contains('/'))
        || target
            .verified_response_fields
            .windows(2)
            .any(|fields| fields[0] >= fields[1])
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the hash-bound created-collection-resource contract is malformed".to_owned(),
        ));
    }
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned create contains query controls outside the hash-bound collection readback contract"
                .to_owned(),
        ));
    }
    let Some(planned) = input.body.as_ref().and_then(Value::as_object) else {
        return Err(CloudflareError::MissingVerificationTarget(
            "planned create body is absent, empty, or not an object".to_owned(),
        ));
    };
    if planned.keys().any(|field| {
        !planned_field_is_bound_to_readback(capability, &target.verified_response_fields, field)
    }) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned create contains a field outside the hash-bound collection readback fields"
                .to_owned(),
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
        || !response_identity_pointer_supported(
            &target.identity_selector,
            &target.response_item_identity_pointer,
        )
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
    if input.body.is_some() {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned delete body is outside the hash-bound collection readback contract"
                .to_owned(),
        ));
    }
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned delete contains query controls outside the hash-bound collection readback contract"
                .to_owned(),
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
        || !response_identity_pointer_supported(
            &target.identity_selector,
            &target.response_item_identity_pointer,
        )
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
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned update contains query controls outside the hash-bound collection readback contract"
                .to_owned(),
        ));
    }
    let Some(planned) = input.body.as_ref().and_then(Value::as_object) else {
        return Err(CloudflareError::MissingVerificationTarget(
            "planned update body is absent, empty, or not an object".to_owned(),
        ));
    };
    if planned.keys().any(|field| {
        !planned_field_is_bound_to_readback(capability, &target.verified_response_fields, field)
    }) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned update contains a field outside the hash-bound collection readback fields"
                .to_owned(),
        ));
    }
    Ok(())
}

fn planned_field_is_bound_to_readback(
    capability: &CapabilityV1,
    verified_response_fields: &[String],
    field: &str,
) -> bool {
    verified_response_fields
        .binary_search_by(|candidate| candidate.as_str().cmp(field))
        .is_ok()
        || capability.request_object_field_is_verification_omitted(field)
}

fn is_update_verifier(strategy: &str) -> bool {
    matches!(
        strategy,
        "same_resource_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_mutation"
            | "parent_collection_item_contains_planned_fields_after_update"
    )
}

fn is_create_verifier(strategy: &str) -> bool {
    matches!(
        strategy,
        "created_resource_contains_planned_fields_by_returned_id"
            | "parent_collection_contains_created_resource_id_and_planned_fields"
    )
}

fn is_delete_verifier(strategy: &str) -> bool {
    matches!(
        strategy,
        "same_resource_returns_not_found_after_delete"
            | "parent_collection_omits_deleted_resource_id"
    )
}

pub fn validate_request_contract(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    validate_response_contract(capability)?;
    validate_selector_contract(capability, &input.selectors)?;
    validate_query_contract(capability, &input.query)?;
    validate_request_body(capability, input.body.as_ref())
}

fn validate_response_contract(capability: &CapabilityV1) -> Result<()> {
    if let Some(response) = capability
        .response_contract
        .as_ref()
        .filter(|response| response.body_mode == ResponseBodyModeV1::Unsupported)
    {
        return Err(CloudflareError::UnsupportedResponseContract(
            response.success_media_types.join(", "),
        ));
    }
    Ok(())
}

fn validate_selector_contract(capability: &CapabilityV1, selectors: &Value) -> Result<()> {
    let values = match selectors {
        Value::Null => None,
        Value::Object(values) => Some(values),
        _ => return Err(CloudflareError::InvalidSelectorObject),
    };
    if let Some(values) = values {
        for (name, value) in values {
            let selector = capability
                .selectors
                .iter()
                .find(|selector| selector.location != "query" && selector.name == *name);
            let Some(selector) = selector else {
                if path_declares_selector(&capability.path, name) {
                    if scalar(value).is_none() {
                        return Err(CloudflareError::InvalidSelector(name.clone()));
                    }
                    continue;
                }
                return Err(CloudflareError::UndeclaredSelector(name.clone()));
            };
            if selector.location == "header" && request_header_is_reserved(name) {
                return Err(CloudflareError::ReservedHeaderSelector(name.clone()));
            }
            if scalar(value).is_none() {
                return Err(CloudflareError::InvalidSelector(name.clone()));
            }
            let schema = selector.contract.as_ref().map(|contract| &contract.schema);
            let Some(canonical) =
                canonical_selector_value_for_schema(value, &selector.value_type, schema)
            else {
                return Err(CloudflareError::InvalidSelector(name.clone()));
            };
            if let Some(schema) = schema {
                validate_request_schema_value(schema, &canonical, "", 0).map_err(|error| {
                    let reason = match error {
                        CloudflareError::InvalidRequestBody(reason) => reason,
                        other => other.to_string(),
                    };
                    CloudflareError::InvalidSelectorSchema {
                        name: name.clone(),
                        reason,
                    }
                })?;
            }
        }
    }
    for selector in capability
        .selectors
        .iter()
        .filter(|selector| selector.location != "query" && selector.required)
    {
        if values.is_none_or(|values| !values.contains_key(&selector.name)) {
            return if selector.location == "header" {
                Err(CloudflareError::MissingHeaderSelector(
                    selector.name.clone(),
                ))
            } else {
                Err(CloudflareError::MissingSelector(selector.name.clone()))
            };
        }
    }
    for name in path_selector_names(&capability.path) {
        if values.is_none_or(|values| !values.contains_key(name)) {
            return Err(CloudflareError::MissingSelector(name.to_owned()));
        }
    }
    Ok(())
}

fn path_selector_names(path: &str) -> impl Iterator<Item = &str> {
    path.trim_start_matches('/')
        .split('/')
        .filter_map(|segment| {
            segment
                .strip_prefix('{')
                .and_then(|segment| segment.strip_suffix('}'))
        })
}

fn path_declares_selector(path: &str, name: &str) -> bool {
    path_selector_names(path).any(|selector| selector == name)
}

fn validate_query_contract(capability: &CapabilityV1, query: &Value) -> Result<()> {
    let values = match query {
        Value::Null => None,
        Value::Object(values) => Some(values),
        _ => return Err(CloudflareError::InvalidQueryObject),
    };
    if let Some(values) = values {
        for (name, value) in values {
            let selector = capability
                .selectors
                .iter()
                .find(|selector| selector.location == "query" && selector.name == *name)
                .ok_or_else(|| CloudflareError::UndeclaredQuerySelector(name.clone()))?;
            let (_, allow_empty) = validated_query_serialization(selector)?;
            if query_value_is_empty(value) && allow_empty {
                continue;
            }
            let Some(canonical) = canonical_query_value(value, &selector.value_type, selector)
            else {
                return Err(CloudflareError::InvalidQuerySelector {
                    name: name.clone(),
                    expected: selector.value_type.clone(),
                });
            };
            if let Some(schema) = selector.contract.as_ref().map(|contract| &contract.schema) {
                validate_request_schema_value(schema, &canonical, "", 0).map_err(|error| {
                    let reason = match error {
                        CloudflareError::InvalidRequestBody(reason) => reason,
                        other => other.to_string(),
                    };
                    CloudflareError::InvalidQuerySelectorSchema {
                        name: name.clone(),
                        reason,
                    }
                })?;
            }
        }
    }
    for selector in capability
        .selectors
        .iter()
        .filter(|selector| selector.location == "query" && selector.required)
    {
        if values.is_none_or(|values| !values.contains_key(&selector.name)) {
            return Err(CloudflareError::MissingQuerySelector(selector.name.clone()));
        }
    }
    Ok(())
}

fn validated_query_serialization(selector: &SelectorV1) -> Result<(bool, bool)> {
    let query = selector
        .contract
        .as_ref()
        .and_then(|contract| contract.query.as_ref());
    let style = query.map_or("form", |query| query.style.as_str());
    if style != "form" {
        return Err(CloudflareError::UnsupportedQuerySerialization {
            name: selector.name.clone(),
            reason: format!("style `{style}` is not implemented"),
        });
    }
    if query.is_some_and(|query| query.allow_reserved) {
        return Err(CloudflareError::UnsupportedQuerySerialization {
            name: selector.name.clone(),
            reason: "allowReserved=true cannot be encoded by the governed URL builder".to_owned(),
        });
    }
    Ok((
        query.is_none_or(|query| query.explode),
        query.is_some_and(|query| query.allow_empty_value),
    ))
}

fn query_value_is_empty(value: &Value) -> bool {
    value.as_str() == Some("") || value.as_array().is_some_and(Vec::is_empty)
}

fn canonical_query_value(value: &Value, expected: &str, selector: &SelectorV1) -> Option<Value> {
    let schema = selector.contract.as_ref().map(|contract| &contract.schema);
    canonical_selector_value_for_schema(value, expected, schema)
}

fn canonical_selector_value_for_schema(
    value: &Value,
    expected: &str,
    schema: Option<&Value>,
) -> Option<Value> {
    match expected {
        "string" => value.as_str().map(|value| Value::String(value.to_owned())),
        "boolean" => value.as_bool().map(Value::Bool).or_else(|| {
            value.as_str().and_then(|value| match value {
                "true" => Some(Value::Bool(true)),
                "false" => Some(Value::Bool(false)),
                _ => None,
            })
        }),
        "integer" => value
            .as_i64()
            .map(serde_json::Number::from)
            .or_else(|| value.as_u64().map(serde_json::Number::from))
            .or_else(|| {
                value.as_str().and_then(|value| {
                    value
                        .parse::<i64>()
                        .map(serde_json::Number::from)
                        .or_else(|_| value.parse::<u64>().map(serde_json::Number::from))
                        .ok()
                })
            })
            .map(Value::Number),
        "number" => value.as_number().cloned().map(Value::Number).or_else(|| {
            value
                .as_str()
                .and_then(|value| serde_json::from_str::<Value>(value).ok())
                .filter(Value::is_number)
        }),
        "array" => {
            let values = value.as_array()?;
            if values.is_empty() {
                return None;
            }
            let item_schema = schema.and_then(|schema| schema.get("items"));
            let item_type = item_schema.and_then(schema_value_type).unwrap_or("unknown");
            if matches!(item_type, "array" | "object") {
                return None;
            }
            values
                .iter()
                .map(|value| canonical_selector_value_for_schema(value, item_type, item_schema))
                .collect::<Option<Vec<_>>>()
                .map(Value::Array)
        }
        "unknown" => scalar(value).map(|_| value.clone()),
        _ => None,
    }
}

fn schema_value_type(schema: &Value) -> Option<&str> {
    schema.get("type").and_then(Value::as_str).or_else(|| {
        let values = schema.get("enum")?.as_array()?;
        let first = values.first()?;
        let value_type = json_value_type(first)?;
        values
            .iter()
            .all(|value| json_value_type(value) == Some(value_type))
            .then_some(value_type)
    })
}

fn json_value_type(value: &Value) -> Option<&'static str> {
    match value {
        Value::Bool(_) => Some("boolean"),
        Value::Number(number) if number.is_i64() || number.is_u64() => Some("integer"),
        Value::Number(_) => Some("number"),
        Value::String(_) => Some("string"),
        Value::Array(_) => Some("array"),
        Value::Object(_) => Some("object"),
        Value::Null => None,
    }
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
    validate_request_schema_value(schema, body, "", 0)
}

const MAX_REQUEST_VALIDATION_DEPTH: usize = 64;

fn validate_request_schema_value(
    schema: &Value,
    value: &Value,
    path: &str,
    depth: usize,
) -> Result<()> {
    let mut remaining_steps = MAX_REQUEST_VALIDATION_STEPS;
    validate_request_schema_value_inner(
        schema,
        value,
        path,
        depth,
        &mut remaining_steps,
        &BTreeSet::new(),
    )
}

const MAX_REQUEST_VALIDATION_STEPS: usize = 65_536;
const REQUEST_VALIDATION_DEPTH_LIMIT_REASON: &str =
    "pinned schema exceeds the validation depth limit";
const REQUEST_VALIDATION_WORK_LIMIT_REASON: &str =
    "request body exceeds the pinned validation work limit";

fn validate_request_schema_value_inner(
    schema: &Value,
    value: &Value,
    path: &str,
    depth: usize,
    remaining_steps: &mut usize,
    inherited_object_properties: &BTreeSet<String>,
) -> Result<()> {
    if depth > MAX_REQUEST_VALIDATION_DEPTH {
        return Err(CloudflareError::InvalidRequestBody(
            REQUEST_VALIDATION_DEPTH_LIMIT_REASON.to_owned(),
        ));
    }
    let Some(next_steps) = remaining_steps.checked_sub(1) else {
        return Err(CloudflareError::InvalidRequestBody(
            REQUEST_VALIDATION_WORK_LIMIT_REASON.to_owned(),
        ));
    };
    *remaining_steps = next_steps;
    if value.is_null()
        && (schema.get("nullable").and_then(Value::as_bool) == Some(true)
            || schema
                .get("enum")
                .and_then(Value::as_array)
                .is_some_and(|values| values.contains(value)))
    {
        return Ok(());
    }
    if let Some(expected) = schema.get("type").and_then(Value::as_str)
        && !json_type_matches(value, expected)
    {
        let reason = if path.is_empty() {
            format!("expected top-level {expected}")
        } else {
            format!("property `{path}` must be {expected}")
        };
        return Err(CloudflareError::InvalidRequestBody(reason));
    }
    if schema
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.contains(value))
    {
        let location = if path.is_empty() {
            "top-level value".to_owned()
        } else {
            format!("property `{path}`")
        };
        return Err(CloudflareError::InvalidRequestBody(format!(
            "{location} is not one of the pinned enum values"
        )));
    }
    validate_request_schema_bounds(schema, value, path, depth, remaining_steps)?;
    if let Some(object) = value.as_object() {
        let mut allowed_properties = inherited_object_properties.clone();
        collect_composed_property_names(schema, &mut allowed_properties, 0);
        validate_request_object(
            schema,
            object,
            path,
            depth,
            remaining_steps,
            &allowed_properties,
        )?;
    }
    if let Some(array) = value.as_array()
        && let Some(items) = schema.get("items")
    {
        for item in array {
            validate_request_schema_value_inner(
                items,
                item,
                path,
                depth + 1,
                remaining_steps,
                &BTreeSet::new(),
            )?;
        }
    }
    validate_schema_composition(
        schema,
        value,
        path,
        depth,
        remaining_steps,
        inherited_object_properties,
    )?;
    Ok(())
}

fn validate_request_schema_bounds(
    schema: &Value,
    value: &Value,
    path: &str,
    depth: usize,
    remaining_steps: &mut usize,
) -> Result<()> {
    if let Some(multiple) = schema.get("multipleOf")
        && let Some(number) = value.as_number()
    {
        let valid = multiple
            .as_number()
            .and_then(|multiple| exact_decimal_multiple(number, multiple))
            .unwrap_or(false);
        if !valid {
            return invalid_request_bound(path, "is not a multiple of the pinned multipleOf value");
        }
    }
    if let Some(number) = value.as_f64() {
        if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
            let exclusive = schema
                .get("exclusiveMinimum")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if number < minimum || (exclusive && number <= minimum) {
                return invalid_request_bound(
                    path,
                    if exclusive {
                        "must be above the pinned minimum"
                    } else {
                        "is below the pinned minimum"
                    },
                );
            }
        }
        if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64) {
            let exclusive = schema
                .get("exclusiveMaximum")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if number > maximum || (exclusive && number >= maximum) {
                return invalid_request_bound(
                    path,
                    if exclusive {
                        "must be below the pinned maximum"
                    } else {
                        "is above the pinned maximum"
                    },
                );
            }
        }
    }
    if let Some(text) = value.as_str() {
        let length = usize_as_u64(text.chars().count());
        validate_length_bounds(schema, path, length, "characters", "minLength", "maxLength")?;
        validate_string_format(schema, text, path)?;
    }
    if let Some(array) = value.as_array() {
        validate_length_bounds(
            schema,
            path,
            usize_as_u64(array.len()),
            "items",
            "minItems",
            "maxItems",
        )?;
        if schema.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
            let mut items = BTreeSet::new();
            for item in array {
                let encoded = schema_equality_key(item, depth + 1, remaining_steps)?;
                if !items.insert(encoded) {
                    return invalid_request_bound(
                        path,
                        "contains duplicate items disallowed by the pinned schema",
                    );
                }
            }
        }
    }
    if let Some(object) = value.as_object() {
        validate_length_bounds(
            schema,
            path,
            usize_as_u64(object.len()),
            "properties",
            "minProperties",
            "maxProperties",
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct DecimalMagnitude {
    coefficient: u128,
    exponent: i32,
}

fn exact_decimal_multiple(
    number: &serde_json::Number,
    multiple: &serde_json::Number,
) -> Option<bool> {
    let value = decimal_magnitude(number)?;
    let divisor = decimal_magnitude(multiple)?;
    if divisor.coefficient == 0 || multiple.to_string().starts_with('-') {
        return None;
    }
    if value.coefficient == 0 {
        return Some(true);
    }

    let common = greatest_common_divisor(value.coefficient, divisor.coefficient);
    let numerator = value.coefficient / common;
    let denominator = divisor.coefficient / common;
    let exponent_difference = value.exponent.checked_sub(divisor.exponent)?;
    if exponent_difference >= 0 {
        let available_tens = u32::try_from(exponent_difference).ok()?;
        let (denominator, twos) = remove_factor(denominator, 2);
        let (denominator, fives) = remove_factor(denominator, 5);
        return Some(denominator == 1 && twos <= available_tens && fives <= available_tens);
    }

    let required_tens = exponent_difference.unsigned_abs();
    let (_, twos) = remove_factor(numerator, 2);
    let (_, fives) = remove_factor(numerator, 5);
    Some(twos >= required_tens && fives >= required_tens)
}

fn decimal_magnitude(number: &serde_json::Number) -> Option<DecimalMagnitude> {
    let rendered = number.to_string();
    let unsigned = rendered
        .strip_prefix('-')
        .or_else(|| rendered.strip_prefix('+'))
        .unwrap_or(&rendered);
    let (mantissa, explicit_exponent) =
        if let Some((mantissa, exponent)) = unsigned.split_once(['e', 'E']) {
            (mantissa, exponent.parse::<i32>().ok()?)
        } else {
            (unsigned, 0)
        };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let mut digits = String::with_capacity(whole.len() + fraction.len());
    digits.push_str(whole);
    digits.push_str(fraction);
    let mut coefficient = digits.parse::<u128>().ok()?;
    let fractional_digits = i32::try_from(fraction.len()).ok()?;
    let mut exponent = explicit_exponent.checked_sub(fractional_digits)?;
    if coefficient == 0 {
        return Some(DecimalMagnitude {
            coefficient,
            exponent: 0,
        });
    }
    while coefficient.is_multiple_of(10) {
        coefficient /= 10;
        exponent = exponent.checked_add(1)?;
    }
    Some(DecimalMagnitude {
        coefficient,
        exponent,
    })
}

fn greatest_common_divisor(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn remove_factor(mut value: u128, factor: u128) -> (u128, u32) {
    let mut count = 0_u32;
    while value.is_multiple_of(factor) {
        value /= factor;
        count = count.saturating_add(1);
    }
    (value, count)
}

fn validate_string_format(schema: &Value, value: &str, path: &str) -> Result<()> {
    let Some(format) = schema.get("format").and_then(Value::as_str) else {
        return Ok(());
    };
    let valid = match format {
        "date-time" => DateTime::parse_from_rfc3339(value).is_ok(),
        "hostname" => is_valid_hostname(value),
        "ipv4" => value.parse::<Ipv4Addr>().is_ok(),
        "ipv6" => value.parse::<Ipv6Addr>().is_ok(),
        _ => true,
    };
    if valid {
        return Ok(());
    }
    invalid_request_bound(path, &format!("does not match the pinned {format} format"))
}

fn is_valid_hostname(value: &str) -> bool {
    if value == "." {
        return true;
    }
    let hostname = value.strip_suffix('.').unwrap_or(value);
    !hostname.is_empty()
        && hostname.len() <= 253
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn validate_length_bounds(
    schema: &Value,
    path: &str,
    length: u64,
    units: &str,
    minimum_key: &str,
    maximum_key: &str,
) -> Result<()> {
    if schema
        .get(minimum_key)
        .and_then(Value::as_u64)
        .is_some_and(|minimum| length < minimum)
    {
        return invalid_request_bound(
            path,
            &format!("has fewer {units} than the pinned {minimum_key}"),
        );
    }
    if schema
        .get(maximum_key)
        .and_then(Value::as_u64)
        .is_some_and(|maximum| length > maximum)
    {
        return invalid_request_bound(
            path,
            &format!("has more {units} than the pinned {maximum_key}"),
        );
    }
    Ok(())
}

fn usize_as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn invalid_request_bound(path: &str, reason: &str) -> Result<()> {
    Err(CloudflareError::InvalidRequestBody(format!(
        "{} {reason}",
        request_schema_location(path)
    )))
}

fn schema_equality_key(value: &Value, depth: usize, remaining_steps: &mut usize) -> Result<String> {
    let mut key = String::new();
    append_schema_equality_key(value, &mut key, depth, remaining_steps)?;
    Ok(key)
}

fn append_schema_equality_key(
    value: &Value,
    key: &mut String,
    depth: usize,
    remaining_steps: &mut usize,
) -> Result<()> {
    if depth > MAX_REQUEST_VALIDATION_DEPTH {
        return Err(CloudflareError::InvalidRequestBody(
            REQUEST_VALIDATION_DEPTH_LIMIT_REASON.to_owned(),
        ));
    }
    let Some(next_steps) = remaining_steps.checked_sub(1) else {
        return Err(CloudflareError::InvalidRequestBody(
            REQUEST_VALIDATION_WORK_LIMIT_REASON.to_owned(),
        ));
    };
    *remaining_steps = next_steps;
    match value {
        Value::Null => key.push('z'),
        Value::Bool(value) => key.push_str(if *value { "b1" } else { "b0" }),
        Value::Number(value) => {
            key.push('n');
            key.push_str(&schema_number_equality_key(value));
            key.push(';');
        }
        Value::String(value) => append_length_prefixed_string('s', value, key),
        Value::Array(values) => {
            key.push('[');
            for value in values {
                append_schema_equality_key(value, key, depth + 1, remaining_steps)?;
            }
            key.push(']');
        }
        Value::Object(values) => {
            key.push('{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            for (name, value) in entries {
                append_length_prefixed_string('k', name, key);
                append_schema_equality_key(value, key, depth + 1, remaining_steps)?;
            }
            key.push('}');
        }
    }
    Ok(())
}

fn append_length_prefixed_string(prefix: char, value: &str, key: &mut String) {
    key.push(prefix);
    key.push_str(&value.len().to_string());
    key.push(':');
    key.push_str(value);
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::float_cmp
)]
fn schema_number_equality_key(number: &serde_json::Number) -> String {
    if let Some(value) = number.as_i64() {
        return value.to_string();
    }
    if let Some(value) = number.as_u64() {
        return value.to_string();
    }
    let Some(value) = number.as_f64() else {
        return number.to_string();
    };
    if value == 0.0 {
        return "0".to_owned();
    }
    if value.fract() == 0.0 {
        if (-9_223_372_036_854_775_808.0..0.0).contains(&value) {
            let integer = value as i64;
            if integer as f64 == value {
                return integer.to_string();
            }
        }
        if (0.0..18_446_744_073_709_551_616.0).contains(&value) {
            let integer = value as u64;
            if integer as f64 == value {
                return integer.to_string();
            }
        }
    }
    format!("f{:016x}", value.to_bits())
}

fn validate_schema_composition(
    schema: &Value,
    value: &Value,
    path: &str,
    depth: usize,
    remaining_steps: &mut usize,
    inherited_object_properties: &BTreeSet<String>,
) -> Result<()> {
    let mut direct_properties = inherited_object_properties.clone();
    direct_properties.extend(
        schema
            .get("properties")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(name, _)| name.clone()),
    );

    if let Some(members) = schema.get("allOf").and_then(Value::as_array) {
        if members.is_empty() {
            return invalid_empty_composition(path, "allOf");
        }
        let mut sibling_properties = direct_properties.clone();
        for member in members {
            collect_composed_property_names(member, &mut sibling_properties, 0);
        }
        for member in members {
            validate_request_schema_value_inner(
                member,
                value,
                path,
                depth + 1,
                remaining_steps,
                &sibling_properties,
            )?;
        }
    }

    if let Some(members) = schema.get("oneOf").and_then(Value::as_array) {
        if members.is_empty() {
            return invalid_empty_composition(path, "oneOf");
        }
        let mut matches = 0_usize;
        for member in members {
            match validate_request_schema_value_inner(
                member,
                value,
                path,
                depth + 1,
                remaining_steps,
                &direct_properties,
            ) {
                Ok(()) => matches += 1,
                Err(error) if validation_error_aborts_composition(&error) => return Err(error),
                Err(_) => {}
            }
        }
        if matches != 1 {
            return Err(CloudflareError::InvalidRequestBody(format!(
                "{} must match exactly one pinned oneOf alternative",
                request_schema_location(path)
            )));
        }
    }

    if let Some(members) = schema.get("anyOf").and_then(Value::as_array) {
        if members.is_empty() {
            return invalid_empty_composition(path, "anyOf");
        }
        let mut sibling_properties = direct_properties.clone();
        for member in members {
            collect_composed_property_names(member, &mut sibling_properties, 0);
        }
        let mut matches = false;
        for member in members {
            match validate_request_schema_value_inner(
                member,
                value,
                path,
                depth + 1,
                remaining_steps,
                &sibling_properties,
            ) {
                Ok(()) => {
                    matches = true;
                    break;
                }
                Err(error) if validation_error_aborts_composition(&error) => return Err(error),
                Err(_) => {}
            }
        }
        if !matches {
            return Err(CloudflareError::InvalidRequestBody(format!(
                "{} must match at least one pinned anyOf alternative",
                request_schema_location(path)
            )));
        }
    }
    Ok(())
}

fn validation_error_aborts_composition(error: &CloudflareError) -> bool {
    matches!(
        error,
        CloudflareError::InvalidRequestBody(reason)
            if reason == REQUEST_VALIDATION_DEPTH_LIMIT_REASON
                || reason == REQUEST_VALIDATION_WORK_LIMIT_REASON
                || reason.contains("declares an empty pinned")
    )
}

fn collect_composed_property_names(
    schema: &Value,
    properties: &mut BTreeSet<String>,
    depth: usize,
) {
    if depth > MAX_REQUEST_VALIDATION_DEPTH {
        return;
    }
    properties.extend(
        schema
            .get("properties")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(name, _)| name.clone()),
    );
    for composition in ["allOf", "oneOf", "anyOf"] {
        for member in schema
            .get(composition)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            collect_composed_property_names(member, properties, depth + 1);
        }
    }
}

fn invalid_empty_composition(path: &str, composition: &str) -> Result<()> {
    Err(CloudflareError::InvalidRequestBody(format!(
        "{} declares an empty pinned {composition} contract",
        request_schema_location(path)
    )))
}

fn request_schema_location(path: &str) -> String {
    if path.is_empty() {
        "top-level value".to_owned()
    } else {
        format!("property `{path}`")
    }
}

fn validate_request_object(
    schema: &Value,
    object: &serde_json::Map<String, Value>,
    path: &str,
    depth: usize,
    remaining_steps: &mut usize,
    allowed_properties: &BTreeSet<String>,
) -> Result<()> {
    for required in schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !object.contains_key(required) {
            return Err(CloudflareError::InvalidRequestBody(format!(
                "missing required property `{}`",
                request_property_path(path, required)
            )));
        }
    }
    let properties = schema.get("properties").and_then(Value::as_object);
    let additional = schema.get("additionalProperties");
    for (name, value) in object {
        if let Some(property) = properties.and_then(|properties| properties.get(name)) {
            validate_request_schema_value_inner(
                property,
                value,
                &request_property_path(path, name),
                depth + 1,
                remaining_steps,
                &BTreeSet::new(),
            )?;
            continue;
        }
        match additional {
            Some(Value::Bool(false)) => {
                let location = if path.is_empty() {
                    "request body"
                } else {
                    path
                };
                return Err(CloudflareError::InvalidRequestBody(format!(
                    "object at `{location}` contains a property disallowed by the pinned schema"
                )));
            }
            Some(additional_schema) if additional_schema.is_object() => {
                validate_request_schema_value_inner(
                    additional_schema,
                    value,
                    path,
                    depth + 1,
                    remaining_steps,
                    &BTreeSet::new(),
                )?;
            }
            None if properties.is_some() && !allowed_properties.contains(name) => {
                let location = if path.is_empty() {
                    "request body"
                } else {
                    path
                };
                return Err(CloudflareError::InvalidRequestBody(format!(
                    "object at `{location}` contains a property outside the pinned contract"
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

fn request_property_path(parent: &str, property: &str) -> String {
    if parent.is_empty() {
        property.to_owned()
    } else {
        format!("{parent}.{property}")
    }
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
