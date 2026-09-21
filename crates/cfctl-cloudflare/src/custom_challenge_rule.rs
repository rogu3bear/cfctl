//! Read and verify the complete parent around an expression-only PATCH.
use crate::{
    CallInput, CloudflareError, CloudflareResponseV1, Executor, OperationVerificationV1, Result,
};
use cfctl_auth::AuthCredential;
use cfctl_core::{CapabilityV1, PlanV1, custom_challenge_rule as rule};
use serde_json::json;
fn rejected() -> CloudflareError {
    CloudflareError::InvalidRequestBody("custom challenge expression contract rejected".into())
}
impl Executor {
    pub async fn read_custom_challenge_parent(
        &self,
        cap: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        if !rule::supported(cap)
            || input.if_match.is_some()
            || input.if_none_match.is_some()
            || input.query != json!({})
            || !input.body.as_ref().is_some_and(rule::valid_body)
        {
            return Err(rejected());
        }
        let mut read = CapabilityV1::new(
            rule::READ_ID,
            "Read custom challenge parent",
            "GET",
            rule::READ_PATH,
        );
        read.selectors = cap
            .selectors
            .iter()
            .filter(|s| s.name != "rule_id")
            .cloned()
            .collect();
        read.response_contract = cap.response_contract.clone();
        let read_input = CallInput {
            selectors: json!({"zone_id":input.selectors["zone_id"],"ruleset_id":input.selectors["ruleset_id"]}),
            query: json!({}),
            ..CallInput::default()
        };
        let mut request = self.builder.build(&read, &read_input)?;
        request.max_bytes = 2 * 1024 * 1024;
        let response = self.send(&request, credential).await?;
        if !response.success || response.status != 200 || !response.errors.is_empty() {
            return Err(rejected());
        }

        rule::target(&response.result, &input.selectors).map_err(|_| rejected())?;
        Ok(response)
    }
    pub(crate) async fn verify_custom_challenge_rule(
        &self,
        plan: &PlanV1,
        apply: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let body = input.body.as_ref().ok_or_else(rejected)?;
        let before = rule::prior(plan, &input.selectors, body).map_err(|_| rejected())?;
        let readback = self
            .read_custom_challenge_parent(&plan.capability, input, credential)
            .await?;
        let passed = apply.success
            && apply.status == 200
            && apply.errors.is_empty()
            && rule::verify_after(before, &apply.result, &input.selectors, body).is_ok()
            && apply.result == readback.result
            && rule::verify_after(before, &readback.result, &input.selectors, body).is_ok();
        let basis = if !apply.success && (apply.status == 429 || apply.status >= 500) {
            "one challenge PATCH returned an ambiguous response; authenticated parent readback does not establish causality; retain the operation for reconciliation without replay or automatic rollback"
        } else if passed {
            "exact custom challenge expression and unchanged parent fields/actions/order"
        } else {
            "challenge rule or parent drift; retain readback for separately approved recovery without replay"
        };
        Ok(OperationVerificationV1 {
            strategy: rule::VERIFY.into(),
            passed,
            basis: basis.into(),
            readback,
            correlated_resource_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use cfctl_core::{
        AdapterStatus, EffectClass, ResponseBodyModeV1, ResponseContractV1, RiskClass,
        SamePathReadContractV1, SelectorV1, hash_value,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    fn capability() -> CapabilityV1 {
        let mut cap = CapabilityV1::new(rule::ID, "Header rule", "PATCH", rule::PATH);
        cap.account_scope = "zone".into();
        cap.permissions = vec!["Zone WAF Read".into(), "Zone WAF Write".into()];
        cap.adapter_status = AdapterStatus::DynamicApi;
        cap.risk = RiskClass::IdentityOrOwnership;
        cap.effect = EffectClass::ReversibleWrite;
        cap.request_schema = Some(rule::request_schema());
        cap.verification.required = true;
        cap.verification.strategy = rule::VERIFY.into();
        cap.rollback.supported = true;
        cap.rollback.strategy = Some(rule::ROLLBACK.into());
        cap.same_path_read = Some(SamePathReadContractV1 {
            path: rule::READ_PATH.into(),
            read_capability_id: rule::READ_ID.into(),
            verified_response_fields: vec!["expression".into()],
        });
        cap.selectors = ["zone_id", "ruleset_id", "rule_id"]
            .map(|name| SelectorV1 {
                name: name.into(),
                location: "path".into(),
                required: true,
                value_type: "string".into(),
                description: None,
                contract: None,
            })
            .to_vec();
        cap.response_contract = Some(ResponseContractV1 {
            success_statuses: vec!["200".into()],
            success_media_types: vec!["application/json".into()],
            body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
        });
        cap
    }
    #[test]
    fn request_builder_preserves_fields_and_excludes_local_guards() {
        let cap = capability();
        let builder = crate::RequestBuilder::new("https://api.cloudflare.com/client/v4").unwrap();
        let definition = json!({"action":"managed_challenge","enabled":false,"expression":"true","description":"policy","ref":"ref"});
        let mut input = CallInput {
            selectors: json!({"zone_id":"a".repeat(32),"ruleset_id":"b".repeat(32),"rule_id":"c".repeat(32)}),
            query: json!({}),
            body: Some(
                json!({"expression":"false","expected_expression":"true","expected_rule_version":"5","expected_ruleset_version":"11","expected_definition":definition}),
            ),
            ..CallInput::default()
        };
        assert!(builder.build(&cap, &input).is_err());
        let request = builder.build_unchecked(&cap, &input).unwrap();
        assert_eq!(request.method, "PATCH");
        assert_eq!(
            request.body,
            Some(
                json!({"action":"managed_challenge","enabled":false,"expression":"false","description":"policy","ref":"ref"})
            )
        );
        assert!(request.url.query().is_none());
        input.if_match = Some("version-11".into());
        assert!(builder.build_unchecked(&cap, &input).is_err());
        input.if_match = None;
        input.query = json!({"dry_run":true});
        assert!(builder.build_unchecked(&cap, &input).is_err());
        input.query = json!({});
        let mut wrong = cap;
        wrong.verification.strategy = "generic".into();
        assert!(builder.build_unchecked(&wrong, &input).is_err());
    }
    #[tokio::test]
    async fn verifier_reads_exact_parent_and_rejects_collateral_drift() {
        let cap = capability();
        let selectors =
            json!({"zone_id":"a".repeat(32),"ruleset_id":"b".repeat(32),"rule_id":"c".repeat(32)});
        let definition = json!({"action":"managed_challenge","description":"policy","enabled":true,"expression":"true","ref":"ref"});
        let body = json!({"expression":"false","expected_expression":"true","expected_rule_version":"5","expected_ruleset_version":"11","expected_definition":definition});
        let mut target = definition;
        target["id"] = selectors["rule_id"].clone();
        target["version"] = json!("5");
        target["enabled"] = json!(true);
        let parent = json!({"id":selectors["ruleset_id"],"kind":"zone","phase":"http_request_firewall_custom","version":"11","rules":[target,{"id":"d".repeat(32),"keep":true}]});
        let input = CallInput {
            selectors,
            query: json!({}),
            body: Some(body),
            ..CallInput::default()
        };
        let receipt = rule::receipt(
            &cap,
            &input.selectors,
            &"e".repeat(32),
            &parent,
            input.body.as_ref().unwrap(),
        )
        .unwrap();
        let mut plan = PlanV1::draft(
            "fixture",
            &"e".repeat(32),
            "catalog",
            cap,
            json!({"live_preconditions":{"same_path_prior_state":receipt}}),
        )
        .unwrap();
        plan.input = serde_json::to_value(&input).unwrap();
        plan.precondition_hashes
            .insert(rule::PRECONDITION.into(), hash_value(&receipt).unwrap());
        for drift in [false, true] {
            let mut after = parent.clone();
            after["version"] = json!("12");
            after["rules"][0]["version"] = json!("6");
            after["rules"][0]["expression"] = json!("false");
            let applied = after.clone();
            if drift {
                after["rules"][1]["keep"] = json!(false);
            }
            let response = json!({"success":true,"errors":[],"result":after}).to_string();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let job = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 16384];
                let n = socket.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..n]);
                assert!(request.starts_with(&format!(
                    "GET /zones/{}/rulesets/{} ",
                    "a".repeat(32),
                    "b".repeat(32)
                )));
                assert!(!request.contains("/rules/"));
                let wire = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                );
                socket.write_all(wire.as_bytes()).await.unwrap();
            });
            let executor = Executor::new(reqwest::Client::new(), &origin).unwrap();
            let apply = CloudflareResponseV1 {
                status: 200,
                success: true,
                result: applied,
                errors: vec![],
                result_info: None,
                etag: None,
                cf_ray: None,
            };
            let observed = executor
                .verify_custom_challenge_rule(
                    &plan,
                    &apply,
                    &input,
                    &AuthCredential::Bearer {
                        token: "fixture".into(),
                    },
                )
                .await
                .unwrap();
            assert_eq!(observed.passed, !drift);
            job.await.unwrap();
        }
    }
}
